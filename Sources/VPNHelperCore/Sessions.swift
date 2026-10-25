import Foundation
import Darwin
import ProcessBridge
import VPNHelperShared

/// Bounded, ordered event queue for one session.
///
/// At most one batch is in flight; the next is sent only after the client acknowledges
/// the previous one. While the client is slow, lines accumulate up to the limits and the
/// oldest lines are dropped (reported as `.dropped(n)`). Start, cookie and terminal events
/// are never dropped. Sequence numbers are assigned when a batch is sent, so the client
/// sees a gap-free, strictly increasing order per session.
public final class EventPump {
    public typealias Sink = HelperCore.EventSink
    public static let maximumEvents = 2000
    static let maximumBytes = 512 * 1024
    static let batchEvents = 256

    let token: String
    var sink: Sink?
    private var pending: [SessionEvent.Kind] = []
    private var pendingBytes = 0
    private var dropped = 0
    private var inFlight = false
    private var nextSequence: UInt64 = 1
    private(set) var deliveredTerminal = false
    var onIdle: (() -> Void)?

    public init(token: String, sink: Sink?) { self.token = token; self.sink = sink }

    public var queuedCount: Int { pending.count }
    var isDrained: Bool { pending.isEmpty && !inFlight && dropped == 0 }

    static func cost(_ kind: SessionEvent.Kind) -> Int {
        switch kind {
        case .line(let text), .cookie(let text), .failed(let text): return text.utf8.count + 32
        default: return 32
        }
    }
    static func droppable(_ kind: SessionEvent.Kind) -> Bool {
        switch kind { case .line, .overflow: return true; default: return false }
    }

    public func enqueue(_ kind: SessionEvent.Kind) {
        guard sink != nil else { return } // Client gone: nothing is retained.
        pending.append(kind)
        pendingBytes += Self.cost(kind)
        while pending.count > Self.maximumEvents || pendingBytes > Self.maximumBytes {
            guard let index = pending.firstIndex(where: Self.droppable) else { break }
            pendingBytes -= Self.cost(pending.remove(at: index))
            dropped += 1
        }
        pump()
    }

    func detach() {
        sink = nil
        pending.removeAll()
        pendingBytes = 0
        dropped = 0
        inFlight = false
        onIdle?()
    }

    func pump() {
        guard !inFlight, let sink, !(pending.isEmpty && dropped == 0) else {
            if pending.isEmpty && !inFlight { onIdle?() }
            return
        }
        var events: [SessionEvent] = []
        if dropped > 0 {
            events.append(SessionEvent(sequence: nextSequence, kind: .dropped(dropped)))
            nextSequence += 1
            dropped = 0
        }
        var bytes = 0
        while !pending.isEmpty, events.count < Self.batchEvents, bytes < Self.maximumBytes / 2 {
            let kind = pending.removeFirst()
            let cost = Self.cost(kind)
            pendingBytes -= cost
            bytes += cost
            events.append(SessionEvent(sequence: nextSequence, kind: kind))
            nextSequence += 1
        }
        if events.contains(where: \.isTerminal) { deliveredTerminal = true }
        inFlight = true
        sink(EventBatch(token: token, events: events)) { [weak self] in
            self?.inFlight = false
            self?.pump()
        }
    }
}

/// Network work tied to a session's client process (WireGuard: the helper configures the
/// tunnel). Called from the session's reader thread: `clientStarted` once the supervisor
/// reported the client PID, `clientEnded` after the supervisor was reaped and before the
/// session's terminal event is queued, so cleanup is done when the app hears about the exit.
protocol SessionObserver: AnyObject {
    var cleanupFailure: String? { get }
    func clientStarted(pid: pid_t)
    /// Every output line of the client (already filtered), in order.
    func clientOutput(_ line: String)
    func clientEnded()
}

extension SessionObserver { var cleanupFailure: String? { nil } }

/// Removes a session's client certificate files once its client has exited.
final class CertificateCleanup: SessionObserver {
    private let remove: () -> Void
    init(_ remove: @escaping () -> Void) { self.remove = remove }
    func clientStarted(pid: pid_t) {}
    func clientOutput(_ line: String) {}
    func clientEnded() { remove() }
}

/// One openfortivpn under its own supervisor. The helper keeps the supervisor's PID
/// (its child, never looked up by name) and the control socket. Stop = "STOP\n";
/// losing the helper or the client = EOF, which the supervisor treats as a stop too.
final class SessionRunner {
    let token: String
    let ownerID: UUID
    let uid: uid_t
    let connectionID: UUID
    let supervisorPID: pid_t
    private let control: Int32
    private let queue: DispatchQueue
    let pump: EventPump
    private(set) var stopRequested = false
    private(set) var finished = false
    var onFinish: ((SessionRunner) -> Void)?
    /// Set before `startReading`; never changed afterwards.
    var observer: SessionObserver?

    init(token: String, ownerID: UUID, uid: uid_t, connectionID: UUID, supervisorPID: pid_t, control: Int32,
         queue: DispatchQueue, pump: EventPump) {
        self.token = token; self.ownerID = ownerID; self.uid = uid; self.connectionID = connectionID
        self.supervisorPID = supervisorPID; self.control = control; self.queue = queue; self.pump = pump
    }

    /// Starts the ordered reader. Runs on its own thread so a slow client never blocks
    /// the supervisor: output is always drained and bounded by EventPump.
    func startReading(captureCookie: Bool, secrets: [String]) {
        let thread = Thread { [self] in
            var filter = OutputLineFilter(captureCookie: captureCookie, secrets: secrets)
            var sawPID = false
            var buffer = [UInt8](repeating: 0, count: 8192)
            func forward(_ events: [OutputLineFilter.Event]) {
                var kinds: [SessionEvent.Kind] = []
                var startedPID: pid_t?
                for event in events {
                    switch event {
                    case .overflow: kinds.append(.overflow)
                    case .cookie(let cookie): kinds.append(.cookie(cookie))
                    case .line(let line):
                        if !sawPID, line.hasPrefix("__VPNGUI_PID__="), let pid = Int32(line.dropFirst("__VPNGUI_PID__=".count)), pid > 1 {
                            sawPID = true
                            kinds.append(.started(pid: pid))
                            startedPID = pid
                        } else if line.hasPrefix("__VPNGUI_") {
                            continue // Exit status comes from waitpid, never from output text.
                        } else {
                            kinds.append(.line(line))
                            observer?.clientOutput(line)
                        }
                    }
                }
                guard !kinds.isEmpty else { return }
                queue.async { kinds.forEach { self.pump.enqueue($0) } }
                // After the started event is queued, so the observer's lines follow it.
                if let startedPID { observer?.clientStarted(pid: startedPID) }
            }
            var status: Int32 = 0
            var reaped: pid_t = 0
            var drainedAfterExit = 0
            while true {
                if reaped <= 0 {
                    reaped = waitpid(supervisorPID, &status, WNOHANG)
                    if reaped < 0 && errno != EINTR { break }
                }
                var descriptor = pollfd(fd: control, events: Int16(POLLIN | POLLHUP), revents: 0)
                let available = poll(&descriptor, 1, reaped == supervisorPID ? 0 : 200)
                if reaped == supervisorPID && (available <= 0 || drainedAfterExit >= 1024 * 1024) { break }
                if available <= 0 { continue }
                let count = Darwin.read(control, &buffer, buffer.count)
                if reaped == supervisorPID, count > 0 { drainedAfterExit += count }
                if count < 0 && errno == EINTR { continue }
                if count <= 0 { break }
                forward(filter.feed(Data(buffer.prefix(count))))
            }
            forward(filter.finish())
            if reaped != supervisorPID {
                repeat { reaped = waitpid(supervisorPID, &status, 0) } while reaped < 0 && errno == EINTR
            }
            let code: Int
            if reaped == supervisorPID {
                let low = status & 0x7f
                code = low == 0 ? Int((status >> 8) & 0xff) : 128 + Int(low)
            } else { code = -1 }
            observer?.clientEnded()
            queue.async {
                // Closed on the queue that also writes STOP, so the number is never reused under it.
                close(self.control)
                self.finished = true
                if let failure = self.observer?.cleanupFailure { self.pump.enqueue(.failed(failure)) }
                else if code == 137 { self.pump.enqueue(.failed("Cliente exigiu encerramento forçado após 10 s. Confira a conectividade e o estado da rede antes de reconectar.")) }
                else if code >= 0 { self.pump.enqueue(.exited(code: code)) }
                else { self.pump.enqueue(.failed("O supervisor encerrou sem status confirmado.")) }
                self.onFinish?(self)
            }
        }
        thread.name = "com.luiz.vpngui.helper.session"
        thread.start()
    }

    /// Idempotent stop; the supervisor bounds graceful shutdown for its own child.
    func stop() {
        guard !finished, !stopRequested else { return }
        stopRequested = true
        let command = Array("STOP\n".utf8)
        _ = command.withUnsafeBytes { Darwin.write(control, $0.baseAddress, $0.count) }
    }

    /// The owning client is gone: stop, close our write side (EOF) and keep draining.
    func abandon() {
        pump.detach()
        stop()
        if !finished { shutdown(control, SHUT_WR) }
    }
}

/// Persistent evidence of supervisors started by this helper, so that a restarted helper
/// knows which earlier sessions may still be cleaning up. Entries are never adopted or
/// signalled; they only block a duplicate start of the same profile until they are gone.
/// A PID is considered the same process only when its start time also matches.
public final class SessionRegistry {
    public struct Entry: Codable, Equatable {
        var token: String
        var uid: UInt32
        var connectionID: UUID
        var pid: Int32
        var startSeconds: UInt64
        var startMicroseconds: UInt64
        public init(token: String, uid: UInt32, connectionID: UUID, pid: Int32, startSeconds: UInt64, startMicroseconds: UInt64) {
            self.token = token; self.uid = uid; self.connectionID = connectionID; self.pid = pid
            self.startSeconds = startSeconds; self.startMicroseconds = startMicroseconds
        }
    }
    let path: String?
    public private(set) var entries: [Entry] = []
    public init(path: String?) {
        self.path = path
        if let path, FileManager.default.fileExists(atPath: path) {
            do {
                let (data, _) = try SecureFile.read(path, limit: 1024 * 1024)
                entries = try JSONDecoder().decode([Entry].self, from: data)
            } catch { persistenceFailure = "Registro de sessões ilegível; recuperação manual necessária: \(error.localizedDescription)" }
        }
    }
    static func identity(of pid: pid_t) -> (UInt64, UInt64)? {
        var seconds: UInt64 = 0, micros: UInt64 = 0
        return vpn_process_start_time(pid, &seconds, &micros) == 0 ? (seconds, micros) : nil
    }
    public static func alive(_ entry: Entry) -> Bool {
        guard let (seconds, micros) = identity(of: entry.pid) else { return false }
        return seconds == entry.startSeconds && micros == entry.startMicroseconds
    }
    public func add(token: String, uid: uid_t, connectionID: UUID, pid: pid_t) throws {
        guard let (seconds, micros) = Self.identity(of: pid) else { throw failure(.internalError, "Identidade do supervisor não pôde ser registrada.") }
        entries.append(Entry(token: token, uid: uid, connectionID: connectionID, pid: pid, startSeconds: seconds, startMicroseconds: micros))
        try persist()
    }
    func remove(token: String) {
        entries.removeAll { $0.token == token }
        save()
    }
    /// Entries from earlier helper processes whose supervisor still exists.
    public func stale(excluding live: Set<String>) -> [Entry] {
        let before = entries.count
        entries.removeAll { !live.contains($0.token) && !Self.alive($0) }
        if entries.count != before { save() }
        return entries.filter { !live.contains($0.token) }
    }
    public private(set) var persistenceFailure: String?
    private func save() {
        do { try persist(); persistenceFailure = nil }
        catch { persistenceFailure = error.localizedDescription } // Keep in-memory evidence; disk retains earlier entries.
    }
    private func persist() throws {
        guard let path else { throw failure(.internalError, "Caminho do registro de sessões indisponível.") }
        try SecureFile.replace(path, data: JSONEncoder().encode(entries), mode: 0o600)
    }
}
