import Foundation
import Darwin
import VPNHelperShared

/// "DNS da internet" chosen in the app: while at least one VPN that leaves the system DNS
/// alone is connected, the primary network service uses these servers; the previous value
/// comes back when the last of them ends. Names of the VPNs' own domains keep resolving
/// through their per-domain resolvers (Fortinet), which take precedence for those names.
///
/// Same mechanism as wg-quick/WireGuardTunnel (Setup:/Network/Service/<primary>/DNS in the
/// dynamic store, not persistent across reboots), recorded first in a root-only file so a
/// helper crash is undone by the next start. A WireGuard profile with its own DNS owns the
/// system DNS while it runs; this controller then stays out of the way.
public final class InternetDNS {
    struct Record: Codable, Equatable {
        var service: String
        /// Binary property list of the previous Setup: dictionary; nil when there was none.
        var original: Data?
        var servers: [String]
    }

    private let host: WireGuardHost
    private let recordPath: String
    private let queue = DispatchQueue(label: "com.luiz.vpngui.helper.internet-dns")
    private var holders: [(token: String, servers: [String])] = []
    private var record: Record?
    private var unreadableRecovery = false
    private var timer: DispatchSourceTimer?
    public var interval: TimeInterval = 3
    /// True while another component (a WireGuard profile with DNS) owns the system DNS.
    public var otherOwner: () -> Bool = { WireGuardTunnel.dnsOwned }

    public init(host: WireGuardHost, recordPath: String) { self.host = host; self.recordPath = recordPath }

    /// Session `token` wants `servers` as the internet DNS. Returns the log line for it.
    public func acquire(token: String, servers: [String]) -> String {
        queue.sync {
            holders.removeAll { $0.token == token }
            holders.append((token, servers))
            startMonitor()
            if otherOwner() {
                return ServiceLanguage.text("[!] Um perfil WireGuard com DNS próprio controla o DNS do sistema; o DNS da internet do TunnelMac fica para depois.")
            }
            guard apply(servers) else {
                return ServiceLanguage.text("[!] Não foi possível definir o DNS da internet; a VPN segue com o DNS atual.")
            }
            startMonitor()
            let list = servers.joined(separator: ", ")
            return ServiceLanguage.text("[#] DNS da internet: \(list) (Configurações do TunnelMac); o anterior volta ao desconectar.")
        }
    }

    /// Session `token` ended. Returns a log line when this restored the previous DNS.
    @discardableResult
    public func release(token: String) -> String? {
        queue.sync {
            let before = holders.count
            holders.removeAll { $0.token == token }
            guard holders.count != before else { return nil }
            if let latest = holders.last {
                if record != nil, record?.servers != latest.servers, !otherOwner() { _ = apply(latest.servers) }
                return nil
            }
            // A WireGuard profile still owns the DNS: it restores our value when it ends, so
            // ours is undone afterwards by the monitor.
            if otherOwner() && record != nil { return nil }
            let restored = restore()
            if record == nil { stopMonitor() }
            return restored ? ServiceLanguage.text("[#] DNS da internet anterior restaurado.") : nil
        }
    }

    /// Undoes a change left by an earlier helper process (no session can hold it any more).
    public func recover() {
        queue.sync {
            guard let (data, _) = try? SecureFile.read(recordPath, limit: 256 * 1024),
                  let saved = try? JSONDecoder().decode(Record.self, from: data) else {
                unreadableRecovery = FileManager.default.fileExists(atPath: recordPath)
                return
            }
            unreadableRecovery = false
            record = saved
            _ = restore()
            if record != nil { startMonitor() }
        }
    }

    public var active: Bool { queue.sync { record != nil } }
    public var cleanupPending: Bool { queue.sync { unreadableRecovery || (holders.isEmpty && record != nil && !otherOwner()) } }

    // MARK: Internals (on `queue`)

    private func apply(_ servers: [String]) -> Bool {
        guard let service = host.primaryService(), WireGuardTunnel.validService(service) else { return false }
        if let record, record.service != service {
            _ = restore()
            guard self.record == nil else { return false }
        }
        let current = host.dnsSetup(service: service)
        // The backup is what was there before the TunnelMac changed it, never our own value.
        let original: Data?
        if let record, record.service == service { original = record.original }
        else { original = current.flatMap { try? PropertyListSerialization.data(fromPropertyList: $0, format: .binary, options: 0) } }
        var value = current ?? [:]
        value["ServerAddresses"] = servers
        let previous = record
        record = Record(service: service, original: original, servers: servers)
        // Fail closed before touching the network if the durable journal cannot be saved.
        do { try save() } catch { record = previous; return false }
        guard host.setDNSSetup(service: service, value: value) else {
            // Keep the original backup; the monitor/recovery can retry safely.
            return false
        }
        flush()
        return true
    }

    /// Puts the previous value back while the service still has our servers; when the user
    /// changed the DNS meanwhile, their value is kept.
    private func restore() -> Bool {
        guard let change = record else { return false }
        guard WireGuardTunnel.servers(host.dnsSetup(service: change.service)) == change.servers else {
            record = nil; unlink(recordPath); return true // Externally replaced, no longer ours.
        }
        let original = change.original.flatMap { try? PropertyListSerialization.propertyList(from: $0, format: nil) as? [String: Any] }
        guard host.setDNSSetup(service: change.service, value: original) else { return false }
        flush()
        record = nil
        unlink(recordPath)
        return true
    }

    private func flush() { _ = host.run(WireGuardTools.dscacheutil, ["-flushcache"]) }

    private func save() throws {
        guard let record else { return }
        try SecureFile.replace(recordPath, data: try JSONEncoder().encode(record), mode: 0o600)
    }

    /// Network changes (another primary service, configd rewriting its Setup: keys, a
    /// WireGuard profile releasing the DNS) apply the chosen servers again.
    private func startMonitor() {
        guard timer == nil else { return }
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + interval, repeating: interval)
        timer.setEventHandler { [weak self] in self?.tick() }
        self.timer = timer
        timer.resume()
    }

    private func stopMonitor() { timer?.cancel(); timer = nil }

    private func tick() {
        guard !otherOwner() else { return }
        guard let wanted = holders.last?.servers else {
            _ = restore()
            if record == nil { stopMonitor() }
            return
        }
        let primary = host.primaryService()
        if let record, primary == record.service,
           WireGuardTunnel.servers(host.dnsSetup(service: record.service)) == wanted { return }
        _ = apply(wanted)
    }
}

/// Holds the internet DNS for one session: from "tunnel up" until the client exits.
final class InternetDNSHold: SessionObserver {
    private let token: String
    private let servers: [String]
    private let controller: InternetDNS
    private let trigger: String?
    var cleanupFailure: String? { !held && controller.cleanupPending ? ServiceLanguage.text("Restauração do DNS da internet pendente.") : nil }
    private var held = false
    var emit: (String) -> Void = { _ in }

    /// `trigger`: output line that marks the tunnel as up; nil = call `tunnelUp()` directly.
    init(token: String, servers: [String], controller: InternetDNS, trigger: String?) {
        self.token = token; self.servers = servers; self.controller = controller; self.trigger = trigger
    }

    func tunnelUp() {
        guard !held else { return }
        held = true
        emit(controller.acquire(token: token, servers: servers))
    }

    func clientStarted(pid: pid_t) {}
    func clientOutput(_ line: String) { if let trigger, line.contains(trigger) { tunnelUp() } }
    func clientEnded() {
        guard held else { return }
        held = false
        if let line = controller.release(token: token) { emit(line) }
    }
}
