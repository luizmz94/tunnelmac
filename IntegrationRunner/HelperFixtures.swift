@testable import VPNApp
import Foundation
import Darwin
import Security
import CryptoKit
import ServiceManagement
import VPNHelperCore
import VPNHelperShared

// Fixtures for the SPEC 04 local checks. Everything runs unprivileged inside the test
// runner: anonymous XPC listeners, a temporary state directory owned by the current user,
// and a shell script standing in for openfortivpn. Nothing is registered with launchd.

@MainActor
final class FakeRegistrar: ServiceRegistrar {
    var status: SMAppService.Status
    var events: [String] = []
    var afterRegister: SMAppService.Status = .requiresApproval
    var registerError: Error?
    var settingsOpened = 0
    /// Observed at unregister time (must be false: cleanup first).
    var activeAtUnregister: [Bool] = []
    weak var manager: VPNManager?
    init(_ status: SMAppService.Status) { self.status = status }
    func register() throws {
        events.append("register")
        if let registerError { throw registerError }
        status = afterRegister
    }
    func unregister(completion: @escaping (Error?) -> Void) {
        events.append("unregister")
        activeAtUnregister.append(manager?.anyActive ?? false)
        status = .notRegistered
        DispatchQueue.main.async { completion(nil) }
    }
    func openSystemSettings() { settingsOpened += 1 }
}

final class FakeAuthorizer: AdminAuthorizing {
    private let lock = NSLock()
    private var _allow = true, _calls = 0
    var allow: Bool { get { lock.withLock { _allow } } set { lock.withLock { _allow = newValue } } }
    var calls: Int { lock.withLock { _calls } }
    func authorize(_ externalForm: Data) -> Bool { lock.withLock { _calls += 1; return _allow } }
}

/// Canned helper used to test the app's reaction to helper states.
final class FakeHelper: NSObject, NSXPCListenerDelegate, VPNHelperXPC {
    let listener = NSXPCListener.anonymous()
    let respond: @Sendable (HelperRequest) -> HelperResponse
    let accept: Bool
    init(accept: Bool = true, respond: @escaping @Sendable (HelperRequest) -> HelperResponse) {
        self.respond = respond
        self.accept = accept
        super.init()
        listener.delegate = self
        listener.resume()
    }
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        guard accept else { return false }
        connection.exportedInterface = HelperInterfaces.helper()
        connection.exportedObject = self
        connection.resume()
        return true
    }
    func perform(_ request: Data, reply: @escaping (Data) -> Void) {
        let response: HelperResponse
        if let decoded = try? MessageCodec.decode(HelperRequest.self, from: request, limit: HelperConstants.maximumRequestSize) {
            response = respond(decoded)
        } else { response = .failure(HelperFailure(.invalidRequest, "Mensagem malformada.")) }
        reply(MessageCodec.encode(response))
    }
    deinit { listener.invalidate() }
}

/// Wraps the production delegate to keep the accepted connections (to simulate drops).
final class RecordingDelegate: NSObject, NSXPCListenerDelegate {
    let inner: HelperListenerDelegate
    private let lock = NSLock()
    private var _connections: [NSXPCConnection] = []
    var connections: [NSXPCConnection] { lock.withLock { _connections } }
    init(_ inner: HelperListenerDelegate) { self.inner = inner }
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        let accepted = inner.listener(listener, shouldAcceptNewConnection: connection)
        if accepted { lock.withLock { _connections.append(connection) } }
        return accepted
    }
}

/// Real HelperCore + production listener delegate behind an anonymous listener.
final class HelperFixture {
    let root: String
    let state: String
    let core: HelperCore
    let listener = NSXPCListener.anonymous()
    let recorder: RecordingDelegate
    let authorizer = FakeAuthorizer()
    let dns: FakeSupplementalDNS
    var store: RuntimeStore { core.stateStore }

    static func temporaryRoot() throws -> String {
        let path = FileManager.default.temporaryDirectory.appendingPathComponent("VPNGUI-helper-\(UUID().uuidString)").path
        guard mkdir(path, 0o755) == 0, let real = realpath(path, nil) else { throw TestSupport.Failure("Raiz temporária indisponível") }
        defer { free(real) }
        return String(cString: real)
    }

    init(root existing: String? = nil, listenerRequirement: String?, delegateRequirement: String?,
         wireGuardHost: WireGuardHost = SystemWireGuardHost(uapiDirectory: "/nonexistent-uapi"), wireGuardInterval: TimeInterval = 3,
         dns: FakeSupplementalDNS = FakeSupplementalDNS()) throws {
        self.dns = dns
        root = try existing ?? Self.temporaryRoot()
        state = root + "/state"
        core = HelperCore(HelperCore.Configuration(
            stateDirectory: state,
            ownership: TrustedOwnership(owners: [getuid()], anchor: root),
            supervisorSource: SupervisorLocator.path,
            supervisorRequirement: nil,
            helperVersion: HelperConstants.fullVersion,
            probeIdentity: nil,
            authorizer: authorizer,
            idleTimeout: 3600,
            wireGuardHost: wireGuardHost,
            wireGuardInterval: wireGuardInterval,
            supplementalDNS: dns))
        recorder = RecordingDelegate(HelperListenerDelegate(core: core, clientRequirement: delegateRequirement))
        if let listenerRequirement { listener.setConnectionCodeSigningRequirement(listenerRequirement) }
        listener.delegate = recorder
        listener.resume()
    }

    @MainActor func client(requirement: String = HelperTests.ownRequirement) -> HelperClient {
        let endpoint = listener.endpoint
        return HelperClient(requirement: requirement) { NSXPCConnection(listenerEndpoint: endpoint) }
    }

    func dropConnections() { recorder.connections.forEach { $0.invalidate() } }

    func tearDown(removeFiles: Bool = true) {
        core.shutdown(timeout: 10)
        listener.invalidate()
        if removeFiles { try? FileManager.default.removeItem(atPath: root) }
    }

    /// Script standing in for openfortivpn. Never contacts the network or prints secrets.
    static let script = """
    #!/bin/sh
    conf=$(/bin/cat /dev/fd/3)
    case "$conf" in
      *"host = exit.invalid"*) echo "INFO:   natural exit"; exit 0;;
      *"host = flood.invalid"*) i=0; while [ $i -lt 3000 ]; do echo "INFO:   line $i"; i=$((i+1)); done; exit 0;;
    esac
    echo "INFO:   Connected to gateway."
    echo "ARGS=$*"
    cert=$(printf '%s\n' "$conf" | /usr/bin/sed -n 's/^user-cert = //p')
    if [ -n "$cert" ]; then
      key=$(printf '%s\n' "$conf" | /usr/bin/sed -n 's/^user-key = //p')
      echo "CERTFILES=$cert $key $(/usr/bin/stat -f %Lp "$cert") $(/usr/bin/head -1 "$cert") $(/usr/bin/head -1 "$key")"
    fi
    echo "ENVKEYS=$(/usr/bin/env | /usr/bin/cut -d= -f1 | /usr/bin/sort | /usr/bin/tr '\\n' ' ')"
    echo "OPENFDS=$(for f in 4 5 6 7 8 9 10; do [ -e /dev/fd/$f ] && printf '%s ' $f; done)"
    for a in "$@"; do
      [ "$a" = "--cookie-on-stdin" ] && echo "STDIN_MD5=$(/sbin/md5 -q)"
      [ "$a" = "-v" ] && echo "DEBUG:  Cookie: SVPNCOOKIE=fixturecaptureZq9"
    done
    echo "INFO:   Got addresses: [10.9.0.2], ns [10.9.0.53, 0.0.0.0], ns_suffix [Corp.invalid;lab.invalid]"
    echo "INFO:   Tunnel is up and running."
    trap 'echo "INFO:   Logged out."; exit 0' TERM
    while :; do /bin/sleep 1 & wait $!; done
    """

    /// Writes an approved runtime exactly in the store's format (hashes, modes, state).
    func installFixtureRuntime(help: String = SAMLCookieTests.help, authorizedUsers: [UInt32] = [getuid()]) throws {
        try store.prepareDirectories()
        let id = "0123456789abcdef01234567"
        let base = store.runtimes + "/" + id
        for directory in [base, base + "/bin", base + "/lib", base + "/lib/ossl-modules", base + "/lib/engines", base + "/etc"] {
            guard mkdir(directory, 0o755) == 0 || errno == EEXIST else { throw TestSupport.Failure("mkdir \(directory)") }
        }
        func write(_ relative: String, _ data: Data, _ mode: Int) throws -> [String: Any] {
            let path = base + "/" + relative
            try? FileManager.default.removeItem(atPath: path)
            guard FileManager.default.createFile(atPath: path, contents: data), chmod(path, mode_t(mode)) == 0 else {
                throw TestSupport.Failure("Não foi possível criar \(relative)")
            }
            return ["path": relative, "sha256": TestSupport.sha256(data), "mode": mode]
        }
        let files = [try write("bin/openfortivpn", Data(Self.script.utf8), 0o555),
                     try write("etc/openssl.cnf", Data("# vazio\n".utf8), 0o444)]
        let capabilities = RuntimeCapabilities(help: help)
        let manifest: [String: Any] = [
            "format": 1, "id": id, "approvedAt": Date().timeIntervalSince1970, "approvedByUID": getuid(),
            "version": "fixture", "inventoryDigest": "fixture", "sourcePath": "/fixture/openfortivpn", "sourceSHA256": "0",
            "capabilities": ["cookieOnStdin": capabilities.cookieOnStdin, "captureCookie": capabilities.captureCookie, "samlPort": capabilities.samlPort],
            "files": files, "sources": [], "systemLibraries": [], "notes": []]
        let manifestPath = base + "/manifest.json"
        try? FileManager.default.removeItem(atPath: manifestPath)
        guard FileManager.default.createFile(atPath: manifestPath, contents: try JSONSerialization.data(withJSONObject: manifest)),
              chmod(manifestPath, 0o444) == 0 else { throw TestSupport.Failure("manifesto") }
        let stateJSON: [String: Any] = ["format": 1, "activeRuntime": id, "authorizedUsers": authorizedUsers]
        try? FileManager.default.removeItem(atPath: store.statePath)
        guard FileManager.default.createFile(atPath: store.statePath, contents: try JSONSerialization.data(withJSONObject: stateJSON)),
              chmod(store.statePath, 0o644) == 0 else { throw TestSupport.Failure("estado") }
    }
}

/// Minimal raw XPC peer to exercise the helper without the app's handshake logic.
@MainActor
final class RawClient {
    let connection: NSXPCConnection
    private let lock = NSLock()
    private var batches: [EventBatch] = []
    private var heldAcks: [() -> Void] = []
    /// When set, the acknowledgement of a batch with a terminal event is held until released.
    var holdTerminalAcks: Bool { get { lock.withLock { _hold } } set { lock.withLock { _hold = newValue } } }
    private var _hold = false
    init(endpoint: NSXPCListenerEndpoint, requirement: String = HelperTests.ownRequirement) {
        connection = NSXPCConnection(listenerEndpoint: endpoint)
        connection.setCodeSigningRequirement(requirement)
        connection.remoteObjectInterface = HelperInterfaces.helper()
        connection.exportedInterface = HelperInterfaces.client()
        connection.exportedObject = BatchCollector { [weak self] batch, reply in
            guard let self else { return reply() }
            let hold = self.lock.withLock {
                self.batches.append(batch)
                guard self._hold, batch.events.contains(where: \.isTerminal) else { return false }
                self.heldAcks.append(reply)
                return true
            }
            if !hold { reply() }
        }
        connection.resume()
    }
    var received: [EventBatch] { lock.withLock { batches } }
    func send(_ data: Data, timeout: TimeInterval = 10) -> HelperResponse? {
        let box = ResponseBox()
        let proxy = connection.remoteObjectProxyWithErrorHandler { _ in box.set(nil) } as? VPNHelperXPC
        proxy?.perform(data) { reply in box.set(try? MessageCodec.decode(HelperResponse.self, from: reply, limit: HelperConstants.maximumBatchSize)) }
        _ = TestSupport.spin(timeout) { box.done }
        return box.value
    }
    func send(_ request: HelperRequest) -> HelperResponse? { send(MessageCodec.encode(request)) }
    func releaseAcks() { lock.withLock { let acks = heldAcks; heldAcks = []; _hold = false; return acks }.forEach { $0() } }
    func invalidate() { connection.invalidate() }
}

final class ResponseBox: @unchecked Sendable {
    private let lock = NSLock()
    private var _done = false
    private var _value: HelperResponse?
    var done: Bool { lock.withLock { _done } }
    var value: HelperResponse? { lock.withLock { _value } }
    func set(_ value: HelperResponse?) { lock.withLock { if !_done { _done = true; _value = value } } }
}

final class BatchCollector: NSObject, VPNHelperClientXPC {
    let handler: (EventBatch, @escaping () -> Void) -> Void
    init(_ handler: @escaping (EventBatch, @escaping () -> Void) -> Void) { self.handler = handler }
    func deliver(_ batch: Data, reply: @escaping () -> Void) {
        guard let decoded = try? MessageCodec.decode(EventBatch.self, from: batch, limit: HelperConstants.maximumBatchSize) else { return reply() }
        handler(decoded, reply)
    }
}

extension TestSupport {
    static func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}

/// Records the per-domain resolvers the helper would publish in the dynamic store.
final class FakeSupplementalDNS: SupplementalDNS {
    private let lock = NSLock()
    private var values: [String: [String: Any]] = [:]
    private(set) var flushes = 0
    var published: [String: [String: Any]] { lock.withLock { values } }
    func set(token: String, value: [String: Any]) -> Bool { lock.withLock { values[token] = value }; return true }
    func remove(token: String) { lock.withLock { _ = values.removeValue(forKey: token) } }
    func tokens() -> [String] { lock.withLock { Array(values.keys) } }
    func flush() { lock.withLock { flushes += 1 } }
}
