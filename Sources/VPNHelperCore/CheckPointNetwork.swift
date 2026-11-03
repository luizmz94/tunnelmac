import Foundation
import Darwin
import SystemConfiguration
import VPNHelperShared

/// Network side of Check Point sessions. snx-rs configures the tunnel by itself: utun,
/// routes through the routing socket (the gateway's split routes, or 0/1 + 128/1 with
/// default-route, plus a host route to the gateway through the physical router) and the
/// VPN's DNS as State:/Network/Service/snx-rs-<utun>/DNS. On SIGTERM it removes all of it.
///
/// Considered and left out of v1: no-dns/no-routing with the helper configuring the network.
/// snx-rs has no hook like openconnect's vpnc-script, so the helper would have to read
/// addresses, routes and DNS from output that snx-rs translates. Letting snx-rs configure and
/// the helper only detect readiness and remove leftovers is smaller, and still covers a
/// SIGKILL: the utun routes die with the utun, but the DNS key and the gateway's host route
/// through the physical router survive it.
///
/// snx-rs removes every snx-rs-* DNS key when it starts, so two sessions would break each
/// other's DNS: the helper runs one Check Point session at a time.
public protocol CheckPointDNSStore: AnyObject {
    /// Interfaces (utunN) with a State:/Network/Service/snx-rs-<utun>/DNS key.
    func interfaces() -> [String]
    func remove(interface: String)
}

public final class SystemCheckPointDNSStore: CheckPointDNSStore {
    private let lock = NSLock()
    private var store: SCDynamicStore?
    public init() {}

    private func dynamicStore() -> SCDynamicStore? {
        if store == nil { store = SCDynamicStoreCreate(nil, "com.luiz.vpngui.helper.checkpoint" as CFString, nil, nil) }
        return store
    }

    public func interfaces() -> [String] {
        lock.withLock {
            guard let store = dynamicStore(),
                  let keys = SCDynamicStoreCopyKeyList(store, "State:/Network/Service/snx-rs-utun[0-9]+/DNS" as CFString) as? [String]
            else { return [] }
            return keys.compactMap(CheckPointNetwork.interface(ofKey:)).sorted()
        }
    }

    public func remove(interface: String) {
        guard CheckPointNetwork.validInterface(interface) else { return }
        lock.withLock {
            if let store = dynamicStore() { _ = SCDynamicStoreRemoveValue(store, CheckPointNetwork.key(interface) as CFString) }
        }
    }
}

enum CheckPointNetwork {
    /// What a session needs undone if snx-rs is killed: written before the spawn, updated
    /// once the interface is known, removed after the cleanup.
    struct Record: Codable, Equatable {
        /// IPv4 the gateway resolved to (snx-rs's host route goes there).
        var gateway: String?
        /// A host route to the gateway existed before the session: never removed.
        var hadHostRoute: Bool
        var interface: String?
    }

    static func recordPath(work: String, token: String) -> String { work + "/cp.\(token).json" }

    static func key(_ interface: String) -> String { "State:/Network/Service/snx-rs-\(interface)/DNS" }

    static func interface(ofKey key: String) -> String? {
        guard let match = key.firstMatch(of: #/^State:/Network/Service/snx-rs-(utun[0-9]{1,3})/DNS$/#) else { return nil }
        return String(match.1)
    }

    static func validInterface(_ name: String) -> Bool { name.range(of: #"^utun[0-9]{1,3}$"#, options: .regularExpression) != nil }

    /// `snx-rs -m info` arguments. ignore-server-cert (-X) is never one of them.
    static func infoArguments(server: String, authorityPath: String?) -> [String] {
        ["-m", "info", "-s", server] + (authorityPath.map { ["-k", $0] } ?? [])
    }

    /// First IPv4 address of the gateway.
    static func gatewayAddress(_ host: String, port: Int, resolver: WireGuardHost) -> String? {
        let literal = host.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        var address = in_addr()
        if inet_pton(AF_INET, literal, &address) == 1 { return literal }
        return resolver.resolve(literal, port: port).first { inet_pton(AF_INET, $0, &address) == 1 }
    }

    /// The host route to `address` outside any tunnel (`route -n get`): its router, or nil.
    static func physicalHostRoute(_ address: String, host: WireGuardHost) -> String? {
        let result = host.run(WireGuardTools.route, ["-n", "get", "-inet", address])
        guard result.status == 0 else { return nil }
        var fields: [String: String] = [:]
        for line in result.output.split(separator: "\n") {
            let parts = line.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            if parts.count == 2 { fields[parts[0]] = parts[1] }
        }
        guard fields["destination"] == address, let flags = fields["flags"], flags.contains("HOST"),
              let router = fields["gateway"], router.range(of: #"^[0-9.]{7,15}$"#, options: .regularExpression) != nil,
              !(fields["interface"] ?? "").hasPrefix("utun") else { return nil }
        return router
    }

    /// Removes what a session left: every snx-rs DNS key (only one Check Point session runs
    /// at a time) and the gateway's host route through the physical router, unless that
    /// route was there before the session.
    static func cleanup(_ record: Record, dns: CheckPointDNSStore, host: WireGuardHost) -> [String] {
        var removed: [String] = []
        let interfaces = dns.interfaces()
        for interface in interfaces {
            dns.remove(interface: interface)
            removed.append("DNS \(interface)")
        }
        if !interfaces.isEmpty { _ = host.run(WireGuardTools.dscacheutil, ["-flushcache"]) }
        if let gateway = record.gateway, !record.hadHostRoute, let router = physicalHostRoute(gateway, host: host) {
            if host.run(WireGuardTools.route, ["-q", "-n", "delete", "-inet", "-host", gateway, router]).status == 0 {
                removed.append("route \(gateway)")
            }
        }
        return removed
    }

    static func read(_ path: String) -> Record? {
        guard let (data, _) = try? SecureFile.read(path, limit: 64 * 1024) else { return nil }
        return try? JSONDecoder().decode(Record.self, from: data)
    }

    static func write(_ record: Record, to path: String) {
        guard let data = try? JSONEncoder().encode(record) else { return }
        try? SecureFile.replace(path, data: data, mode: 0o600)
    }

    /// Answer of `snx-rs -m info`. A failed query with no login type is reported in the app's
    /// language; a TLS failure (wrong address for the certificate, untrusted authority) has its own text.
    static func gatewayInfo(_ output: String, status: Int32) -> CheckPointGatewayInfo {
        let options = CheckPointRules.loginOptions(fromInfo: output)
        var failure: String?
        if status != 0 && options.isEmpty {
            let lines = output.split(whereSeparator: \.isNewline).map(String.init)
            if lines.contains(where: { CheckPointOutput.classify($0) == .certificateFailed }) {
                failure = ServiceLanguage.text("O gateway não apresentou um certificado válido para este endereço com a autoridade confiada.")
            } else if let detail = lines.last(where: { $0.hasPrefix("Error:") }) {
                let text = String(detail.dropFirst("Error:".count).trimmingCharacters(in: .whitespaces).prefix(200))
                failure = ServiceLanguage.text("Não foi possível consultar o gateway Check Point: \(text)")
            } else {
                failure = ServiceLanguage.text("Não foi possível consultar o gateway Check Point (código \(status)).")
            }
        }
        return CheckPointGatewayInfo(loginOptions: options, fingerprintWords: CheckPointRules.fingerprintWords(fromInfo: output),
                                     supportedProtocols: CheckPointRules.supportedProtocols(fromInfo: output), failure: failure)
    }

    /// Records of sessions that are gone (helper crash or restart). While a Check Point
    /// session still runs, the DNS keys are its own and stay.
    static func recover(work: String, live: Set<String>, dns: CheckPointDNSStore, host: WireGuardHost,
                        removeAuthority: (String) -> Void) {
        let entries = ((try? FileManager.default.contentsOfDirectory(atPath: work)) ?? [])
            .filter { $0.hasPrefix("cp.") && $0.hasSuffix(".json") }
        let tokens = entries.map { String($0.dropFirst(3).dropLast(5)) }
        let running = tokens.contains(where: live.contains)
        for token in tokens where !live.contains(token) {
            let path = recordPath(work: work, token: token)
            // The running session's DNS key and gateway route are its own.
            if !running, let record = read(path) { _ = cleanup(record, dns: dns, host: host) }
            removeAuthority(token)
            unlink(path)
        }
    }
}

/// Readiness and cleanup of one snx-rs session.
///
/// Ready, in order of preference (the output is translated, so text is the fallback):
/// 1. a State:/Network/Service/snx-rs-utunN/DNS key appears and utunN exists (polled about
///    every second until the connection timeout, and checked again when the output says the
///    tunnel is up);
/// 2. without that key (a gateway that sends no DNS): the `Interface: utunN` line of the
///    connection block, whose value is stable in every language, or cli-tunnel-connected in
///    any of the 17 languages of snx-rs 6.6.1 once the interface is known.
/// An interface that does not exist when the tunnel reports up is a failure, and so is a
/// tunnel not ready when the timeout ends: the helper stops snx-rs.
final class CheckPointSession: SessionObserver {
    enum Source: Equatable { case dns, output }
    private let token: String
    private let recordPath: String
    private let dns: CheckPointDNSStore
    private let host: WireGuardHost
    private let removeAuthority: () -> Void
    var emit: (String) -> Void = { _ in }
    var fail: () -> Void = {}
    var interval: TimeInterval = 1
    var timeout: TimeInterval = 120
    private let lock = NSLock()
    private var record: Record
    private var outputInterface: String?
    private(set) var readySource: Source?
    private var ended = false
    private var failed = false
    private let poller = DispatchQueue(label: "com.luiz.vpngui.helper.checkpoint")
    typealias Record = CheckPointNetwork.Record

    init(token: String, record: Record, recordPath: String, dns: CheckPointDNSStore, host: WireGuardHost,
         removeAuthority: @escaping () -> Void) {
        self.token = token; self.record = record; self.recordPath = recordPath
        self.dns = dns; self.host = host; self.removeAuthority = removeAuthority
    }

    func clientStarted(pid: pid_t) { schedule(deadline: Date().addingTimeInterval(timeout)) }

    private func schedule(deadline: Date) {
        poller.asyncAfter(deadline: .now() + interval) { [weak self] in
            guard let self else { return }
            guard self.waiting() else { return }
            if self.checkDNS() { return }
            if Date() < deadline {
                self.schedule(deadline: deadline)
            } else {
                self.stop(CheckPointRules.networkTimeout + "\(Int(self.timeout.rounded())) s.")
            }
        }
    }

    private func waiting() -> Bool { lock.withLock { readySource == nil && !ended && !failed } }

    /// Once, and only while not ready: a later markReady or failure does nothing.
    private func stop(_ line: String) {
        let first = lock.withLock { () -> Bool in
            guard readySource == nil, !ended, !failed else { return false }
            failed = true
            return true
        }
        guard first else { return }
        emit(line)
        fail()
    }

    /// Ready through the DNS key (path 1).
    @discardableResult private func checkDNS() -> Bool {
        guard let interface = dns.interfaces().first(where: exists) else { return false }
        markReady(interface, source: .dns)
        return true
    }

    private func exists(_ interface: String) -> Bool {
        CheckPointNetwork.validInterface(interface) && host.run(WireGuardTools.ifconfig, [interface]).status == 0
    }

    func clientOutput(_ line: String) {
        let interface = CheckPointOutput.interface(line)
        let connected = CheckPointOutput.classify(line) == .connected
        guard interface != nil || connected else { return }
        let (waiting, known): (Bool, String?) = lock.withLock {
            if let interface { outputInterface = interface }
            return (readySource == nil && !ended && !failed, outputInterface)
        }
        guard waiting, !checkDNS(), let known else { return }
        // Path 2: the gateway sent no DNS (or snx-rs has not published it).
        guard exists(known) else {
            stop(CheckPointRules.networkFailure + " \(known)")
            return
        }
        markReady(known, source: .output)
    }

    private func markReady(_ interface: String, source: Source) {
        let snapshot: Record? = lock.withLock {
            guard readySource == nil, !ended, !failed else { return nil }
            readySource = source
            record.interface = interface
            return record
        }
        guard let snapshot else { return }
        CheckPointNetwork.write(snapshot, to: recordPath)
        if source == .output {
            emit(ServiceLanguage.text("[i] TunnelMac: o gateway Check Point não enviou DNS; nomes internos podem resolver só pelo IP."))
        }
        emit(CheckPointRules.networkReady + interface)
    }

    func clientEnded() {
        let snapshot = lock.withLock { () -> Record in ended = true; return record }
        _ = CheckPointNetwork.cleanup(snapshot, dns: dns, host: host)
        removeAuthority()
        unlink(recordPath)
    }
}
