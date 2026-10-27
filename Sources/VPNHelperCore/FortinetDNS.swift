import Foundation
import Darwin
import SystemConfiguration
import VPNHelperShared

/// Per-domain resolvers published by the helper in the dynamic store
/// (State:/Network/Service/TunnelMac-<token>/DNS with SupplementalMatchDomains).
/// Production: `SystemSupplementalDNS`; local checks record the calls instead.
public protocol SupplementalDNS: AnyObject {
    func set(token: String, value: [String: Any]) -> Bool
    func remove(token: String)
    /// Tokens of every resolver of ours currently published.
    func tokens() -> [String]
    /// Drops cached answers (including names that failed before the tunnel was up).
    func flush()
}

public final class SystemSupplementalDNS: SupplementalDNS {
    static let prefix = "TunnelMac-"
    private let lock = NSLock()
    private var store: SCDynamicStore?
    public init() {}

    private func key(_ token: String) -> CFString { "State:/Network/Service/\(Self.prefix)\(token)/DNS" as CFString }
    private func dynamicStore() -> SCDynamicStore? {
        if store == nil { store = SCDynamicStoreCreate(nil, "com.luiz.vpngui.helper.dns" as CFString, nil, nil) }
        return store
    }

    public func set(token: String, value: [String: Any]) -> Bool {
        lock.withLock { dynamicStore().map { SCDynamicStoreSetValue($0, key(token), value as CFDictionary) } ?? false }
    }

    public func remove(token: String) {
        lock.withLock { if let store = dynamicStore() { _ = SCDynamicStoreRemoveValue(store, key(token)) } }
    }

    public func tokens() -> [String] {
        lock.withLock {
            guard let store = dynamicStore(),
                  let keys = SCDynamicStoreCopyKeyList(store, "State:/Network/Service/\(Self.prefix)[^/]+/DNS" as CFString) as? [String]
            else { return [] }
            return keys.compactMap { key in
                let service = key.split(separator: "/").dropFirst(3).first.map(String.init) ?? ""
                return service.hasPrefix(Self.prefix) ? String(service.dropFirst(Self.prefix.count)) : nil
            }
        }
    }

    public func flush() {
        _ = try? Probe.run(WireGuardTools.dscacheutil, ["-flushcache"], environment: ["PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C"],
                           identity: nil, timeout: 15_000)
    }
}

/// DNS of an openfortivpn session. On macOS openfortivpn only edits /etc/resolv.conf, which
/// nslookup/dig read but the system resolver (every app) ignores. The helper reads the
/// gateway's servers and domains from openfortivpn's "Got addresses" line and, once the
/// tunnel is up, publishes them as a per-domain resolver: names under those domains go to
/// the VPN's DNS, everything else keeps the current DNS, and several VPNs can coexist.
/// Removed when openfortivpn exits, and by the next helper start if the helper died first.
public final class FortinetDNS: SessionObserver {
    let token: String
    private let store: SupplementalDNS
    var emit: (String) -> Void = { _ in }
    private var servers: [String] = []
    private var domains: [String] = []
    private var applied = false

    init(token: String, store: SupplementalDNS) { self.token = token; self.store = store }

    func clientStarted(pid: pid_t) {}

    func clientOutput(_ line: String) {
        if let parsed = Self.parse(line) {
            (servers, domains) = parsed
        } else if !applied, line.contains("Tunnel is up and running") {
            apply()
        }
    }

    func clientEnded() {
        guard applied else { return }
        store.remove(token: token)
        store.flush()
        applied = false
    }

    private func apply() {
        guard !servers.isEmpty else { return }
        guard !domains.isEmpty else {
            emit(ServiceLanguage.text("[!] O gateway não informou domínios de DNS; nomes internos podem não resolver nos apps (só pelo IP)."))
            return
        }
        let value: [String: Any] = ["ServerAddresses": servers, "SupplementalMatchDomains": domains]
        if store.set(token: token, value: value) {
            applied = true
            store.flush()
            let list = servers.joined(separator: ", "), names = domains.joined(separator: ", ")
            emit(ServiceLanguage.text("[#] DNS da VPN (\(list)) para \(names); os demais nomes seguem no DNS atual."))
        } else {
            emit(ServiceLanguage.text("[!] Não foi possível registrar o DNS da VPN no sistema; nomes internos podem não resolver nos apps."))
        }
    }

    /// `INFO:   Got addresses: [ip], ns [a.b.c.d, e.f.g.h], ns_suffix [dom1;dom2]` (io.c).
    /// Values come from the gateway: only literal IPv4 addresses and plain domain names pass.
    public static func parse(_ line: String) -> (servers: [String], domains: [String])? {
        guard let range = line.range(of: "Got addresses: ") else { return nil }
        let text = line[range.upperBound...]
        func bracket(after label: String) -> String? {
            guard let start = text.range(of: label + "[") else { return nil }
            guard let end = text[start.upperBound...].firstIndex(of: "]") else { return nil }
            return String(text[start.upperBound..<end])
        }
        let separators = CharacterSet(charactersIn: ",; ")
        var servers: [String] = []
        for item in (bracket(after: "ns ") ?? "").components(separatedBy: separators) where !item.isEmpty {
            var address = in_addr()
            guard inet_pton(AF_INET, item, &address) == 1, address.s_addr != 0, !servers.contains(item) else { continue }
            servers.append(item)
        }
        var domains: [String] = []
        for raw in (bracket(after: "ns_suffix ") ?? "").components(separatedBy: separators) where !raw.isEmpty {
            let domain = raw.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
            guard validDomain(domain), !domains.contains(domain), domains.count < 16 else { continue }
            domains.append(domain)
        }
        return (servers, domains)
    }

    static func validDomain(_ value: String) -> Bool {
        guard !value.isEmpty, value.count <= 253 else { return false }
        let labels = value.split(separator: ".", omittingEmptySubsequences: false)
        return labels.allSatisfy { label in
            !label.isEmpty && label.count <= 63 && !label.hasPrefix("-") && !label.hasSuffix("-")
                && label.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_") }
        }
    }
}

/// Several observers on one session, called in order.
final class SessionObservers: SessionObserver {
    var cleanupFailure: String? { observers.compactMap(\.cleanupFailure).first }
    private let observers: [SessionObserver]
    init(_ observers: [SessionObserver]) { self.observers = observers }
    func clientStarted(pid: pid_t) { observers.forEach { $0.clientStarted(pid: pid) } }
    func clientOutput(_ line: String) { observers.forEach { $0.clientOutput(line) } }
    func clientEnded() { observers.forEach { $0.clientEnded() } }
}
