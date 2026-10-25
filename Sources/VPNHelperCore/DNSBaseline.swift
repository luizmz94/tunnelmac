import Foundation
import Darwin
import VPNHelperShared

/// The user's own DNS, saved before the first VPN starts and checked after the last one ends.
///
/// Every client changes the same key, Setup:/Network/Service/<primary>/DNS: WireGuard
/// profiles with DNS, the internet DNS and OpenVPN's dns-updown. Each one undoes its own
/// change, but a client that dies midway (or a dns-updown that fails) can leave a VPN's
/// servers behind. Once no session runs, the key is compared with the saved value and the
/// saved value comes back, unless the current one is what the user configured in System
/// Settings meanwhile (or the saved settings cannot be read). Sessions that start while others run share the first snapshot, so
/// a VPN's own servers are never taken for the user's. Recorded in a root-only file: a
/// helper crash is settled by the next start.
public final class DNSBaseline {
    struct Record: Codable, Equatable {
        var service: String
        /// Binary property list of the Setup: dictionary; nil when there was none (DHCP).
        var original: Data?
    }

    enum Outcome: Equatable {
        case unchanged
        case restored(servers: [String])
        case keptUserChange(servers: [String])
        case failed
    }

    private let host: WireGuardHost
    private let recordPath: String
    private(set) var record: Record?

    public init(host: WireGuardHost, recordPath: String) { self.host = host; self.recordPath = recordPath }

    /// Before a session starts while no other one runs. A snapshot not yet settled (earlier
    /// helper, or a check still waiting for a client's cleanup) is kept: it predates every VPN.
    func capture() {
        if record == nil { record = load() }
        guard record == nil, let service = host.primaryService(), WireGuardTunnel.validService(service) else { return }
        let original = host.dnsSetup(service: service).flatMap {
            try? PropertyListSerialization.data(fromPropertyList: $0, format: .binary, options: 0)
        }
        record = Record(service: service, original: original)
        // Without the file only a helper crash goes unchecked; the session itself is not refused.
        try? SecureFile.replace(recordPath, data: try JSONEncoder().encode(record), mode: 0o600)
    }

    /// After the last session ended and every client undid its own change. nil: nothing saved.
    func settle() -> Outcome? {
        if record == nil { record = load() }
        guard let record else { return nil }
        let current = host.dnsSetup(service: record.service)
        let original = record.original.flatMap { try? PropertyListSerialization.propertyList(from: $0, format: nil) as? [String: Any] }
        if Self.same(current, original) { clear(); return .unchanged }
        let servers = WireGuardTunnel.servers(current)
        // Without the saved settings a network change (configd rewriting the key with the
        // user's configuration) cannot be told from a leftover: leave it.
        guard let configured = host.configuredDNSServers(service: record.service) else { clear(); return .unchanged }
        if configured == servers, !servers.isEmpty {
            clear()
            return .keptUserChange(servers: servers)
        }
        guard host.setDNSSetup(service: record.service, value: original) else { return .failed }
        _ = host.run(WireGuardTools.dscacheutil, ["-flushcache"])
        clear()
        return .restored(servers: WireGuardTunnel.servers(original))
    }

    /// Log line for the last session's log; nil when there is nothing to tell.
    static func message(_ outcome: Outcome?) -> String? {
        switch outcome {
        case .restored(let servers):
            let value = servers.isEmpty ? "automático (da rede)" : servers.joined(separator: ", ")
            return "[#] DNS de antes da VPN restaurado: \(value)."
        case .keptUserChange:
            return "[i] O DNS foi alterado nos Ajustes do Sistema durante a VPN; a nova configuração foi mantida."
        case .failed:
            return "[!] Não foi possível restaurar o DNS de antes da VPN; o serviço tenta novamente."
        case .unchanged, nil:
            return nil
        }
    }

    private func load() -> Record? {
        guard let (data, _) = try? SecureFile.read(recordPath, limit: 256 * 1024) else { return nil }
        return try? JSONDecoder().decode(Record.self, from: data)
    }

    private func clear() { record = nil; unlink(recordPath) }

    private static func same(_ a: [String: Any]?, _ b: [String: Any]?) -> Bool {
        switch (a, b) {
        case (nil, nil): return true
        case let (a?, b?): return NSDictionary(dictionary: a).isEqual(to: b)
        default: return false
        }
    }
}
