import Foundation
 
/// The single "Servidor" field of a Fortinet connection, written like FortiClient's
/// remote gateway: host, host:port or host:port/realm (port 443 when omitted).
enum GatewayAddress {
    static let defaultPort = 443

    static func parse(_ input: String) throws -> (host: String, port: Int, realm: String) {
        var value = input.trimmingCharacters(in: .whitespacesAndNewlines)
        if value.lowercased().hasPrefix("https://") { value = String(value.dropFirst("https://".count)) }
        var realm = ""
        if let slash = value.firstIndex(of: "/") {
            realm = String(value[value.index(after: slash)...])
            if realm.hasSuffix("/") { realm.removeLast() }
            value = String(value[..<slash])
        }
        var host = value, port = defaultPort
        if let split = HostPortInput.split(value) {
            host = split.host; port = split.port
        } else if value.filter({ $0 == ":" }).count == 1 {
            throw AppFailure(String(localized: "Porta inválida. Use vpn.exemplo.com ou vpn.exemplo.com:10443."))
        }
        do { host = try ConnectionRules.normalizedHost(host) } catch {
            throw AppFailure(String(localized: "Informe o servidor como vpn.exemplo.com ou vpn.exemplo.com:10443."))
        }
        do { try ConnectionRules.checkRealm(realm) } catch let violation as RuleViolation { throw AppFailure(violation.message) }
        return (host, port, realm)
    }

    /// Text shown in the field and in lists: the port only when it is not 443.
    static func display(host: String, port: Int, realm: String) -> String {
        guard !host.isEmpty else { return "" }
        var text = host
        if port != defaultPort { text += ":\(port)" }
        if !realm.isEmpty { text += (port == defaultPort ? ":\(port)" : "") + "/\(realm)" }
        return text
    }
}

enum HostPortInput {
    static func split(_ input: String) -> (host: String, port: Int)? {
        let value = input.trimmingCharacters(in: .whitespacesAndNewlines)
        let pattern = #"^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+):([0-9]{1,5})$"#
        guard let regex = try? NSRegularExpression(pattern: pattern),
              let match = regex.firstMatch(in: value, range: NSRange(value.startIndex..., in: value)),
              let hostRange = Range(match.range(at: 1), in: value),
              let portRange = Range(match.range(at: 2), in: value),
              let port = Int(value[portRange]), (1...65535).contains(port) else { return nil }
        return (String(value[hostRange]), port)
    }
}
import Security
import Darwin
import VPNHelperShared

struct AppFailure: LocalizedError {
    let message: String
    /// A journaled write stopped halfway; the data stays read-only until the app restarts.
    var pendingRecovery = false
    init(_ message: String, pendingRecovery: Bool = false) { self.message = message; self.pendingRecovery = pendingRecovery }
    var errorDescription: String? { message }
    static func isPendingRecovery(_ error: Error) -> Bool {
        (error as? AppFailure)?.pendingRecovery == true || (error as? BackupImportFailure)?.pendingRecovery == true
    }
}

extension Authentication {
    var title: String { self == .password ? String(localized: "Senha") : "SAML (navegador)" }
}

/// VPN protocol of a saved connection. Existing cadastros (no key) are Fortinet.
enum VPNProtocol: String, Codable, CaseIterable, Identifiable {
    case fortinet, openvpn, wireguard
    var id: String { rawValue }
    var title: String {
        switch self {
        case .fortinet: return "Fortinet SSL VPN"
        case .openvpn: return "OpenVPN"
        case .wireguard: return "WireGuard"
        }
    }
    var runtime: RuntimeKind {
        switch self {
        case .fortinet: return .openfortivpn
        case .openvpn: return .openvpn
        case .wireguard: return .wireguard
        }
    }
}

/// Original files that other macOS users can still read (they may hold private keys).
enum ExposedFiles {
    static func stillExposed(_ paths: [String]?) -> [String] {
        (paths ?? []).filter { path in
            guard let attributes = try? FileManager.default.attributesOfItem(atPath: path),
                  let mode = (attributes[.posixPermissions] as? NSNumber)?.intValue else { return false }
            return mode & 0o077 != 0
        }
    }
}

/// What the app shows about an imported WireGuard profile. The profile itself (with the
/// private key) lives in the WireGuard profile store, never in connections.json.
struct WireGuardSummary: Codable, Equatable {
    var endpoints: [String]
    var addresses: [String]
    var dns: [String]
    var allowedIPs: [String]
    var fullTunnel: Bool
    /// Derived from the private key; the value the server administrator registers.
    var publicKey: String
    var warnings: [String] = []
    var source: String = ""
    var importedAt = Date()
    var exposedOriginals: [String]?
    var stillExposed: [String] { ExposedFiles.stillExposed(exposedOriginals) }
    /// "Todo o tráfego" or the routed networks.
    var routesDescription: String {
        if fullTunnel {
            let defaults = allowedIPs.filter { $0.hasSuffix("/0") }.joined(separator: ", ")
            return String(localized: "Todo o tráfego (\(defaults))")
        }
        return allowedIPs.isEmpty ? String(localized: "Nenhuma rota") : allowedIPs.joined(separator: ", ")
    }
}

/// What the app shows about an imported OpenVPN profile. The profile itself (with its
/// inline certificates and keys) lives in the OpenVPN ProfileStore, never in connections.json.
struct OpenVPNSummary: Codable, Equatable {
    var remotes: [OpenVPNRemote]
    var requiresCredentials: Bool
    var warnings: [String] = []
    var source: String = ""
    var importedAt = Date()
    /// Compatibility option this profile offers (auth RSA-SHAx → SHAx), applied or not.
    var compatibility: OpenVPNCompatibility.DigestFix?
    /// Original key files that other macOS users could read at import time (full paths).
    var exposedOriginals: [String]?

    /// Those originals that still exist and are still readable by others.
    var stillExposed: [String] { ExposedFiles.stillExposed(exposedOriginals) }
}

struct Connection: Codable, Identifiable, Equatable {
    var id = UUID()
    var name = ""
    /// Fortinet gateway. Empty for OpenVPN (servers come from the profile), so an older
    /// app version reading this file can never try such a cadastro with openfortivpn.
    var server = ""
    var port = 443
    /// FortiGate realm ("/realm" in the gateway address), empty when none.
    var realm = ""
    var username = ""
    var authentication: Authentication = .password
    var trustedCertificate = ""
    /// Fortinet only: Keychain identity sent as the client certificate.
    var clientCertificate: ClientCertificateReference?
    var kind: VPNProtocol = .fortinet
    var openVPN: OpenVPNSummary?
    var wireGuard: WireGuardSummary?

    var isOpenVPN: Bool { kind == .openvpn }
    var isWireGuard: Bool { kind == .wireguard }
    /// OpenVPN and WireGuard connections come from an imported profile file.
    var usesProfile: Bool { kind != .fortinet }
    /// Whether connecting needs the password saved in the Keychain.
    var usesPassword: Bool {
        switch kind {
        case .fortinet: return authentication == .password
        case .openvpn: return openVPN?.requiresCredentials ?? false
        case .wireguard: return false
        }
    }
    /// "host:port" for Fortinet, the first remote/endpoint (and how many more) for the others.
    var endpoint: String {
        let servers: [String]
        switch kind {
        case .fortinet:
            let address = GatewayAddress.display(host: server, port: port, realm: realm)
            return address.isEmpty ? kind.title : address
        case .openvpn: servers = (openVPN?.remotes ?? []).map(\.display)
        case .wireguard: servers = wireGuard?.endpoints ?? []
        }
        guard let first = servers.first else { return kind.title }
        return servers.count > 1 ? "\(first) +\(servers.count - 1)" : first
    }

    func validated() throws -> Connection {
        // Same rules the helper applies again to every request.
        var value = self
        value.name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.name.isEmpty else { throw AppFailure(String(localized: "Informe um nome.")) }
        if isWireGuard {
            guard wireGuard != nil else { throw AppFailure(String(localized: "Perfil WireGuard ausente; importe-o novamente.")) }
            value.server = ""
            value.trustedCertificate = ""
            value.clientCertificate = nil
            value.realm = ""
            value.authentication = .password
            value.username = ""
            value.openVPN = nil
            return value
        }
        if isOpenVPN {
            guard let summary = openVPN else { throw AppFailure(String(localized: "Perfil OpenVPN ausente; importe-o novamente.")) }
            value.server = ""
            value.trustedCertificate = ""
            value.clientCertificate = nil
            value.realm = ""
            value.authentication = .password
            value.username = username.trimmingCharacters(in: .whitespacesAndNewlines)
            if summary.requiresCredentials {
                guard !value.username.isEmpty else { throw AppFailure(String(localized: "Informe o usuário.")) }
                do { try OpenVPNRules.checkCredential(value.username, label: String(localized: "Usuário")) }
                catch let violation as RuleViolation { throw AppFailure(violation.message) }
            } else { value.username = "" }
            return value
        }
        do {
            value.server = try ConnectionRules.normalizedHost(server)
            try ConnectionRules.checkPort(port)
            try ConnectionRules.checkRealm(realm)
            try ConnectionRules.checkConfigValue(username, label: String(localized: "Usuário"))
            value.trustedCertificate = try ConnectionRules.normalizedCertificate(trustedCertificate)
        } catch let violation as RuleViolation { throw AppFailure(violation.message) }
        guard authentication != .password || !username.isEmpty else { throw AppFailure(String(localized: "Informe o usuário.")) }
        if let reference = clientCertificate, !ClientCertificateReference.isValidHash(reference.sha1) {
            throw AppFailure(String(localized: "Certificado do cliente inválido; escolha-o de novo."))
        }
        return value
    }

    static func checkConfigValue(_ text: String, label: String) throws {
        do { try ConnectionRules.checkConfigValue(text, label: label) }
        catch let violation as RuleViolation { throw AppFailure(violation.message) }
    }
}

extension Connection {
    enum CodingKeys: String, CodingKey {
        case id, name, server, port, realm, username, authentication, trustedCertificate, clientCertificate, kind, openVPN, wireGuard
    }
    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        id = try values.decode(UUID.self, forKey: .id)
        name = try values.decode(String.self, forKey: .name)
        server = try values.decode(String.self, forKey: .server)
        port = try values.decode(Int.self, forKey: .port)
        realm = try values.decodeIfPresent(String.self, forKey: .realm) ?? ""
        username = try values.decode(String.self, forKey: .username)
        authentication = try values.decode(Authentication.self, forKey: .authentication)
        trustedCertificate = try values.decode(String.self, forKey: .trustedCertificate)
        clientCertificate = try values.decodeIfPresent(ClientCertificateReference.self, forKey: .clientCertificate)
        kind = try values.decodeIfPresent(VPNProtocol.self, forKey: .kind) ?? .fortinet
        openVPN = try values.decodeIfPresent(OpenVPNSummary.self, forKey: .openVPN)
        wireGuard = try values.decodeIfPresent(WireGuardSummary.self, forKey: .wireGuard)
    }
}

struct SavedData: Codable {
    var connections: [Connection] = []
}
