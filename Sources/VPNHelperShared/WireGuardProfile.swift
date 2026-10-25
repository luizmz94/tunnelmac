import Foundation
import Darwin

/// An IPv4 or IPv6 address with a prefix length, already validated and in canonical text.
public struct WireGuardCIDR: Codable, Equatable, Hashable, Sendable {
    public var address: String
    public var prefix: Int
    public var isIPv6: Bool
    public var text: String { "\(address)/\(prefix)" }
    /// 0.0.0.0/0 or ::/0: every address of the family goes through the tunnel.
    public var isDefault: Bool { prefix == 0 }

    public init(address: String, prefix: Int, isIPv6: Bool) {
        self.address = address; self.prefix = prefix; self.isIPv6 = isIPv6
    }

    /// True for any prefix covering a literal endpoint, including split defaults.
    public func contains(_ literal: String) -> Bool {
        guard let (_, v6) = WireGuardAddress.canonical(literal), v6 == isIPv6 else { return false }
        var network = [UInt8](repeating: 0, count: isIPv6 ? 16 : 4)
        var candidate = network
        guard inet_pton(isIPv6 ? AF_INET6 : AF_INET, address, &network) == 1,
              inet_pton(isIPv6 ? AF_INET6 : AF_INET, literal, &candidate) == 1 else { return false }
        for bit in 0..<prefix {
            let mask = UInt8(1 << (7 - bit % 8))
            if network[bit / 8] & mask != candidate[bit / 8] & mask { return false }
        }
        return true
    }

    /// "10.8.0.3/32", "fd00::3/128" or a bare address (full-length prefix).
    public static func parse(_ value: String) throws -> WireGuardCIDR {
        let parts = value.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard parts.count <= 2, let (address, isIPv6) = WireGuardAddress.canonical(parts[0]) else {
            throw RuleViolation("Endereço IP inválido: \(value)")
        }
        let maximum = isIPv6 ? 128 : 32
        var prefix = maximum
        if parts.count == 2 {
            guard parts[1].count <= 3, parts[1].allSatisfy({ $0.isASCII && $0.isNumber }), let number = Int(parts[1]), number <= maximum else {
                throw RuleViolation("Prefixo inválido em \(value)")
            }
            prefix = number
        }
        return WireGuardCIDR(address: address, prefix: prefix, isIPv6: isIPv6)
    }
}

public enum WireGuardAddress {
    /// Canonical text of a literal IPv4/IPv6 address (inet_pton → inet_ntop), nil otherwise.
    public static func canonical(_ value: String) -> (String, Bool)? {
        guard !value.isEmpty, value.utf8.count <= 64, value.allSatisfy({ $0.isASCII && ($0.isHexDigit || $0 == "." || $0 == ":") }) else { return nil }
        var v4 = in_addr()
        if value.contains("."), !value.contains(":"), inet_pton(AF_INET, value, &v4) == 1 {
            var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            guard inet_ntop(AF_INET, &v4, &buffer, socklen_t(buffer.count)) != nil else { return nil }
            return (String(cString: buffer), false)
        }
        var v6 = in6_addr()
        if value.contains(":"), inet_pton(AF_INET6, value, &v6) == 1 {
            var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            guard inet_ntop(AF_INET6, &v6, &buffer, socklen_t(buffer.count)) != nil else { return nil }
            return (String(cString: buffer), true)
        }
        return nil
    }
}

/// Peer endpoint: hostname, IPv4 or [IPv6], and a UDP port.
public struct WireGuardEndpoint: Codable, Equatable, Sendable {
    public var host: String
    public var port: Int
    public var display: String { host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)" }

    public init(host: String, port: Int) { self.host = host; self.port = port }

    public static func parse(_ value: String) throws -> WireGuardEndpoint {
        let host: String, portText: String
        if value.hasPrefix("[") {
            guard let close = value.firstIndex(of: "]"), value[value.index(after: close)...].hasPrefix(":") else {
                throw RuleViolation("Endpoint inválido: \(value)")
            }
            host = String(value[value.index(after: value.startIndex)..<close])
            portText = String(value[value.index(close, offsetBy: 2)...])
            guard let (canonical, isIPv6) = WireGuardAddress.canonical(host), isIPv6 else { throw RuleViolation("Endpoint inválido: \(value)") }
            return try WireGuardEndpoint(host: canonical, port: port(portText, value))
        }
        guard let colon = value.lastIndex(of: ":"), !value[..<colon].contains(":") else {
            throw RuleViolation("Endpoint precisa ter servidor e porta (servidor:porta): \(value)")
        }
        host = String(value[..<colon])
        portText = String(value[value.index(after: colon)...])
        if let (canonical, _) = WireGuardAddress.canonical(host) { return try WireGuardEndpoint(host: canonical, port: port(portText, value)) }
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-")
        guard !host.isEmpty, host.count <= 253, host.unicodeScalars.allSatisfy(allowed.contains), !host.hasPrefix("-"), !host.hasPrefix("."),
              !host.contains("..") else {
            throw RuleViolation("Servidor inválido no endpoint: \(value)")
        }
        return try WireGuardEndpoint(host: host.lowercased(), port: port(portText, value))
    }

    private static func port(_ text: String, _ value: String) throws -> Int {
        guard (1...5).contains(text.count), text.allSatisfy({ $0.isASCII && $0.isNumber }), let port = Int(text), (1...65535).contains(port) else {
            throw RuleViolation("Porta inválida no endpoint: \(value)")
        }
        return port
    }
}

public struct WireGuardPeer: Codable, Equatable, Sendable {
    public var publicKey: String
    public var presharedKey: String?
    public var endpoint: WireGuardEndpoint?
    public var allowedIPs: [WireGuardCIDR]
    public var persistentKeepalive: Int?
    public init(publicKey: String, presharedKey: String? = nil, endpoint: WireGuardEndpoint? = nil,
                allowedIPs: [WireGuardCIDR] = [], persistentKeepalive: Int? = nil) {
        self.publicKey = publicKey; self.presharedKey = presharedKey; self.endpoint = endpoint
        self.allowedIPs = allowedIPs; self.persistentKeepalive = persistentKeepalive
    }
}

/// A wg-quick style configuration (one [Interface], one or more [Peer]) reduced to what the
/// service implements itself. PreUp/PostUp/PreDown/PostDown, SaveConfig and FwMark are never
/// part of a normalized profile: the app drops them at import (with a warning) and the
/// helper refuses any profile that still has them. Unknown keys refuse the import.
public struct WireGuardProfile: Equatable, Sendable {
    public enum Table: String, Equatable, Sendable { case auto, off }

    public var privateKey: String
    public var listenPort: Int?
    public var addresses: [WireGuardCIDR]
    public var dnsServers: [String]
    public var dnsSearch: [String]
    public var mtu: Int?
    public var table: Table
    public var peers: [WireGuardPeer]

    public static let maximumSize = 64 * 1024
    public static let maximumPeers = 64
    public static let maximumEntries = 256

    /// Keys removed at import, with the reason shown to the user.
    public static let dropped: [String: String] = [
        "preup": "comandos executados como root pelo wg-quick; o TunnelMac não executa scripts do perfil",
        "postup": "comandos executados como root pelo wg-quick; o TunnelMac não executa scripts do perfil",
        "predown": "comandos executados como root pelo wg-quick; o TunnelMac não executa scripts do perfil",
        "postdown": "comandos executados como root pelo wg-quick; o TunnelMac não executa scripts do perfil",
        "saveconfig": "o TunnelMac nunca regrava o perfil a partir da interface",
        "fwmark": "marcação de pacotes não existe no macOS"
    ]

    public init(privateKey: String, listenPort: Int? = nil, addresses: [WireGuardCIDR], dnsServers: [String] = [],
                dnsSearch: [String] = [], mtu: Int? = nil, table: Table = .auto, peers: [WireGuardPeer]) {
        self.privateKey = privateKey; self.listenPort = listenPort; self.addresses = addresses
        self.dnsServers = dnsServers; self.dnsSearch = dnsSearch; self.mtu = mtu; self.table = table; self.peers = peers
    }

    public struct Parsed: Equatable, Sendable {
        public var profile: WireGuardProfile
        /// Keys removed (spelling of their first appearance), in order.
        public var dropped: [String]
    }

    /// Strict check used by the helper and when reading the app's saved copy.
    public static func validated(_ text: String) throws -> WireGuardProfile {
        let parsed = try parse(text)
        guard parsed.dropped.isEmpty else {
            throw RuleViolation("O perfil WireGuard contém \(parsed.dropped.joined(separator: ", ")), que o serviço não aceita.")
        }
        return parsed.profile
    }

    public static func parse(_ text: String) throws -> Parsed {
        guard text.utf8.count <= maximumSize else { throw RuleViolation("O perfil WireGuard passa de 64 KB.") }
        guard !text.unicodeScalars.contains(where: { $0.value == 0 }) else { throw RuleViolation("O perfil WireGuard contém bytes nulos.") }
        enum Section { case none, interface, peer }
        var section = Section.none
        var interfaceSeen = false
        var privateKey: String?
        var listenPort: Int?
        var addresses: [WireGuardCIDR] = []
        var dnsServers: [String] = [], dnsSearch: [String] = []
        var mtu: Int?
        var table = Table.auto
        var peers: [WireGuardPeer] = []
        var current: WireGuardPeer?
        var currentHasKey = false
        var dropped: [String] = []
        var entries = 0
        func finishPeer() throws {
            guard let peer = current else { return }
            guard currentHasKey else { throw RuleViolation("Um [Peer] do perfil não tem PublicKey.") }
            peers.append(peer)
            current = nil; currentHasKey = false
        }
        func list(_ value: String) -> [String] {
            value.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        }
        func count(_ added: Int) throws {
            entries += added
            guard entries <= maximumEntries else { throw RuleViolation("O perfil WireGuard tem entradas demais.") }
        }
        let lines = text.replacingOccurrences(of: "\r\n", with: "\n").split(separator: "\n", omittingEmptySubsequences: false)
        for (index, raw) in lines.enumerated() {
            let number = index + 1
            let line = String(raw.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false).first ?? "")
                .trimmingCharacters(in: .whitespaces)
            if line.isEmpty { continue }
            guard !line.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) && $0 != "\t" }) else {
                throw RuleViolation("Linha \(number): caracteres de controle não são aceitos.")
            }
            if line.hasPrefix("[") {
                switch line.lowercased() {
                case "[interface]":
                    guard !interfaceSeen else { throw RuleViolation("Linha \(number): o perfil tem mais de uma seção [Interface].") }
                    try finishPeer()
                    interfaceSeen = true
                    section = .interface
                case "[peer]":
                    try finishPeer()
                    guard peers.count < maximumPeers else { throw RuleViolation("O perfil WireGuard tem peers demais.") }
                    current = WireGuardPeer(publicKey: "")
                    section = .peer
                default:
                    throw RuleViolation("Linha \(number): seção \(line) desconhecida.")
                }
                continue
            }
            guard let equals = line.firstIndex(of: "=") else { throw RuleViolation("Linha \(number): esperado Chave = Valor.") }
            let name = line[..<equals].trimmingCharacters(in: .whitespaces)
            let value = line[line.index(after: equals)...].trimmingCharacters(in: .whitespaces)
            let key = name.lowercased()
            if Self.dropped[key] != nil, section == .interface {
                if !dropped.contains(where: { $0.lowercased() == key }) { dropped.append(name) }
                continue
            }
            switch section {
            case .none:
                throw RuleViolation("Linha \(number): \(name) fora de uma seção [Interface] ou [Peer].")
            case .interface:
                switch key {
                case "privatekey":
                    guard privateKey == nil else { throw RuleViolation("Linha \(number): PrivateKey repetida.") }
                    privateKey = try WireGuardKey.check(value, label: "PrivateKey")
                case "listenport":
                    guard let port = Int(value), (0...65535).contains(port), value.allSatisfy({ $0.isASCII && $0.isNumber }) else {
                        throw RuleViolation("Linha \(number): ListenPort inválida.")
                    }
                    listenPort = port
                case "address":
                    let items = list(value)
                    try count(items.count)
                    for item in items { addresses.append(try WireGuardCIDR.parse(item)) }
                case "dns":
                    let items = list(value)
                    try count(items.count)
                    for item in items {
                        if let (canonical, _) = WireGuardAddress.canonical(item) { dnsServers.append(canonical) }
                        else { dnsSearch.append(try checkDomain(item, line: number)) }
                    }
                case "mtu":
                    guard let number = Int(value), (576...9000).contains(number), value.allSatisfy({ $0.isASCII && $0.isNumber }) else {
                        throw RuleViolation("Linha \(number): MTU deve estar entre 576 e 9000.")
                    }
                    mtu = number
                case "table":
                    switch value.lowercased() {
                    case "auto", "main": table = .auto
                    case "off": table = .off
                    default: throw RuleViolation("Linha \(number): Table = \(value) não é suportado no macOS (use auto, main ou off).")
                    }
                default:
                    throw RuleViolation("Linha \(number): \(name) não é uma opção de [Interface] que o app suporte.")
                }
            case .peer:
                guard var peer = current else { continue }
                switch key {
                case "publickey":
                    guard !currentHasKey else { throw RuleViolation("Linha \(number): PublicKey repetida no mesmo [Peer].") }
                    peer.publicKey = try WireGuardKey.check(value, label: "PublicKey")
                    currentHasKey = true
                case "presharedkey":
                    guard peer.presharedKey == nil else { throw RuleViolation("Linha \(number): PresharedKey repetida.") }
                    peer.presharedKey = try WireGuardKey.check(value, label: "PresharedKey")
                case "endpoint":
                    guard peer.endpoint == nil else { throw RuleViolation("Linha \(number): Endpoint repetido no mesmo [Peer].") }
                    peer.endpoint = try WireGuardEndpoint.parse(value)
                case "allowedips":
                    let items = list(value)
                    try count(items.count)
                    for item in items { peer.allowedIPs.append(try WireGuardCIDR.parse(item)) }
                case "persistentkeepalive":
                    if value.lowercased() == "off" { peer.persistentKeepalive = nil; break }
                    guard let seconds = Int(value), (0...65535).contains(seconds), value.allSatisfy({ $0.isASCII && $0.isNumber }) else {
                        throw RuleViolation("Linha \(number): PersistentKeepalive inválido.")
                    }
                    peer.persistentKeepalive = seconds == 0 ? nil : seconds
                default:
                    throw RuleViolation("Linha \(number): \(name) não é uma opção de [Peer] que o app suporte.")
                }
                current = peer
            }
        }
        try finishPeer()
        guard interfaceSeen, let privateKey else { throw RuleViolation("O perfil não tem [Interface] com PrivateKey; não parece um perfil WireGuard.") }
        guard !peers.isEmpty else { throw RuleViolation("O perfil não tem nenhum [Peer].") }
        guard Set(peers.map(\.publicKey)).count == peers.count else { throw RuleViolation("Dois [Peer] usam a mesma PublicKey.") }
        guard !addresses.isEmpty else { throw RuleViolation("O perfil não tem Address em [Interface].") }
        let profile = WireGuardProfile(privateKey: privateKey, listenPort: listenPort, addresses: addresses, dnsServers: dnsServers,
                                       dnsSearch: dnsSearch, mtu: mtu, table: table, peers: peers)
        return Parsed(profile: profile, dropped: dropped)
    }

    static func checkDomain(_ value: String, line: Int) throws -> String {
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_")
        guard !value.isEmpty, value.count <= 253, value.unicodeScalars.allSatisfy(allowed.contains), !value.hasPrefix("-"), !value.hasPrefix(".") else {
            throw RuleViolation("Linha \(line): DNS \(value) não é um IP nem um domínio de busca válido.")
        }
        return value.lowercased()
    }

    /// Canonical text saved by the app and sent to the helper (keys in wg-quick spelling).
    public var text: String {
        var lines = ["[Interface]", "PrivateKey = \(privateKey)"]
        if let listenPort { lines.append("ListenPort = \(listenPort)") }
        lines.append("Address = " + addresses.map(\.text).joined(separator: ", "))
        if !dnsServers.isEmpty || !dnsSearch.isEmpty { lines.append("DNS = " + (dnsServers + dnsSearch).joined(separator: ", ")) }
        if let mtu { lines.append("MTU = \(mtu)") }
        if table == .off { lines.append("Table = off") }
        for peer in peers {
            lines += ["", "[Peer]", "PublicKey = \(peer.publicKey)"]
            if let key = peer.presharedKey { lines.append("PresharedKey = \(key)") }
            if !peer.allowedIPs.isEmpty { lines.append("AllowedIPs = " + peer.allowedIPs.map(\.text).joined(separator: ", ")) }
            if let endpoint = peer.endpoint { lines.append("Endpoint = \(endpoint.display)") }
            if let keepalive = peer.persistentKeepalive { lines.append("PersistentKeepalive = \(keepalive)") }
        }
        return lines.joined(separator: "\n") + "\n"
    }

    /// Every allowed IP of every peer, without repeats.
    public var allowedIPs: [WireGuardCIDR] {
        var seen = Set<WireGuardCIDR>()
        return peers.flatMap(\.allowedIPs).filter { seen.insert($0).inserted }
    }
    public var routesAllIPv4: Bool { table == .auto && allowedIPs.contains { $0.isDefault && !$0.isIPv6 } }
    public var routesAllIPv6: Bool { table == .auto && allowedIPs.contains { $0.isDefault && $0.isIPv6 } }

    /// Configuration for wireguard-go's UAPI socket ("set=1" request). Endpoints must
    /// already be resolved to literal addresses, in peer order (nil for peers without one).
    public func uapiConfiguration(endpoints: [String?]) throws -> String {
        guard endpoints.count == peers.count else { throw RuleViolation("Endpoints resolvidos não correspondem aos peers.") }
        var lines = ["set=1", "private_key=" + (try WireGuardKey.hex(privateKey))]
        if let listenPort { lines.append("listen_port=\(listenPort)") }
        lines.append("replace_peers=true")
        for (peer, endpoint) in zip(peers, endpoints) {
            lines.append("public_key=" + (try WireGuardKey.hex(peer.publicKey)))
            if let key = peer.presharedKey { lines.append("preshared_key=" + (try WireGuardKey.hex(key))) }
            if let endpoint { lines.append("endpoint=" + endpoint) }
            if let keepalive = peer.persistentKeepalive { lines.append("persistent_keepalive_interval=\(keepalive)") }
            lines.append("replace_allowed_ips=true")
            for ip in peer.allowedIPs { lines.append("allowed_ip=" + ip.text) }
        }
        return lines.joined(separator: "\n") + "\n\n"
    }
}

/// Curve25519 keys in WireGuard's base64 form (32 bytes).
public enum WireGuardKey {
    public static func decode(_ value: String) -> Data? {
        guard value.count == 44, value.hasSuffix("="), let data = Data(base64Encoded: value), data.count == 32 else { return nil }
        return data
    }
    static func check(_ value: String, label: String) throws -> String {
        guard decode(value) != nil else { throw RuleViolation("\(label) não é uma chave WireGuard válida (base64 de 32 bytes).") }
        return value
    }
    public static func hex(_ value: String) throws -> String {
        guard let data = decode(value) else { throw RuleViolation("Chave WireGuard inválida.") }
        return data.map { String(format: "%02x", $0) }.joined()
    }
    /// Short form used by wireguard-go's log ("ZTJk…f2Tw"), never the private key.
    public static func short(_ value: String) -> String { value.count > 8 ? "\(value.prefix(4))…\(value.dropLast().suffix(4))" : value }
}

/// Lines the helper adds to a WireGuard session's log. The app recognizes the ready marker.
public enum WireGuardMarkers {
    public static let ready = "[+] TunnelMac: túnel WireGuard configurado"
    public static let handshake = "[+] TunnelMac: handshake concluído"
    public static let failure = "ERROR: TunnelMac:"
}

extension RuntimeCapabilities {
    /// `wireguard-go --version`: "wireguard-go v0.0.20250522\n\nUserspace WireGuard daemon for darwin-arm64."
    public static func looksLikeWireGuardGo(_ version: String) -> Bool {
        version.hasPrefix("wireguard-go v") && version.contains("Userspace WireGuard daemon for darwin")
    }
}
