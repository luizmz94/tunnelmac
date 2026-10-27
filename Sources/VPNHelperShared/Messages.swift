import Foundation

// MARK: - XPC interfaces

/// The only exported surface of the helper: a closed set of typed requests
/// (`HelperRequest`), each size-limited and validated before it is handled.
/// There is no command, script, PID, file path to write, or free argument vector.
@objc public protocol VPNHelperXPC {
    func perform(_ request: Data, reply: @escaping (Data) -> Void)
}

/// Exported by the app so the helper can stream the events of the app's own sessions.
/// The reply acknowledges a batch; the helper sends the next one only afterwards.
@objc public protocol VPNHelperClientXPC {
    func deliver(_ batch: Data, reply: @escaping () -> Void)
}

public enum HelperInterfaces {
    public static func helper() -> NSXPCInterface { NSXPCInterface(with: VPNHelperXPC.self) }
    public static func client() -> NSXPCInterface { NSXPCInterface(with: VPNHelperClientXPC.self) }
}

// MARK: - Requests

public struct HelloRequest: Codable, Equatable, Sendable {
    public var protocolVersion: Int
    public var appVersion: String
    /// Language the app shows (a tag such as "de" or "pt-BR"); the helper's messages follow it.
    public var language: String?
    public init(protocolVersion: Int = HelperConstants.protocolVersion, appVersion: String, language: String? = nil) {
        self.protocolVersion = protocolVersion; self.appVersion = appVersion; self.language = language
    }
}

/// Structured connection data. Secrets travel only inside this authenticated message
/// and are written by the helper to its own protected descriptors.
public struct ConnectionRequest: Codable, Equatable, Sendable {
    public var connectionID: UUID
    public var host: String
    public var port: Int
    public var username: String
    public var authentication: Authentication
    public var trustedCertificate: String
    public var password: String?
    public var mode: SAMLCookieMode
    public var cookie: String?
    /// Optional client certificate (exported from the user's Keychain for this connection).
    public var clientCertificate: ClientCertificate?
    /// FortiGate realm; nil or empty when the gateway has none.
    public var realm: String?
    /// "DNS da internet" chosen in the app; nil = leave the system DNS alone.
    public var internetDNS: [String]?
    public init(connectionID: UUID, host: String, port: Int, username: String, authentication: Authentication,
                trustedCertificate: String, password: String?, mode: SAMLCookieMode, cookie: String?,
                clientCertificate: ClientCertificate? = nil, realm: String? = nil, internetDNS: [String]? = nil) {
        self.connectionID = connectionID; self.host = host; self.port = port; self.username = username
        self.authentication = authentication; self.trustedCertificate = trustedCertificate
        self.password = password; self.mode = mode; self.cookie = cookie; self.clientCertificate = clientCertificate
        self.realm = realm; self.internetDNS = internetDNS
    }

    /// Validation run by the helper against the approved runtime. Returns the plan the
    /// helper will execute; the app's requested mode must match it exactly.
    public func validatedPlan(capabilities: RuntimeCapabilities) throws -> LaunchPlan {
        _ = try ConfigRenderer.render(host: host, port: port, username: username, password: nil,
                                      trustedCertificate: trustedCertificate, realm: realm ?? "")
        _ = try clientCertificate?.validated()
        if let internetDNS { _ = try ConnectionRules.internetDNS(internetDNS) }
        switch authentication {
        case .password:
            guard let password, !password.isEmpty, !username.isEmpty else {
                throw RuleViolation(ServiceLanguage.text("Perfil por senha exige usuário e senha."))
            }
            try ConnectionRules.checkConfigValue(password, label: ServiceLanguage.text("Senha"))
            guard mode == .none, cookie == nil else { throw RuleViolation(ServiceLanguage.text("Perfil por senha não usa sessão SAML.")) }
        case .saml:
            guard password == nil else { throw RuleViolation(ServiceLanguage.text("Perfil SAML não envia senha.")) }
            if mode == .reuse {
                guard let cookie, SAMLCookieRules.isValid(cookie) else { throw RuleViolation(ServiceLanguage.text("Sessão SAML em formato inesperado.")) }
                guard capabilities.cookieOnStdin else { throw RuleViolation(ServiceLanguage.text("O openfortivpn aprovado não lê a sessão SAML pela entrada padrão.")) }
            } else {
                guard cookie == nil else { throw RuleViolation(ServiceLanguage.text("Sessão SAML enviada sem modo de reaproveitamento.")) }
                guard capabilities.samlPort else {
                    throw RuleViolation(ServiceLanguage.text("Esta versão não documenta --saml-login[=port]; atualize o openfortivpn para usar a porta de callback SAML explícita."))
                }
            }
        }
        let plan = LaunchPlan.make(authentication: authentication, capabilities: capabilities, cookieAvailable: mode == .reuse)
        guard plan.mode == mode else { throw RuleViolation(ServiceLanguage.text("Modo de sessão incompatível com o openfortivpn aprovado.")) }
        return plan
    }
}

/// OpenVPN session: a normalized profile (inline material only) plus optional credentials.
/// The helper validates the profile with the same allowlist and renders the final config.
public struct OpenVPNRequest: Codable, Equatable, Sendable {
    public var connectionID: UUID
    public var profile: String
    public var username: String?
    public var password: String?
    public init(connectionID: UUID, profile: String, username: String?, password: String?) {
        self.connectionID = connectionID; self.profile = profile; self.username = username; self.password = password
    }
}

/// WireGuard session: a normalized wg-quick style profile. The helper validates it again,
/// sends the keys to wireguard-go over its root-only UAPI socket and configures addresses,
/// routes and DNS itself; no PreUp/PostUp script exists in a normalized profile.
public struct WireGuardRequest: Codable, Equatable, Sendable {
    public var connectionID: UUID
    public var profile: String
    /// "DNS da internet"; used only when the profile has no DNS of its own.
    public var internetDNS: [String]?
    public init(connectionID: UUID, profile: String, internetDNS: [String]? = nil) {
        self.connectionID = connectionID; self.profile = profile; self.internetDNS = internetDNS
    }
}

/// The VPN clients the helper can freeze and run. Each has its own approved copy.
public enum RuntimeKind: String, Codable, CaseIterable, Sendable {
    case openfortivpn, openvpn, wireguard
    public var executableName: String { self == .wireguard ? "wireguard-go" : rawValue }
    public var title: String {
        switch self {
        case .openfortivpn: return "openfortivpn"
        case .openvpn: return "OpenVPN"
        case .wireguard: return "WireGuard"
        }
    }
}

public enum HelperRequest: Codable, Equatable, Sendable {
    case hello(HelloRequest)
    case status
    /// Read-only inventory of a candidate installation (discovery hint from the app).
    case inspectRuntime(path: String)
    /// Distinct, admin-authorized operation: copies the inventory the helper itself
    /// computed (must equal `digest`) into the protected runtime and authorizes the caller.
    case approveRuntime(path: String, digest: String, authorization: Data)
    /// Admin-authorized removal of the helper's own managed files (no active sessions).
    case removeManagedFiles(authorization: Data)
    case start(ConnectionRequest)
    /// Same flow for the OpenVPN runtime (inventory includes its dns-updown script).
    case inspectOpenVPNRuntime(path: String)
    case approveOpenVPNRuntime(path: String, digest: String, authorization: Data)
    case startOpenVPN(OpenVPNRequest)
    /// Same flow for wireguard-go (a single static Mach-O; no script is frozen).
    case inspectWireGuardRuntime(path: String)
    case approveWireGuardRuntime(path: String, digest: String, authorization: Data)
    case startWireGuard(WireGuardRequest)
    case stop(token: String)
    case stopAll
    /// Refuse unless every client and stale supervisor is idle; prevent new starts.
    case prepareForMaintenance
    case cancelMaintenance
}

// MARK: - Responses

public struct RuntimeSummary: Codable, Equatable, Sendable {
    public var id: String
    public var version: String
    public var approvedAt: Date
    public var capabilities: RuntimeCapabilities
    public var sourcePath: String
    public var sourceSHA256: String
    public var sources: [InventoryItem]?
    public var inventoryDigest: String?
    public init(id: String, version: String, approvedAt: Date, capabilities: RuntimeCapabilities, sourcePath: String, sourceSHA256: String, sources: [InventoryItem]? = nil, inventoryDigest: String? = nil) {
        self.id = id; self.version = version; self.approvedAt = approvedAt; self.capabilities = capabilities
        self.sourcePath = sourcePath; self.sourceSHA256 = sourceSHA256; self.sources = sources; self.inventoryDigest = inventoryDigest
    }
}

public struct HelperStatus: Codable, Equatable, Sendable {
    public var protocolVersion: Int
    public var helperVersion: String
    public var runtime: RuntimeSummary?
    /// Why the runtime is unusable right now (missing, altered, untrusted path...).
    public var runtimeProblem: String?
    public var userAuthorized: Bool
    /// Sessions owned by this connection.
    public var activeSessions: Int
    /// Profiles of this user whose previous supervisor (from an earlier helper process or
    /// connection) is still alive. They are never adopted; new starts wait for them to end.
    public var stoppingConnections: [UUID]
    /// Approved OpenVPN copy, independent of the openfortivpn one.
    public var openVPNRuntime: RuntimeSummary?
    public var openVPNRuntimeProblem: String?
    /// Approved wireguard-go copy.
    public var wireGuardRuntime: RuntimeSummary?
    public var wireGuardRuntimeProblem: String?
    public init(protocolVersion: Int, helperVersion: String, runtime: RuntimeSummary?, runtimeProblem: String?,
                userAuthorized: Bool, activeSessions: Int, stoppingConnections: [UUID],
                openVPNRuntime: RuntimeSummary? = nil, openVPNRuntimeProblem: String? = nil,
                wireGuardRuntime: RuntimeSummary? = nil, wireGuardRuntimeProblem: String? = nil) {
        self.protocolVersion = protocolVersion; self.helperVersion = helperVersion; self.runtime = runtime
        self.runtimeProblem = runtimeProblem; self.userAuthorized = userAuthorized
        self.activeSessions = activeSessions; self.stoppingConnections = stoppingConnections
        self.openVPNRuntime = openVPNRuntime; self.openVPNRuntimeProblem = openVPNRuntimeProblem
        self.wireGuardRuntime = wireGuardRuntime; self.wireGuardRuntimeProblem = wireGuardRuntimeProblem
    }
    public func runtime(_ kind: RuntimeKind) -> RuntimeSummary? {
        switch kind {
        case .openfortivpn: return runtime
        case .openvpn: return openVPNRuntime
        case .wireguard: return wireGuardRuntime
        }
    }
    public func runtimeProblem(_ kind: RuntimeKind) -> String? {
        switch kind {
        case .openfortivpn: return runtimeProblem
        case .openvpn: return openVPNRuntimeProblem
        case .wireguard: return wireGuardRuntimeProblem
        }
    }
    /// At least one VPN client is approved.
    public var anyRuntime: Bool { RuntimeKind.allCases.contains { runtime($0) != nil } }
}

public struct InventoryItem: Codable, Equatable, Sendable {
    public enum Role: String, Codable, Sendable { case executable, library, script }
    public var role: Role
    public var sourcePath: String
    public var sha256: String
    public var size: Int
    public var ownerUID: UInt32
    /// The file or one of its directories can be changed without root.
    public var mutableLocation: Bool
    public init(role: Role, sourcePath: String, sha256: String, size: Int, ownerUID: UInt32, mutableLocation: Bool) {
        self.role = role; self.sourcePath = sourcePath; self.sha256 = sha256; self.size = size
        self.ownerUID = ownerUID; self.mutableLocation = mutableLocation
    }
}

public struct RuntimeInspection: Codable, Equatable, Sendable {
    public var candidatePath: String
    public var resolvedPath: String
    /// Digest over the whole inventory, computed by the helper (not by the client).
    public var digest: String
    public var items: [InventoryItem]
    public var systemLibraries: [String]
    public var packageVersion: String?
    public var warnings: [String]
    public var kind: RuntimeKind
    public init(candidatePath: String, resolvedPath: String, digest: String, items: [InventoryItem],
                systemLibraries: [String], packageVersion: String?, warnings: [String], kind: RuntimeKind = .openfortivpn) {
        self.candidatePath = candidatePath; self.resolvedPath = resolvedPath; self.digest = digest; self.items = items
        self.systemLibraries = systemLibraries; self.packageVersion = packageVersion; self.warnings = warnings
        self.kind = kind
    }
}

public struct HelperFailure: Codable, Error, LocalizedError, Equatable, Sendable {
    public enum Code: String, Codable, Sendable {
        case invalidRequest, handshakeRequired, incompatibleProtocol, userNotAuthorized
        case runtimeUnavailable, runtimeRejected, authorizationDenied, duplicateSession
        case unknownSession, limitReached, busy, internalError, transport, unavailable, timeout
    }
    public var code: Code
    public var message: String
    public init(_ code: Code, _ message: String) { self.code = code; self.message = message }
    public var errorDescription: String? { message }
}

public enum HelperResponse: Codable, Equatable, Sendable {
    case status(HelperStatus)
    case inspection(RuntimeInspection)
    case started(token: String, plan: LaunchPlan)
    case stopped(remaining: Int)
    case done
    case failure(HelperFailure)
}

// MARK: - Events

public struct SessionEvent: Codable, Equatable, Sendable {
    public enum Kind: Codable, Equatable, Sendable {
        case started(pid: Int32)
        case line(String)
        case cookie(String)
        case overflow
        /// Lines dropped because the client did not keep up (bounded buffer).
        case dropped(Int)
        /// The supervisor was reaped; the code is the client's exit status.
        case exited(code: Int)
        /// The session ended without a confirmed client exit (spawn failure, lost channel).
        case failed(String)
    }
    public var sequence: UInt64
    public var kind: Kind
    public init(sequence: UInt64, kind: Kind) { self.sequence = sequence; self.kind = kind }
    public var isTerminal: Bool {
        switch kind { case .exited, .failed: return true; default: return false }
    }
}

public struct EventBatch: Codable, Equatable, Sendable {
    public var token: String
    public var events: [SessionEvent]
    public init(token: String, events: [SessionEvent]) { self.token = token; self.events = events }
}

// MARK: - Codec

public enum MessageCodec {
    public static func encode<T: Encodable>(_ value: T) -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .secondsSince1970
        return (try? encoder.encode(value)) ?? Data()
    }
    public static func decode<T: Decodable>(_ type: T.Type, from data: Data, limit: Int) throws -> T {
        guard !data.isEmpty, data.count <= limit else { throw HelperFailure(.invalidRequest, ServiceLanguage.text("Mensagem vazia ou acima do limite.")) }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        do { return try decoder.decode(type, from: data) }
        catch { throw HelperFailure(.invalidRequest, ServiceLanguage.text("Mensagem malformada.")) }
    }
}
