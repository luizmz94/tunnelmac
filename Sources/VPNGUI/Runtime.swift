import Foundation
import AppKit
import Darwin
import VPNHelperShared

enum ConnectionState {
    case disconnected, authorizing, waitingForSAML, connecting, authenticating, connected, reconnecting, disconnecting, failed
    var active: Bool { ![.disconnected, .failed].contains(self) }
    var title: String {
        switch self {
        case .disconnected: return String(localized: "Desconectada")
        case .authorizing: return String(localized: "Iniciando")
        case .waitingForSAML: return String(localized: "Na fila do SAML")
        case .connecting: return String(localized: "Conectando")
        case .authenticating: return String(localized: "Aguardando SAML")
        case .connected: return String(localized: "Conectada")
        case .reconnecting: return String(localized: "Reconectando")
        case .disconnecting: return String(localized: "Desconectando")
        case .failed: return String(localized: "Falha")
        }
    }
}

// Gateways commonly return to a fixed localhost:8020, regardless of --saml-login.
// Serialize only browser handshakes; established tunnels remain independent.
struct SAMLLoginGate {
    private(set) var owner: UUID?
    private(set) var waiting: [UUID] = []
    mutating func acquire(_ id: UUID) -> Bool {
        if owner == id { return true }
        if owner == nil { owner = id; return true }
        if !waiting.contains(id) { waiting.append(id) }
        return false
    }
    mutating func release(_ id: UUID) -> UUID? {
        waiting.removeAll { $0 == id }
        guard owner == id else { return nil }
        owner = waiting.isEmpty ? nil : waiting.removeFirst()
        return owner
    }
}

struct OutputRules {
    static func certificateDigest(_ line: String) -> String? {
        guard let range = line.range(of: #"(?i)^ERROR:\s+(?:--trusted-cert\s+|trusted-cert\s*=\s*)([0-9a-f]{64})\s*$"#, options: .regularExpression) else { return nil }
        let value = String(line[range]).trimmingCharacters(in: .whitespacesAndNewlines)
        return String(value.suffix(64)).lowercased()
    }
    static func safe(_ line: String, secret: String?) -> String {
        // These upstream errors mention secrets generically. Preserve a fixed diagnostic,
        // never any trailing server response or credential supplied on the original line.
        let diagnostics: [(String, String)] = [
            (#"^ERROR:\s+Could not authenticate to gateway\."#,
             String(localized: "ERROR: Falha na autenticação no gateway. Confira usuário, senha e os requisitos de autenticação do servidor.")),
            (#"^ERROR:\s+Failed to retrieve SAML cookie"#,
             String(localized: "ERROR: Falha ao concluir a autenticação SAML. O callback do navegador não foi recebido corretamente na porta local 8020.")),
            (#"^ERROR:\s+Finally failed to retrieve SAML authentication token"#,
             String(localized: "ERROR: O tempo de espera pelo retorno SAML do navegador terminou.")),
            (#"^ERROR:\s+No password given"#,
             String(localized: "ERROR: A senha da VPN não foi fornecida.")),
            (#"^ERROR:\s+No cookie given"#,
             String(localized: "ERROR: A sessão de autenticação não foi fornecida."))
        ]
        for (pattern, diagnostic) in diagnostics {
            if line.range(of: pattern, options: .regularExpression) != nil { return diagnostic }
        }
        let sensitive = #"(?i)(password|passwd|senha|cookie|token|authorization|samlresponse|assertion|secret|credential|bearer|otp\s*[:=])"#
        if line.range(of: sensitive, options: .regularExpression) != nil {
            return String(localized: "[mensagem com credenciais ocultada]")
        }
        var result = line
        if let secret, !secret.isEmpty { result = result.replacingOccurrences(of: secret, with: String(localized: "[oculto]")) }
        // Authentication URLs can contain session material even with an unknown parameter name.
        result = result.replacingOccurrences(of: #"https?://[^\s'\"<>]+"#,
                                             with: String(localized: "[URL ocultada]"), options: .regularExpression)
        return String(result.prefix(4000))
    }
    static func authenticationURL(_ line: String, connection: Connection) -> URL? {
        guard line.contains("Authenticate at"),
              let range = line.range(of: #"https://[^\s'\"<>]+"#, options: .regularExpression),
              let url = URL(string: String(line[range])),
              url.scheme == "https", url.user == nil, url.password == nil,
              let host = url.host,
              host.lowercased() == connection.server.trimmingCharacters(in: CharacterSet(charactersIn: "[]")).lowercased(),
              (url.port ?? 443) == connection.port,
              url.path == "/remote/saml/start" else { return nil }
        return url
    }
}

@MainActor
final class Session: ObservableObject, Identifiable {
    let id: UUID
    @Published var state: ConnectionState = .disconnected
    @Published var logs: [String] = []
    @Published var authenticationRejected = false
    @Published var connectedAt: Date?
    @Published var suggestedCertificate: String?
    /// OpenVPN refused `auth RSA-SHAx`; the app offers the digest fix (never applied alone).
    @Published var digestFix: OpenVPNCompatibility.DigestFix?
    var certificateValidationFailed = false
    var retryBlocked = false
    private var conflictingCertificates = false
    var wasConnected = false
    var reconnectAttempts = 0
    var reconnectTask: DispatchWorkItem?
    static func duration(since start: Date, at now: Date) -> String {
        let seconds = max(0, Int(now.timeIntervalSince(start)))
        return String(format: "%02d:%02d:%02d", seconds / 3600, (seconds / 60) % 60, seconds % 60)
    }
    var retryDelay: TimeInterval? {
        guard wasConnected, !wantsDisconnect, !authenticationRejected,
              !certificateValidationFailed, !retryBlocked, reconnectAttempts < 3 else { return nil }
        return TimeInterval(10 * (1 << reconnectAttempts))
    }
    var pid: Int32?
    /// Opaque identifier of this session in the privileged helper.
    var token: String?
    var lastSequence: UInt64 = 0
    var samlPort: Int?
    var wantsDisconnect = false
    var openedURL = false
    var secret: String?
    var generation = UUID()
    // SAML session reuse for the current client process only.
    var cookieMode: SAMLCookieMode = .none
    var cookieCandidate: String?
    var cookieConflict = false
    var cookieRejected = false
    var cookieTransportFailure = false
    var reachedGateway = false
    var tunnelUp = false
    var tunnelHandled = false
    /// The service could not configure a WireGuard tunnel (keys, addresses, routes):
    /// the session ends as a failure even though wireguard-go exits normally.
    var setupFailed = false
    init(id: UUID) { self.id = id }
    func log(_ text: String) {
        logs.append(OutputRules.safe(text, secret: secret))
        if logs.count > 1500 { logs.removeFirst(logs.count - 1500) }
    }
    /// The failure notice points at the logs: clearing them also dismisses it.
    func clearLogs() {
        logs.removeAll(keepingCapacity: true)
        if state == .failed { state = .disconnected }
    }
    var canClearLogs: Bool { !logs.isEmpty || state == .failed }
    func begin(retrying: Bool = false, client: String = "openfortivpn", routedBy: String? = nil) {
        reconnectTask?.cancel(); reconnectTask = nil
        if !retrying { wasConnected = false; reconnectAttempts = 0 }
        connectedAt = nil
        suggestedCertificate = nil
        certificateValidationFailed = false
        retryBlocked = false
        conflictingCertificates = false
        state = .authorizing
        wantsDisconnect = false
        openedURL = false
        pid = nil
        token = nil
        lastSequence = 0
        generation = UUID()
        cookieMode = .none
        cookieCandidate = nil
        cookieConflict = false
        cookieRejected = false
        cookieTransportFailure = false
        reachedGateway = false
        tunnelUp = false
        tunnelHandled = false
        digestFix = nil
        setupFailed = false
        let routing = routedBy ?? String(localized: "pelo \(client)")
        log(String(localized: "Iniciando conexão. Rotas e DNS serão tratados \(routing); redes sobrepostas podem gerar conflitos."))
    }
    /// wireguard-go (verbose) plus the lines the service adds while it configures the tunnel.
    /// WireGuard has no connection to wait for: the tunnel is up once it is configured; the
    /// first handshake is only logged. wireguard-go keeps re-sending handshakes by itself.
    func acceptWireGuard(_ line: String) {
        if line.hasPrefix(WireGuardMarkers.failure) {
            setupFailed = true
            retryBlocked = true
        }
        if line.hasPrefix(WireGuardMarkers.ready) && !wantsDisconnect {
            if connectedAt == nil { connectedAt = Date() }
            wasConnected = true
            tunnelUp = true
            state = .connected
        }
        log(WireGuardMarkers.display(line))
    }
    /// OpenVPN 2.7 messages (verb 3). openvpn reconnects internally (ping-restart, retries);
    /// the app only marks the state and blocks its own retry after credential/config errors.
    func acceptOpenVPN(_ line: String) {
        if line.contains("AUTH_FAILED") {
            authenticationRejected = true
            retryBlocked = true
        }
        if let fix = OpenVPNCompatibility.digestFix(fromLog: line) {
            digestFix = fix
            retryBlocked = true
        }
        if line.range(of: #"VERIFY ERROR|Options error|Cannot load|Exiting due to fatal error|private key password verification failed"#,
                      options: .regularExpression) != nil {
            retryBlocked = true
        }
        if line.contains("Initialization Sequence Completed") && !wantsDisconnect {
            if connectedAt == nil { connectedAt = Date() }
            wasConnected = true
            tunnelUp = true
            state = .connected
        } else if line.contains("process restarting") && state == .connected && !wantsDisconnect {
            // ping-restart or a lost server: openvpn keeps the process and reconnects itself.
            state = .connecting
            connectedAt = nil
            tunnelUp = false
        }
        log(line)
        if line.contains("AUTH_FAILED") {
            log(String(localized: "O servidor recusou usuário ou senha. Confira as credenciais antes de tentar de novo."))
        }
        if let fix = digestFix, line.contains("Message hash algorithm") {
            log(String(localized: "O perfil usa auth \(fix.from), que o OpenVPN não aceita. O app pode corrigir a cópia do perfil para auth \(fix.to)."))
        }
    }
    /// openconnect (GlobalProtect) messages plus the lines of the helper's vpnc-script.
    /// openconnect reconnects by itself after network changes; its exit is final.
    func acceptGlobalProtect(_ line: String, saml: Bool) {
        if line.range(of: #"(?i)certificate.*(failed verification|verify failed|didn't match)|Server SSL certificate didn't match"#,
                      options: .regularExpression) != nil {
            certificateValidationFailed = true
            retryBlocked = true
        }
        if line.hasPrefix("Login failed") || line.contains("Failed to complete authentication") {
            retryBlocked = true
            if !saml { authenticationRejected = true }
        }
        if line.hasPrefix(GlobalProtectRules.networkFailure) {
            setupFailed = true
            retryBlocked = true
        }
        // Connected only once the helper's script has set up addresses, routes and DNS.
        if line.hasPrefix(GlobalProtectRules.networkReady) && !wantsDisconnect {
            if connectedAt == nil { connectedAt = Date() }
            wasConnected = true
            tunnelUp = true
            state = .connected
        }
        log(GlobalProtectMarkers.display(line))
        if line.contains("HIP report") && line.hasPrefix("WARNING:") {
            log(String(localized: "O gateway pediu um relatório HIP, que o TunnelMac não envia; alguns recursos da rede podem ficar limitados."))
        }
        if line.hasPrefix("Login failed") && saml {
            log(String(localized: "O gateway recusou a sessão do login SAML. Conecte de novo para abrir um novo login no navegador."))
        }
    }
    func accept(_ line: String, connection: Connection, openBrowser: (URL) -> Void) {
        if connection.isOpenVPN { acceptOpenVPN(line); return }
        if connection.isGlobalProtect { acceptGlobalProtect(line, saml: connection.authentication == .saml); return }
        if connection.isWireGuard { acceptWireGuard(line); return }
        if line.range(of: #"(?i)^ERROR:.*(?:certificate|\bTLS\b|\bSSL\b|authenticate|SAML|No password|No cookie|\bOTP\b)"#, options: .regularExpression) != nil {
            retryBlocked = true
        }
        if line.range(of: #"^ERROR:\s+Gateway certificate validation failed"#, options: .regularExpression) != nil {
            certificateValidationFailed = true
        }
        if certificateValidationFailed, let digest = OutputRules.certificateDigest(line), !conflictingCertificates {
            if let previous = suggestedCertificate, previous != digest {
                conflictingCertificates = true; suggestedCertificate = nil
            } else { suggestedCertificate = digest }
        }
        if cookieMode == .reuse {
            // A refused saved session is not a credential failure: never trigger the review lock.
            if !tunnelUp && SAMLCookieRules.isRejection(line) { cookieRejected = true }
            if SAMLCookieRules.isTransportFailure(line) { cookieTransportFailure = true }
            if line.range(of: #"^INFO:\s+Connected to gateway\."#, options: .regularExpression) != nil { reachedGateway = true }
        } else if line.range(of: #"^ERROR:\s+Could not authenticate to gateway\."#, options: .regularExpression) != nil {
            authenticationRejected = true
        }
        if line.contains("Tunnel is up and running") && !wantsDisconnect {
            if connectedAt == nil { connectedAt = Date() }
            wasConnected = true
            tunnelUp = true
            state = .connected
        }
        if connection.authentication == .saml, !openedURL,
           let url = OutputRules.authenticationURL(line, connection: connection) {
            openedURL = true
            if !wantsDisconnect { state = .authenticating; openBrowser(url) }
        }
        log(line)
    }
    func finish(exit: Int?, error: String? = nil) {
        if let connectedAt, Date().timeIntervalSince(connectedAt) >= 60 { reconnectAttempts = 0 }
        connectedAt = nil
        if let error { log(error) }
        if wantsDisconnect && exit != nil && !setupFailed {
            state = .disconnected
        } else if exit == 0 && error == nil && !setupFailed { state = .disconnected }
        else { state = .failed }
        if let exit { log(String(localized: "Processo encerrado (código \(exit)).")) }
        pid = nil
        token = nil
        samlPort = nil
        secret = nil
        cookieCandidate = nil
    }
}


@MainActor
final class VPNManager: ObservableObject {
    @Published var sessions: [UUID: Session] = [:]
    private var samlGate = SAMLLoginGate()
    private var pendingSAML: [UUID: Connection] = [:]
    /// GlobalProtect sessions whose browser login is running (no helper session yet).
    private var globalProtectLogins: Set<UUID> = []
    /// Connection of a running cookie attempt, needed for its single SAML fallback.
    private var cookieAttempts: [UUID: Connection] = [:]
    /// Refused cookies the Keychain would not delete (e.g. items written by the old VPNGUI.app):
    /// never offered again until a new capture overwrites them.
    private var refusedCookies: Set<UUID> = []
    /// Profiles of running sessions, to interpret their events.
    private var running: [UUID: Connection] = [:]
    /// Helper token → session.
    private var tokens: [String: UUID] = [:]
    var cookies = SAMLCookieStore()
    /// The privileged helper (production) or nil.
    weak var transport: SessionTransport?
    /// Local checks only: replaces the helper with an in-process recorder.
    struct LaunchHarness {
        var help: String
        var launched: (Session, ConnectionRequest, LaunchPlan) -> Void
        var openVPNLaunched: ((Session, OpenVPNRequest) -> Void)? = nil
        var wireGuardLaunched: ((Session, WireGuardRequest) -> Void)? = nil
        var globalProtectLaunched: ((Session, GlobalProtectRequest) -> Void)? = nil
        /// Local checks: the browser login's result (nil = the real browser flow).
        var globalProtectLogin: ((Connection) async throws -> GlobalProtectCookie)? = nil
    }
    var harness: LaunchHarness?
    /// "DNS da internet" from Configurações, read at each connection (nil = do not change).
    var internetDNS: () -> [String]? = { nil }
    /// Reads the client certificate from the Keychain (replaced by local checks).
    var certificateExporter: (ClientCertificateReference) throws -> ClientCertificate = ClientIdentities.export
    var changed: (() -> Void)?
    var retry: ((UUID) -> Void)?
    var anyActive: Bool { sessions.values.contains { $0.state.active } }
    func session(_ id: UUID) -> Session {
        if let session = sessions[id] { return session }
        let session = Session(id: id)
        sessions[id] = session
        return session
    }
    /// `profile` is the saved OpenVPN or WireGuard profile of the connection.
    func connect(_ connection: Connection, password: String?, retrying: Bool = false, profile: String? = nil) {
        let session = session(connection.id)
        guard !session.state.active || (retrying && session.state == .reconnecting) else { return }
        switch connection.kind {
        case .fortinet: session.begin(retrying: retrying, client: "openfortivpn")
        case .openvpn: session.begin(retrying: retrying, client: "OpenVPN")
        case .wireguard: session.begin(retrying: retrying, client: "WireGuard", routedBy: String(localized: "pelo serviço do TunnelMac, a partir do perfil WireGuard"))
        case .globalProtect: session.begin(retrying: retrying, client: "OpenConnect", routedBy: String(localized: "pelo script de rede do serviço do TunnelMac"))
        }
        session.secret = password
        if connection.isGlobalProtect {
            if connection.authentication == .saml { queueOrStart(session, connection: connection, password: nil) }
            else { startGlobalProtect(session, connection: connection, password: password, cookie: nil) }
            return
        }
        if connection.isOpenVPN {
            startOpenVPN(session, connection: connection, password: password, profile: profile)
            return
        }
        if connection.isWireGuard {
            startWireGuard(session, connection: connection, profile: profile)
            return
        }
        cookieAttempts.removeValue(forKey: connection.id)
        if connection.authentication == .saml, harness == nil {
            let generation = session.generation
            let store = cookies
            let refused = refusedCookies.contains(connection.id)
            Task {
                let lookup = (try? await PersistenceIO.run { refused ? SAMLCookieLookup.none : store.lookup(connection) }) ?? .none
                guard session.generation == generation, session.state.active else { return }
                if session.wantsDisconnect { end(session, exit: 0); return }
                if case .cookie(let cookie) = lookup {
                    reuseCookie(cookie, connection: connection, session: session)
                } else { queueOrStart(session, connection: connection, password: password) }
            }
            return
        }
        if connection.authentication == .saml, let cookie = savedCookie(for: connection, session: session) {
            reuseCookie(cookie, connection: connection, session: session)
            return
        }
        queueOrStart(session, connection: connection, password: password)
    }
    private func reuseCookie(_ cookie: String, connection: Connection, session: Session) {
        session.cookieMode = .reuse
        cookieAttempts[connection.id] = connection
        session.log(String(localized: "Tentando reaproveitar a sessão SAML recente. Se o gateway recusar, um único login SAML será iniciado."))
        start(session, connection: connection, password: nil, cookie: cookie)
    }
    private func savedCookie(for connection: Connection, session: Session) -> String? {
        guard !refusedCookies.contains(connection.id) else { return nil }
        switch cookies.lookup(connection) {
        case .cookie(let cookie): return cookie
        case .none: return nil
        case .failure:
            session.log(String(localized: "Não foi possível consultar a sessão SAML salva no Keychain; usando o login SAML normal."))
            return nil
        }
    }
    private func queueOrStart(_ session: Session, connection: Connection, password: String?) {
        if connection.authentication == .saml && !samlGate.acquire(connection.id) {
            session.state = .waitingForSAML
            pendingSAML[connection.id] = connection
            session.log(String(localized: "Aguardando a autenticação SAML anterior liberar o callback local 8020. Túneis já conectados continuam ativos."))
            changed?()
            return
        }
        if connection.isGlobalProtect { loginGlobalProtect(session, connection: connection); return }
        start(session, connection: connection, password: password)
    }
    /// SAML in the browser first (holding the SAML queue), then openconnect with the cookie.
    private func loginGlobalProtect(_ session: Session, connection: Connection) {
        session.state = .authorizing
        changed?()
        if harness == nil {
            guard let transport else { end(session, exit: nil, error: String(localized: "Serviço privilegiado indisponível.")); return }
            if let reason = transport.unavailableReason(for: .openconnect) { end(session, exit: nil, error: reason); return }
        }
        let validated: Connection
        do { validated = try connection.validated() }
        catch { end(session, exit: nil, error: error.localizedDescription); return }
        session.state = .authenticating
        session.log(String(localized: "Consultando o gateway GlobalProtect para o login SAML."))
        changed?()
        let generation = session.generation
        let login = harness?.globalProtectLogin
        globalProtectLogins.insert(session.id)
        Task {
            defer { if session.generation == generation { globalProtectLogins.remove(session.id) } }
            do {
                let cookie: GlobalProtectCookie
                if let login { cookie = try await login(validated) }
                else { cookie = try await GlobalProtectLogin.shared.login(validated) { session.log($0) } }
                guard session.generation == generation, session.state.active else { return }
                if session.wantsDisconnect { end(session, exit: 0); return }
                releaseSAML(session.id)
                session.log(String(localized: "Login SAML concluído; a sessão fica só na memória do app e do serviço."))
                startGlobalProtect(session, connection: connection, password: nil, cookie: cookie)
            } catch {
                guard session.generation == generation, session.state.active else { return }
                if error is CancellationError || session.wantsDisconnect { end(session, exit: 0); return }
                session.retryBlocked = true
                end(session, exit: nil, error: error.localizedDescription)
            }
        }
    }
    private func startGlobalProtect(_ session: Session, connection: Connection, password: String?, cookie: GlobalProtectCookie?) {
        session.state = .authorizing
        changed?()
        if harness == nil {
            guard let transport else { end(session, exit: nil, error: String(localized: "Serviço privilegiado indisponível.")); return }
            if let reason = transport.unavailableReason(for: .openconnect) { end(session, exit: nil, error: reason); return }
        }
        if session.wantsDisconnect { end(session, exit: 0); return }
        let request: GlobalProtectRequest
        do {
            let c = try connection.validated()
            request = GlobalProtectRequest(connectionID: c.id, host: c.server, port: c.port, username: c.username,
                                           authentication: c.authentication, trustedCertificate: c.trustedCertificate,
                                           password: c.authentication == .password ? password : nil,
                                           cookie: c.authentication == .saml ? cookie : nil, internalNetworks: c.allTraffic ? nil : c.routedNetworks)
        } catch { end(session, exit: nil, error: error.localizedDescription); return }
        if let cookie { session.secret = cookie.value }
        running[session.id] = connection
        if let harness { harness.globalProtectLaunched?(session, request); return }
        guard let transport else { end(session, exit: nil, error: String(localized: "Serviço privilegiado indisponível.")); return }
        launch(session, plan: LaunchPlan(clientArguments: [], mode: .none)) { completion in
            transport.startGlobalProtect(request, completion: completion)
        }
    }
    /// The user pasted the globalprotectcallback: link the browser showed.
    func pasteGlobalProtectCallback(_ text: String) {
        GlobalProtectLogin.shared.receive(text)
    }
    func waitsForGlobalProtectBrowser(_ id: UUID) -> Bool {
        GlobalProtectLogin.shared.isWaiting(for: id)
    }
    private func start(_ session: Session, connection: Connection, password: String?, cookie: String? = nil) {
        session.state = .authorizing
        changed?()
        let capabilities: RuntimeCapabilities
        if let harness {
            capabilities = RuntimeCapabilities(help: harness.help)
        } else {
            guard let transport else { end(session, exit: nil, error: String(localized: "Serviço privilegiado indisponível.")); return }
            if let reason = transport.unavailableReason(for: .openfortivpn) { end(session, exit: nil, error: reason); return }
            guard let available = transport.capabilities else {
                end(session, exit: nil, error: String(localized: "O serviço não informou o openfortivpn aprovado.")); return
            }
            capabilities = available
        }
        prepare(session, connection: connection, password: password, cookie: cookie, capabilities: capabilities)
    }
    private func prepare(_ session: Session, connection: Connection, password: String?, cookie: String?,
                         capabilities: RuntimeCapabilities) {
        if session.wantsDisconnect { end(session, exit: 0); return }
        let plan = LaunchPlan.make(authentication: connection.authentication, capabilities: capabilities, cookieAvailable: cookie != nil)
        if cookie != nil && plan.mode != .reuse {
            // Incompatible client: keep the cache untouched and use the regular SAML queue.
            session.cookieMode = .none
            cookieAttempts.removeValue(forKey: session.id)
            session.log(String(localized: "Esta versão do openfortivpn não lê a sessão SAML pela entrada padrão; usando o login SAML normal."))
            queueOrStart(session, connection: connection, password: password)
            return
        }
        if connection.authentication == .saml {
            if !capabilities.samlPort && plan.mode != .reuse {
                end(session, exit: nil, error: String(localized: "Esta versão não documenta --saml-login[=port]; atualize o openfortivpn para usar a porta de callback SAML explícita."))
                return
            }
            if plan.mode == .none {
                session.log(String(localized: "Esta versão do openfortivpn não permite guardar a sessão SAML; cada conexão abrirá o navegador."))
            }
            if plan.mode != .reuse {
                // The callback port is bound by the original client inside the helper; no
                // unprivileged pre-check (it could refuse a previous listener in TIME_WAIT).
                session.samlPort = HelperConstants.samlPort
                session.log(String(localized: "Autenticação SAML na porta local \(HelperConstants.samlPort)."))
            }
        }
        let validated: Connection
        do { validated = try connection.validated() }
        catch { end(session, exit: nil, error: error.localizedDescription); return }
        guard let reference = validated.clientCertificate else {
            send(session, connection: connection, validated: validated, password: password, cookie: cookie, plan: plan, certificate: nil)
            return
        }
        // Exported off the main thread: macOS may show its Keychain access dialog meanwhile.
        session.log(String(localized: "Usando o certificado do cliente \"\(reference.name)\" do Keychain. Se o macOS pedir, permita o acesso do TunnelMac à chave."))
        let generation = session.generation
        let exporter = certificateExporter
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let result = Result { try exporter(reference) }
            DispatchQueue.main.async { [weak self] in
                guard let self, session.generation == generation, session.state.active else { return }
                if session.wantsDisconnect { self.end(session, exit: 0); return }
                switch result {
                case .success(let certificate):
                    self.send(session, connection: connection, validated: validated, password: password, cookie: cookie,
                              plan: plan, certificate: certificate)
                case .failure(let error):
                    session.retryBlocked = true // A refused Keychain access must not prompt again by itself.
                    self.end(session, exit: nil, error: error.localizedDescription)
                }
            }
        }
    }
    private func send(_ session: Session, connection: Connection, validated c: Connection, password: String?, cookie: String?,
                      plan: LaunchPlan, certificate: ClientCertificate?) {
        let request = ConnectionRequest(connectionID: c.id, host: c.server, port: c.port, username: c.username,
                                        authentication: c.authentication, trustedCertificate: c.trustedCertificate,
                                        password: c.authentication == .password ? password : nil,
                                        mode: plan.mode, cookie: plan.mode == .reuse ? cookie : nil,
                                        clientCertificate: certificate, realm: c.realm.isEmpty ? nil : c.realm,
                                        internetDNS: internetDNS())
        session.cookieMode = plan.mode
        running[session.id] = connection
        if let harness { harness.launched(session, request, plan); return }
        launch(session, request: request, plan: plan)
    }
    private func startOpenVPN(_ session: Session, connection: Connection, password: String?, profile: String?) {
        session.state = .authorizing
        changed?()
        if harness == nil {
            guard let transport else { end(session, exit: nil, error: String(localized: "Serviço privilegiado indisponível.")); return }
            if let reason = transport.unavailableReason(for: .openvpn) { end(session, exit: nil, error: reason); return }
        }
        if session.wantsDisconnect { end(session, exit: 0); return }
        let request: OpenVPNRequest
        do {
            let c = try connection.validated()
            guard let profile else { throw AppFailure(String(localized: "Perfil OpenVPN indisponível; importe-o novamente.")) }
            let credentials = c.usesPassword
            request = OpenVPNRequest(connectionID: c.id, profile: profile, username: credentials ? c.username : nil,
                                     password: credentials ? password : nil)
        } catch { end(session, exit: nil, error: error.localizedDescription); return }
        running[session.id] = connection
        if let harness { harness.openVPNLaunched?(session, request); return }
        guard let transport else { end(session, exit: nil, error: String(localized: "Serviço privilegiado indisponível.")); return }
        launch(session, plan: LaunchPlan(clientArguments: [], mode: .none)) { completion in
            transport.startOpenVPN(request, completion: completion)
        }
    }
    private func startWireGuard(_ session: Session, connection: Connection, profile: String?) {
        session.state = .authorizing
        changed?()
        if harness == nil {
            guard let transport else { end(session, exit: nil, error: String(localized: "Serviço privilegiado indisponível.")); return }
            if let reason = transport.unavailableReason(for: .wireguard) { end(session, exit: nil, error: reason); return }
        }
        if session.wantsDisconnect { end(session, exit: 0); return }
        let request: WireGuardRequest
        do {
            let c = try connection.validated()
            guard let profile else { throw AppFailure(String(localized: "Perfil WireGuard indisponível; importe-o novamente.")) }
            request = WireGuardRequest(connectionID: c.id, profile: profile, internetDNS: internetDNS())
        } catch { end(session, exit: nil, error: error.localizedDescription); return }
        running[session.id] = connection
        if let harness { harness.wireGuardLaunched?(session, request); return }
        guard let transport else { end(session, exit: nil, error: String(localized: "Serviço privilegiado indisponível.")); return }
        launch(session, plan: LaunchPlan(clientArguments: [], mode: .none)) { completion in
            transport.startWireGuard(request, completion: completion)
        }
    }
    private func launch(_ session: Session, request: ConnectionRequest, plan: LaunchPlan) {
        guard let transport else { end(session, exit: nil, error: String(localized: "Serviço privilegiado indisponível.")); return }
        launch(session, plan: plan) { completion in transport.start(request, completion: completion) }
    }
    private func launch(_ session: Session, plan: LaunchPlan,
                        send: (@escaping (Result<(String, LaunchPlan), HelperFailure>) -> Void) -> Void) {
        guard let transport else { end(session, exit: nil, error: String(localized: "Serviço privilegiado indisponível.")); return }
        let generation = session.generation
        send { [weak self] result in
            guard let self else { return }
            guard session.generation == generation, session.state.active else {
                // Superseded while starting: never leave an orphan session in the helper.
                if case .success((let token, _)) = result { transport.stop(token) { _ in } }
                return
            }
            switch result {
            case .success((let token, let confirmed)):
                session.token = token
                self.tokens[token] = session.id
                if confirmed != plan { session.log(String(localized: "O serviço ajustou o plano de execução ao openfortivpn aprovado.")) }
                if session.wantsDisconnect { self.interrupt(session) }
            case .failure(let failure):
                self.end(session, exit: nil, error: failure.message)
            }
        }
    }
    /// Ordered events of one helper session. Unknown tokens and replays are ignored.
    func receive(_ batch: EventBatch) {
        guard let id = tokens[batch.token], let session = sessions[id], session.token == batch.token,
              let connection = running[id] else { return }
        let generation = session.generation
        for event in batch.events {
            guard session.generation == generation, session.token == batch.token else { return }
            if event.sequence <= session.lastSequence { continue }
            if event.sequence != session.lastSequence + 1 {
                session.log(String(localized: "[eventos fora de ordem do serviço descartados]"))
            }
            session.lastSequence = event.sequence
            switch event.kind {
            case .started(let pid):
                session.pid = pid
                if !session.wantsDisconnect && session.state == .authorizing { session.state = .connecting }
                changed?()
            case .line(let line): receive(.line(line), session: session, connection: connection, generation: generation)
            case .cookie(let cookie): receive(.cookie(cookie), session: session, connection: connection, generation: generation)
            case .overflow: receive(.overflow, session: session, connection: connection, generation: generation)
            case .dropped(let count):
                session.log(String(localized: "[\(count) linha(s) de log descartada(s): a interface não acompanhou a saída]"))
            case .exited(let code):
                tokens.removeValue(forKey: batch.token)
                end(session, exit: code)
            case .failed(let message):
                tokens.removeValue(forKey: batch.token)
                end(session, exit: nil, error: message)
            }
        }
    }
    /// The XPC connection was lost. The helper (or the supervisor, on EOF) stops these
    /// sessions; the app never presumes a tunnel is still up and never reconnects by itself.
    func transportLost() {
        for (token, id) in tokens {
            guard let session = sessions[id], session.token == token else { continue }
            end(session, exit: nil, error: String(localized: "Canal com o serviço privilegiado perdido. O supervisor encerra o túnel ao perder o canal; nenhuma reconexão automática foi feita."))
        }
        tokens.removeAll()
    }
    func receive(_ event: OutputLineFilter.Event, session: Session, connection: Connection, generation: UUID) {
        switch event {
        case .line(let line): receive(line, session: session, connection: connection, generation: generation)
        case .overflow:
            guard session.generation == generation else { return }
            session.log(String(localized: "[linha excessivamente longa descartada]"))
        case .cookie(let cookie):
            guard session.generation == generation, session.cookieMode == .capture, !session.tunnelUp else { return }
            if session.cookieConflict { return }
            if let candidate = session.cookieCandidate, candidate != cookie {
                // Ambiguous output: never guess which session belongs to the tunnel.
                session.cookieConflict = true
                session.cookieCandidate = nil
            } else { session.cookieCandidate = cookie }
        }
    }
    func receive(_ line: String, session: Session, connection: Connection, generation: UUID) {
        guard session.generation == generation else { return }
        session.accept(line, connection: connection) { url in
            if NSWorkspace.shared.open(url) {
                session.log(String(localized: "Navegador aberto. Conclua o login; aguardando o retorno local na porta 8020."))
            } else { session.log(String(localized: "Não foi possível abrir o navegador padrão.")) }
        }
        // run_tunnel connects to the gateway only after wait_for_http_request
        // has consumed the callback and closed its listener.
        if connection.authentication == .saml && line.range(of: #"^INFO:\s+Connected to gateway\."#, options: .regularExpression) != nil {
            // The callback page on the local port ("You may close this browser tab now").
            if session.openedURL, harness == nil {
                GlobalProtectLogin.closeReturnTabs(prefix: "http://127.0.0.1:\(HelperConstants.samlPort)/")
            }
            releaseSAML(session.id)
        }
        if session.tunnelUp && !session.tunnelHandled {
            session.tunnelHandled = true
            tunnelEstablished(session, connection: connection)
        }
        changed?()
    }
    /// The candidate cookie becomes cache only after the tunnel is confirmed.
    private func tunnelEstablished(_ session: Session, connection: Connection) {
        switch session.cookieMode {
        case .reuse:
            cookieAttempts.removeValue(forKey: session.id)
            session.log(String(localized: "Sessão SAML reaproveitada sem abrir o navegador."))
        case .capture:
            defer { session.cookieCandidate = nil }
            if let candidate = session.cookieCandidate, !session.cookieConflict {
                if harness != nil { persistCookie(candidate, connection: connection, session: session) }
                else {
                    let generation = session.generation, store = cookies
                    Task {
                        guard session.generation == generation, running[session.id] != nil else { return }
                        do {
                            try await PersistenceIO.run { try store.save(candidate, for: connection) }
                            guard session.generation == generation else { return }
                            refusedCookies.remove(connection.id)
                            session.log(String(localized: "Sessão SAML guardada no Keychain por até 30 minutos."))
                        } catch { session.log(String(localized: "Não foi possível guardar a sessão SAML no Keychain; a próxima conexão usará o navegador.")) }
                    }
                }
            } else if session.cookieConflict {
                session.log(String(localized: "A saída do openfortivpn informou sessões diferentes; nenhuma foi guardada."))
            } else {
                session.log(String(localized: "O openfortivpn instalado não informou a sessão SAML; a próxima conexão usará o navegador."))
            }
        case .none: break
        }
    }
    func disconnect(_ id: UUID) {
        let session = session(id)
        guard session.state.active, !session.wantsDisconnect else { return }
        session.reconnectTask?.cancel(); session.reconnectTask = nil
        if session.state == .reconnecting || session.state == .waitingForSAML {
            session.wantsDisconnect = true
            self.end(session, exit: 0)
            return
        }
        if globalProtectLogins.contains(id) {
            // GlobalProtect browser login (no helper session yet): stop waiting for the browser.
            session.wantsDisconnect = true
            globalProtectLogins.remove(id)
            GlobalProtectLogin.shared.cancel(id)
            self.end(session, exit: 0)
            return
        }
        session.wantsDisconnect = true
        session.state = .disconnecting
        session.log(String(localized: "Solicitando encerramento normal e aguardando a limpeza de rotas e DNS…"))
        if session.token != nil { interrupt(session) }
        changed?()
    }
    private func interrupt(_ session: Session) {
        guard let token = session.token, let transport else { return }
        let generation = session.generation
        transport.stop(token) { failure in
            guard let failure, session.generation == generation, session.token == token else { return }
            if failure.code == .unknownSession { return } // Already finishing; its exit event follows.
            session.log(String(localized: "Não foi possível enviar o pedido de encerramento ao serviço (\(failure.message)). Aguardando a saída; tente novamente."))
            session.wantsDisconnect = false
            self.changed?()
        }
    }
    func end(_ session: Session, exit: Int?, error: String? = nil) {
        if let token = session.token { tokens.removeValue(forKey: token) }
        let fallback = cookieFallback(session, exit: exit)
        session.finish(exit: exit, error: error)
        running.removeValue(forKey: session.id)
        releaseSAML(session.id)
        if let connection = fallback {
            // The cookie process has exited and its supervisor confirmed cleanup.
            // Exactly one regular SAML login follows; reconnect counters are preserved.
            session.begin(retrying: true)
            queueOrStart(session, connection: connection, password: nil)
            changed?()
            return
        }
        // Retry only after a tunnel actually worked and its process confirmed exit.
        // Authentication/TLS failures and explicit disconnects always stop retries.
        if exit != nil, retry != nil, let delay = session.retryDelay {
            session.reconnectAttempts += 1
            session.state = .reconnecting
            session.log(String(localized: "Conexão caiu. Nova tentativa \(session.reconnectAttempts)/3 em \(Int(delay)) segundos. Desconectar cancela a reconexão."))
            let generation = session.generation
            let task = DispatchWorkItem { [weak self, weak session] in
                guard let self, let session, session.generation == generation,
                      session.state == .reconnecting, !session.wantsDisconnect else { return }
                self.retry?(session.id)
            }
            session.reconnectTask = task
            DispatchQueue.main.asyncAfter(deadline: .now() + delay, execute: task)
        }
        changed?()
    }
    /// Decides what a finished cookie attempt means. Only an explicit gateway refusal
    /// triggers the single SAML fallback; cancellation, authorization and network/TLS
    /// failures never do.
    private func cookieFallback(_ session: Session, exit: Int?) -> Connection? {
        guard session.cookieMode == .reuse, let attempt = cookieAttempts.removeValue(forKey: session.id) else { return nil }
        guard !session.tunnelUp, !session.wantsDisconnect, exit != nil else { return nil }
        if session.cookieRejected && !session.cookieTransportFailure {
            discardCookie(session)
            session.log(String(localized: "O gateway recusou a sessão SAML salva (expirada ou encerrada). Ela foi descartada; iniciando um login SAML no navegador."))
            return attempt
        }
        if session.reachedGateway && !session.cookieTransportFailure {
            discardCookie(session)
            session.log(String(localized: "A sessão SAML salva não foi confirmada pelo gateway e foi descartada. A próxima conexão usará o navegador."))
        } else {
            session.log(String(localized: "A tentativa com a sessão SAML salva falhou por rede ou TLS; isso não indica sessão inválida."))
        }
        return nil
    }
    private func persistCookie(_ candidate: String, connection: Connection, session: Session) {
        do {
            try cookies.save(candidate, for: connection)
            refusedCookies.remove(connection.id)
            session.log(String(localized: "Sessão SAML guardada no Keychain por até 30 minutos para a próxima conexão."))
        } catch { session.log(String(localized: "Não foi possível guardar a sessão SAML no Keychain; a próxima conexão usará o navegador.")) }
    }
    private func discardCookie(_ session: Session) {
        refusedCookies.insert(session.id) // Never offer a rejected cookie while deletion waits.
        if harness != nil {
            do { try cookies.delete(session.id) } catch { session.log(String(localized: "Não foi possível apagar a sessão SAML recusada do Keychain.")) }
            return
        }
        let store = cookies, id = session.id
        Task {
            do { try await PersistenceIO.run { try store.delete(id) } }
            catch { session.log(String(localized: "Não foi possível apagar a sessão SAML recusada do Keychain; ela não será reutilizada nesta sessão do app.")) }
        }
    }
    func retryFailed(_ id: UUID, message: String) {
        let session = session(id)
        session.reconnectTask?.cancel(); session.reconnectTask = nil
        session.finish(exit: nil, error: message)
        changed?()
    }
    private func releaseSAML(_ id: UUID) {
        pendingSAML.removeValue(forKey: id)
        guard let next = samlGate.release(id), let connection = pendingSAML.removeValue(forKey: next) else { return }
        if connection.isGlobalProtect { loginGlobalProtect(session(next), connection: connection); return }
        start(session(next), connection: connection, password: nil, cookie: nil)
    }
    func disconnectAll() {
        let waiting = sessions.values.filter { $0.state == .waitingForSAML }.map(\.id)
        for id in waiting { disconnect(id) }
        let active = sessions.values.filter { $0.state.active }.map(\.id)
        for id in active { disconnect(id) }
    }
}

/// The helper's vpnc-script writes its lines in Portuguese; the log shows them in the app's language.
enum GlobalProtectMarkers {
    static func display(_ line: String) -> String {
        func between(_ prefix: String, _ suffix: String) -> String? {
            guard line.hasPrefix(prefix), line.hasSuffix(suffix), line.count >= prefix.count + suffix.count else { return nil }
            return String(line.dropFirst(prefix.count).dropLast(suffix.count))
        }
        if let rest = between("[#] DNS da VPN (", " para todos os nomes."), let close = rest.lastIndex(of: ")") {
            let servers = rest[..<close].trimmingCharacters(in: .whitespaces)
            return String(localized: "[#] DNS da VPN (\(servers)) para todos os nomes.")
        }
        if let rest = between("[#] DNS da VPN (", "; os demais nomes seguem no DNS atual."), let close = rest.range(of: ") para ") {
            let servers = rest[..<close.lowerBound].trimmingCharacters(in: .whitespaces)
            let domains = String(rest[close.upperBound...])
            return String(localized: "[#] DNS da VPN (\(servers)) para \(domains); os demais nomes seguem no DNS atual.")
        }
        if let interface = between(GlobalProtectRules.networkReady, ".") {
            return String(localized: "[+] TunnelMac: rede do túnel configurada em \(interface).")
        }
        if let routes = between(GlobalProtectRules.networkFailure, ".") {
            return String(localized: "[!] TunnelMac: rotas obrigatórias não configuradas (\(routes.trimmingCharacters(in: .whitespaces))); a conexão foi encerrada.")
        }
        switch line {
        case "[i] O gateway pede todo o tráfego pela VPN; só as redes internas escolhidas usarão o túnel.":
            return String(localized: "[i] O gateway pede todo o tráfego pela VPN; só as redes internas escolhidas usarão o túnel.")
        case "[#] Rotas e DNS da VPN removidos.":
            return String(localized: "[#] Rotas e DNS da VPN removidos.")
        default: return line
        }
    }
}

extension WireGuardMarkers {
    /// The helper writes its marker lines in Portuguese, the form the app recognizes;
    /// the log shows them in the app's language.
    static func display(_ line: String) -> String {
        func detail(after marker: String, _ joiner: String) -> String? {
            guard line.hasPrefix(marker + joiner), line.hasSuffix(".") else { return nil }
            return String(line.dropFirst(marker.count + joiner.count).dropLast())
        }
        if let interface = detail(after: ready, " em ") {
            return String(localized: "[+] TunnelMac: túnel WireGuard configurado em \(interface).")
        }
        if let server = detail(after: handshake, " com ") {
            return String(localized: "[+] TunnelMac: handshake concluído com \(server).")
        }
        return line
    }
}
