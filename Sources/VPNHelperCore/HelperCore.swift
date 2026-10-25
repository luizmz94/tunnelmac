import Foundation
import Darwin
import ProcessBridge
import VPNHelperShared

/// Policy and state of the privileged helper, independent of the XPC transport so that
/// local checks can drive it through anonymous listeners with harmless children.
public final class HelperCore {
    public typealias EventSink = (EventBatch, @escaping () -> Void) -> Void
    public struct Configuration {
        public var stateDirectory: String
        public var ownership: TrustedOwnership
        public var supervisorSource: String
        /// Requirement for the supervisor copy. nil only in local checks (no signature to check).
        public var supervisorRequirement: String?
        public var helperVersion: String
        /// Identity used to run --help/--version of a staged runtime (production: nobody).
        public var probeIdentity: (uid_t, gid_t)?
        public var authorizer: AdminAuthorizing
        public var idleTimeout: TimeInterval
        public var onIdle: (() -> Void)?
        /// System access of WireGuard sessions (production: root tools, UAPI, dynamic store).
        public var wireGuardHost: WireGuardHost
        /// Monitor period of WireGuard sessions (handshake, gateway and DNS checks).
        public var wireGuardInterval: TimeInterval
        /// Per-domain DNS of openfortivpn sessions (production: the dynamic store).
        public var supplementalDNS: SupplementalDNS
        public init(stateDirectory: String, ownership: TrustedOwnership, supervisorSource: String,
                    supervisorRequirement: String?, helperVersion: String, probeIdentity: (uid_t, gid_t)?,
                    authorizer: AdminAuthorizing, idleTimeout: TimeInterval = 30, onIdle: (() -> Void)? = nil,
                    wireGuardHost: WireGuardHost = SystemWireGuardHost(), wireGuardInterval: TimeInterval = 3,
                    supplementalDNS: SupplementalDNS = SystemSupplementalDNS()) {
            self.supplementalDNS = supplementalDNS
            self.stateDirectory = stateDirectory; self.ownership = ownership; self.supervisorSource = supervisorSource
            self.supervisorRequirement = supervisorRequirement; self.helperVersion = helperVersion
            self.probeIdentity = probeIdentity; self.authorizer = authorizer
            self.idleTimeout = idleTimeout; self.onIdle = onIdle
            self.wireGuardHost = wireGuardHost; self.wireGuardInterval = wireGuardInterval
        }
    }

    /// One authenticated XPC connection. Sessions belong to exactly one client.
    public final class Client {
        public let id = UUID()
        public let uid: uid_t
        public let auditSession: Int32
        var handshaken = false
        var sink: EventPump.Sink?
        var alive = true
        init(uid: uid_t, auditSession: Int32, sink: EventPump.Sink?) { self.uid = uid; self.auditSession = auditSession; self.sink = sink }
    }

    public let configuration: Configuration
    let queue = DispatchQueue(label: "com.luiz.vpngui.helper.core")
    private let work = DispatchQueue(label: "com.luiz.vpngui.helper.approval")
    let store: RuntimeStore
    let registry: SessionRegistry
    private var clients: [UUID: Client] = [:]
    private(set) var sessions: [String: SessionRunner] = [:]
    private var maintenanceOwner: UUID?
    private var idleTask: DispatchWorkItem?
    /// "DNS da internet", shared by every session that asks for it.
    let internetDNS: InternetDNS

    public init(_ configuration: Configuration) {
        self.configuration = configuration
        store = RuntimeStore(root: configuration.stateDirectory, ownership: configuration.ownership,
                             probeIdentity: configuration.probeIdentity)
        try? store.prepareDirectories()
        internetDNS = InternetDNS(host: configuration.wireGuardHost, recordPath: store.internetDNSRecord)
        registry = SessionRegistry(path: store.registryPath)
        queue.async {
            self.recoverWireGuard()
            self.internetDNS.recover()
            let live = Set(self.registry.stale(excluding: []).map(\.token))
            self.store.sweepClientCertificates(keeping: live)
            // Per-domain DNS left by sessions of an earlier helper process.
            let dns = self.configuration.supplementalDNS
            let leftovers = dns.tokens().filter { !live.contains($0) }
            leftovers.forEach { dns.remove(token: $0) }
            if !leftovers.isEmpty { dns.flush() }
            self.scheduleIdleCheck()
        }
    }

    // MARK: Clients

    public func connect(uid: uid_t, auditSession: Int32, sink: @escaping EventSink) -> Client {
        // Acknowledgements arrive on an XPC queue; the pump state lives on `queue`.
        let serialized: EventPump.Sink = { [queue] batch, acknowledged in
            sink(batch) { queue.async(execute: acknowledged) }
        }
        return queue.sync {
            let client = Client(uid: uid, auditSession: auditSession, sink: serialized)
            clients[client.id] = client
            idleTask?.cancel(); idleTask = nil
            return client
        }
    }

    /// XPC invalidation/interruption: stop and clean every session of this client only.
    public func disconnect(_ client: Client) {
        queue.async {
            client.alive = false
            client.sink = nil
            self.clients.removeValue(forKey: client.id)
            if self.maintenanceOwner == client.id { self.maintenanceOwner = nil }
            for session in self.sessions.values where session.ownerID == client.id { session.abandon() }
            self.scheduleIdleCheck()
        }
    }

    /// Helper exit (SIGTERM from launchd, unregister): stop everything and wait, bounded.
    public func shutdown(timeout: TimeInterval) {
        let group = DispatchGroup()
        queue.sync {
            for session in sessions.values where !session.finished {
                group.enter()
                let previous = session.onFinish
                session.onFinish = { runner in previous?(runner); group.leave() }
                session.abandon()
            }
        }
        _ = group.wait(timeout: .now() + timeout)
    }

    private func scheduleIdleCheck() {
        guard let onIdle = configuration.onIdle, clients.isEmpty, sessions.isEmpty else { return }
        idleTask?.cancel()
        let task = DispatchWorkItem { [weak self] in
            guard let self, self.clients.isEmpty, self.sessions.isEmpty else { return }
            onIdle()
        }
        idleTask = task
        queue.asyncAfter(deadline: .now() + configuration.idleTimeout, execute: task)
    }

    // MARK: Requests

    public func handle(_ data: Data, from client: Client, reply: @escaping (Data) -> Void) {
        let respond: (HelperResponse) -> Void = { reply(MessageCodec.encode($0)) }
        let request: HelperRequest
        do { request = try MessageCodec.decode(HelperRequest.self, from: data, limit: HelperConstants.maximumRequestSize) }
        catch { respond(.failure(error as? HelperFailure ?? HelperFailure(.invalidRequest, "Mensagem malformada."))); return }
        queue.async {
            guard client.alive else { respond(.failure(HelperFailure(.transport, "Conexão encerrada."))); return }
            if case .hello(let hello) = request {
                guard hello.protocolVersion == HelperConstants.protocolVersion else {
                    client.handshaken = false
                    respond(.failure(HelperFailure(.incompatibleProtocol,
                        "Protocolo do app (\(hello.protocolVersion)) diferente do serviço (\(HelperConstants.protocolVersion), versão \(self.configuration.helperVersion)). Atualize o serviço pelo app.")))
                    return
                }
                client.handshaken = true
                respond(.status(self.status(for: client)))
                return
            }
            guard client.handshaken else {
                respond(.failure(HelperFailure(.handshakeRequired, "Handshake obrigatório antes de qualquer operação."))); return
            }
            switch request {
            case .hello: break
            case .status: respond(.status(self.status(for: client)))
            case .start(let connection): respond(self.start(connection, for: client))
            case .startOpenVPN(let connection): respond(self.startOpenVPN(connection, for: client))
            case .startWireGuard(let connection): respond(self.startWireGuard(connection, for: client))
            case .stop(let token): respond(self.stop(token, for: client))
            case .stopAll:
                for session in self.sessions.values where session.ownerID == client.id { session.stop() }
                respond(.stopped(remaining: self.sessions.values.filter { $0.ownerID == client.id }.count))
            case .prepareForMaintenance:
                guard client.uid != 0, self.maintenanceOwner == nil || self.maintenanceOwner == client.id,
                      self.sessions.isEmpty, self.registry.stale(excluding: []).isEmpty else {
                    respond(.failure(HelperFailure(.busy, "Há sessões ou supervisores pendentes; manutenção cancelada.")))
                    return
                }
                self.recoverWireGuard()
                guard !self.networkCleanupPending, self.registry.persistenceFailure == nil else {
                    respond(.failure(HelperFailure(.busy, "Restauração da rede ou persistência pendente; serviço preservado para recuperação.")))
                    return
                }
                self.maintenanceOwner = client.id
                respond(.done)
            case .cancelMaintenance:
                if self.maintenanceOwner == client.id { self.maintenanceOwner = nil }
                respond(.done)
            case .inspectRuntime(let path): self.inspect(path: path, kind: .openfortivpn, client: client, respond: respond)
            case .inspectOpenVPNRuntime(let path): self.inspect(path: path, kind: .openvpn, client: client, respond: respond)
            case .approveRuntime(let path, let digest, let authorization):
                self.approve(path: path, digest: digest, authorization: authorization, kind: .openfortivpn, client: client, respond: respond)
            case .approveOpenVPNRuntime(let path, let digest, let authorization):
                self.approve(path: path, digest: digest, authorization: authorization, kind: .openvpn, client: client, respond: respond)
            case .inspectWireGuardRuntime(let path): self.inspect(path: path, kind: .wireguard, client: client, respond: respond)
            case .approveWireGuardRuntime(let path, let digest, let authorization):
                self.approve(path: path, digest: digest, authorization: authorization, kind: .wireguard, client: client, respond: respond)
            case .removeManagedFiles(let authorization):
                self.removeManagedFiles(authorization: authorization, client: client, respond: respond)
            }
        }
    }

    static func wrap(_ error: Error) -> HelperFailure {
        if let failure = error as? HelperFailure { return failure }
        if let violation = error as? RuleViolation { return HelperFailure(.invalidRequest, violation.message) }
        return HelperFailure(.internalError, error.localizedDescription)
    }

    private func inspect(path: String, kind: RuntimeKind, client: Client, respond: @escaping (HelperResponse) -> Void) {
        let uid = client.uid
        work.async {
            do { respond(.inspection(try RuntimeInspector.inspect(candidate: path, requester: uid, kind: kind).report)) }
            catch { respond(.failure(Self.wrap(error))) }
        }
    }

    func status(for client: Client) -> HelperStatus {
        var runtime: RuntimeSummary?
        var problem: String?
        do { runtime = try store.loadActive().summary } catch { problem = Self.wrap(error).message }
        var openVPN: RuntimeSummary?
        var openVPNProblem: String?
        do { openVPN = try store.loadActive(.openvpn).summary } catch { openVPNProblem = Self.wrap(error).message }
        var wireGuard: RuntimeSummary?
        var wireGuardProblem: String?
        do { wireGuard = try store.loadActive(.wireguard).summary } catch { wireGuardProblem = Self.wrap(error).message }
        let authorized = (try? store.loadState().authorizedUsers.contains(client.uid)) ?? false
        let stale = registry.stale(excluding: Set(sessions.keys)).filter { $0.uid == client.uid }.map(\.connectionID)
        return HelperStatus(protocolVersion: HelperConstants.protocolVersion, helperVersion: configuration.helperVersion,
                            runtime: runtime, runtimeProblem: problem, userAuthorized: authorized,
                            activeSessions: sessions.values.filter { $0.ownerID == client.id }.count,
                            stoppingConnections: Array(Set(stale)),
                            openVPNRuntime: openVPN, openVPNRuntimeProblem: openVPNProblem,
                            wireGuardRuntime: wireGuard, wireGuardRuntimeProblem: wireGuardProblem)
    }

    /// Checks shared by every client kind, before anything is prepared.
    private func admit(_ connectionID: UUID, for client: Client) -> HelperFailure? {
        recoverWireGuard()
        guard !networkCleanupPending, registry.persistenceFailure == nil else {
            return HelperFailure(.busy, "Recuperação de rede ou registro pendente. Reinicie o serviço antes de conectar novamente.")
        }
        guard maintenanceOwner == nil else { return HelperFailure(.busy, "Serviço em manutenção.") }
        guard client.uid != 0 else { return HelperFailure(.userNotAuthorized, "O app não deve rodar como root.") }
        guard (try? store.loadState().authorizedUsers.contains(client.uid)) == true else {
            return HelperFailure(.userNotAuthorized, "Este usuário do macOS ainda não foi autorizado por um administrador para usar o serviço.")
        }
        // A finished runner (supervisor reaped and cleaned up) only waits for the delivery of its
        // final events; it must not block the next start, e.g. the SAML fallback after a cookie.
        if sessions.values.contains(where: { !$0.finished && $0.uid == client.uid && $0.connectionID == connectionID }) {
            return HelperFailure(.duplicateSession, "Esta conexão já tem uma sessão ativa ou encerrando.")
        }
        if registry.stale(excluding: Set(sessions.keys)).contains(where: { $0.uid == client.uid && $0.connectionID == connectionID }) {
            return HelperFailure(.busy, "A sessão anterior desta conexão ainda está encerrando. Aguarde a limpeza e tente novamente.")
        }
        guard sessions.values.filter({ !$0.finished && $0.ownerID == client.id }).count < HelperConstants.maximumSessionsPerClient else {
            return HelperFailure(.limitReached, "Limite de conexões simultâneas atingido.")
        }
        return nil
    }

    private func startOpenVPN(_ request: OpenVPNRequest, for client: Client) -> HelperResponse {
        if let refusal = admit(request.connectionID, for: client) { return .failure(refusal) }
        let runtime: ActiveRuntime
        do { runtime = try store.loadActive(.openvpn) } catch { return .failure(Self.wrap(error)) }
        guard runtime.dnsScript != nil else {
            return .failure(HelperFailure(.runtimeRejected, "O runtime OpenVPN não possui dns-updown protegido; reinstale o cliente e aprove novamente para garantir o DNS da VPN."))
        }
        var content: Data
        do {
            content = Data(try OpenVPNConfigRenderer.render(profile: request.profile, username: request.username,
                                                            password: request.password, dnsScript: runtime.dnsScript).utf8)
        } catch { return .failure(Self.wrap(error)) }
        defer { content.resetBytes(in: 0..<content.count) }
        let plan = LaunchPlan(clientArguments: [], mode: .none)
        return launch(connectionID: request.connectionID, client: client, runtime: runtime, content: content, cookie: nil,
                      supervisorArguments: ["--openvpn", runtime.executable], plan: plan,
                      secrets: (request.password?.count ?? 0) >= 4 ? [request.password!] : [])
    }

    /// Undoes routes and DNS left by WireGuard sessions of an earlier helper process.
    /// Sessions of this process and supervisors still alive keep their records.
    private var networkCleanupPending: Bool {
        let live = Set(sessions.keys)
        let records = (try? FileManager.default.contentsOfDirectory(atPath: store.wireGuardRecords)) ?? []
        return internetDNS.cleanupPending || records.contains { $0.hasSuffix(".json") && !live.contains(String($0.dropLast(5))) }
    }

    private func recoverWireGuard() {
        let live = Set(sessions.keys).union(registry.stale(excluding: Set(sessions.keys)).map(\.token))
        WireGuardTunnel.recover(directory: store.wireGuardRecords, host: configuration.wireGuardHost, live: live)
        store.sweepWork(keeping: live)
    }

    private func startWireGuard(_ request: WireGuardRequest, for client: Client) -> HelperResponse {
        if let refusal = admit(request.connectionID, for: client) { return .failure(refusal) }
        let runtime: ActiveRuntime
        do { runtime = try store.loadActive(.wireguard) } catch { return .failure(Self.wrap(error)) }
        let profile: WireGuardProfile
        let internetServers: [String]?
        do {
            profile = try WireGuardProfile.validated(request.profile)
            internetServers = try request.internetDNS.map(ConnectionRules.internetDNS)
        } catch { return .failure(Self.wrap(error)) }
        let internetDNS = self.internetDNS
        recoverWireGuard()
        do { try store.prepareDirectories() } catch { return .failure(Self.wrap(error)) }
        let token = UUID().uuidString
        let nameFile = store.work + "/wg.\(token).name"
        unlink(nameFile)
        let tunnel = WireGuardTunnel(token: token, profile: profile, host: configuration.wireGuardHost, nameFile: nameFile,
                                     recordPath: store.wireGuardRecords + "/\(token).json")
        tunnel.interval = configuration.wireGuardInterval
        // wireguard-go reads nothing else from the environment. Errors only: its verbose log
        // is thread bookkeeping; the handshake is read from UAPI by the tunnel monitor.
        let environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C",
                           "WG_TUN_NAME_FILE": nameFile, "LOG_LEVEL": "error"]
        return launch(connectionID: request.connectionID, client: client, runtime: runtime, content: Data(), cookie: nil,
                      supervisorArguments: ["--wireguard", runtime.executable], plan: LaunchPlan(clientArguments: [], mode: .none),
                      secrets: [], token: token, environment: environment) { [queue] runner in
            tunnel.emit = { [weak runner] line in queue.async { runner?.pump.enqueue(.line(line)) } }
            tunnel.fail = { [weak runner] in queue.async { runner?.stop() } }
            guard let servers = internetServers else { return tunnel }
            guard profile.dnsServers.isEmpty else {
                tunnel.emit("[i] O perfil WireGuard define o próprio DNS; o DNS da internet do TunnelMac não é usado nesta conexão.")
                return tunnel
            }
            let hold = InternetDNSHold(token: token, servers: servers, controller: internetDNS, trigger: nil)
            hold.emit = tunnel.emit
            tunnel.ready = { hold.tunnelUp() }
            return SessionObservers([tunnel, hold])
        }
    }

    private func start(_ request: ConnectionRequest, for client: Client) -> HelperResponse {
        if let refusal = admit(request.connectionID, for: client) { return .failure(refusal) }
        let runtime: ActiveRuntime
        do { runtime = try store.loadActive() } catch { return .failure(Self.wrap(error)) }
        let plan: LaunchPlan
        do { plan = try request.validatedPlan(capabilities: runtime.manifest.capabilities) }
        catch { return .failure(Self.wrap(error)) }
        let token = UUID().uuidString
        var files: ClientCertificateFiles?
        var content: Data
        do {
            if let certificate = request.clientCertificate {
                files = try store.writeClientCertificate(try certificate.validated(), token: token)
            }
            content = Data(try ConfigRenderer.render(host: request.host, port: request.port, username: request.username,
                                                     password: request.authentication == .password ? request.password : nil,
                                                     trustedCertificate: request.trustedCertificate,
                                                     realm: request.realm ?? "", clientCertificate: files).utf8)
        } catch {
            if files != nil { store.removeClientCertificate(token: token) }
            return .failure(Self.wrap(error))
        }
        defer { content.resetBytes(in: 0..<content.count) }
        var secrets = plan.usesCookie ? [request.cookie ?? ""] : []
        if let files { secrets.append(files.passphrase) }
        let store = self.store
        let dns = FortinetDNS(token: token, store: configuration.supplementalDNS)
        let internetDNS = self.internetDNS
        let response = launch(connectionID: request.connectionID, client: client, runtime: runtime, content: content,
                              cookie: plan.usesCookie ? request.cookie : nil,
                              supervisorArguments: plan.supervisorArguments(binary: runtime.executable), plan: plan,
                              secrets: secrets, token: token) { [queue] runner in
            dns.emit = { [weak runner] line in queue.async { runner?.pump.enqueue(.line(line)) } }
            var observers: [SessionObserver] = [dns]
            if let servers = try? request.internetDNS.map(ConnectionRules.internetDNS) {
                let hold = InternetDNSHold(token: token, servers: servers, controller: internetDNS, trigger: "Tunnel is up and running")
                hold.emit = dns.emit
                observers.append(hold)
            }
            if files != nil { observers.append(CertificateCleanup { store.removeClientCertificate(token: token) }) }
            return SessionObservers(observers)
        }
        if case .failure = response, files != nil { store.removeClientCertificate(token: token) }
        return response
    }

    /// Supervisor start shared by every client: protected config descriptor, optional cookie
    /// pipe, fixed environment, session bookkeeping and the ordered event reader.
    private func launch(connectionID: UUID, client: Client, runtime: ActiveRuntime, content: Data, cookie: String?,
                        supervisorArguments: [String], plan: LaunchPlan, secrets: [String],
                        token: String = UUID().uuidString, environment: [String: String]? = nil,
                        observer: ((SessionRunner) -> SessionObserver)? = nil) -> HelperResponse {
        let supervisor: String
        do { supervisor = try store.preparedSupervisor(source: configuration.supervisorSource, requirement: configuration.supervisorRequirement) }
        catch { return .failure(Self.wrap(error)) }
        var configFD: Int32 = -1, cookieFD: Int32 = -1
        defer { if configFD >= 0 { close(configFD) }; if cookieFD >= 0 { close(cookieFD) } }
        do {
            try store.ownership.verifyChain(store.work)
            configFD = try ProtectedDescriptor.anonymousFile(content, directory: store.work)
            if let cookie { cookieFD = try ProtectedDescriptor.pipe(Data(cookie.utf8)) }
        } catch { return .failure(Self.wrap(error)) }
        let argv = [supervisor] + supervisorArguments
        let environment = RuntimeEnvironment.list(environment ?? runtime.environment)
        var pid: pid_t = 0
        var cArguments: [UnsafeMutablePointer<CChar>?] = argv.map { strdup($0) } + [nil]
        var cEnvironment: [UnsafeMutablePointer<CChar>?] = environment.map { strdup($0) } + [nil]
        defer { cArguments.forEach { free($0) }; cEnvironment.forEach { free($0) } }
        let control = cArguments.withUnsafeMutableBufferPointer { a in
            cEnvironment.withUnsafeMutableBufferPointer { e in
                vpn_spawn_supervisor(supervisor, a.baseAddress, e.baseAddress, configFD, cookieFD, &pid)
            }
        }
        guard control >= 0 else {
            return .failure(HelperFailure(.internalError, "Não foi possível iniciar o supervisor (\(String(cString: strerror(errno))))."))
        }
        let pump = EventPump(token: token, sink: client.sink)
        let runner = SessionRunner(token: token, ownerID: client.id, uid: client.uid, connectionID: connectionID,
                                   supervisorPID: pid, control: control, queue: queue, pump: pump)
        runner.observer = observer?(runner)
        runner.onFinish = { [weak self] runner in
            guard let self else { return }
            self.registry.remove(token: runner.token)
            // Keep the session (and its duplicate guard) until the terminal event was handed over.
            let finish = { [weak self] in
                guard let self, self.sessions[runner.token] === runner else { return }
                self.sessions.removeValue(forKey: runner.token)
                self.scheduleIdleCheck()
            }
            if runner.pump.sink == nil || runner.pump.isDrained { finish() } else { runner.pump.onIdle = finish }
        }
        sessions[token] = runner
        do { try registry.add(token: token, uid: client.uid, connectionID: connectionID, pid: pid) }
        catch {
            runner.stop()
            runner.startReading(captureCookie: false, secrets: secrets)
            return .failure(Self.wrap(error))
        }
        runner.startReading(captureCookie: plan.mode == .capture, secrets: secrets)
        return .started(token: token, plan: plan)
    }

    private func stop(_ token: String, for client: Client) -> HelperResponse {
        // A token of another client is indistinguishable from an unknown one.
        guard let session = sessions[token], session.ownerID == client.id else {
            return .failure(HelperFailure(.unknownSession, "Sessão desconhecida."))
        }
        session.stop()
        return .stopped(remaining: sessions.values.filter { $0.ownerID == client.id }.count)
    }

    private func approve(path: String, digest: String, authorization: Data, kind: RuntimeKind, client: Client,
                         respond: @escaping (HelperResponse) -> Void) {
        guard client.uid != 0 else { respond(.failure(HelperFailure(.userNotAuthorized, "O app não deve rodar como root."))); return }
        let uid = client.uid
        work.async {
            do {
                let inventory = try RuntimeInspector.inspect(candidate: path, requester: uid, kind: kind)
                guard inventory.digest == digest else {
                    throw HelperFailure(.runtimeRejected, "A instalação mudou desde a inspeção. Revise o inventário novamente antes de aprovar.")
                }
                guard self.configuration.authorizer.authorize(authorization) else {
                    throw HelperFailure(.authorizationDenied, "Aprovação de administrador cancelada ou recusada.")
                }
                // Serialized with start/status on the core queue. Installing never replaces a
                // runtime in use: a new directory is created and the previous one is kept.
                var outcome: Result<Void, Error> = .success(())
                self.queue.sync {
                    do {
                        guard self.sessions.isEmpty, self.registry.stale(excluding: []).isEmpty, !self.networkCleanupPending else {
                            throw HelperFailure(.busy, "Desconecte todas as VPNs e aguarde a limpeza antes de aprovar outro runtime.")
                        }
                        try self.store.install(inventory, approvedBy: uid)
                    } catch { outcome = .failure(error) }
                }
                try outcome.get()
                self.queue.async { respond(.status(self.status(for: client))) }
            } catch { respond(.failure(Self.wrap(error))) }
        }
    }

    private func removeManagedFiles(authorization: Data, client: Client, respond: @escaping (HelperResponse) -> Void) {
        guard sessions.isEmpty, registry.stale(excluding: []).isEmpty, !networkCleanupPending else {
            respond(.failure(HelperFailure(.busy, "Há sessões ativas ou encerrando; desconecte antes de remover os arquivos do serviço."))); return
        }
        work.async {
            guard self.configuration.authorizer.authorize(authorization) else {
                respond(.failure(HelperFailure(.authorizationDenied, "Aprovação de administrador cancelada ou recusada."))); return
            }
            self.queue.async {
                guard self.sessions.isEmpty else {
                    respond(.failure(HelperFailure(.busy, "Uma sessão começou durante a remoção; nada foi apagado."))); return
                }
                self.store.removeAll()
                respond(.done)
            }
        }
    }

    // MARK: Local checks

    public var sessionCount: Int { queue.sync { sessions.count } }
    public var stateStore: RuntimeStore { store }
}
