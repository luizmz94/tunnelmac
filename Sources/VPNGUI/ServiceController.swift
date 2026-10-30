import Foundation
import AppKit
import ServiceManagement
import CryptoKit
import VPNHelperShared

/// Registration API used by the controller. Production: SMAppService.daemon(plistName:).
@MainActor
protocol ServiceRegistrar: AnyObject {
    var status: SMAppService.Status { get }
    func register() throws
    func unregister(completion: @escaping (Error?) -> Void)
    func openSystemSettings()
}

@MainActor
final class DaemonRegistrar: ServiceRegistrar {
    /// A fresh object per read: one kept from launch can go on reporting requiresApproval
    /// after the switch is turned on in System Settings.
    private var service: SMAppService { SMAppService.daemon(plistName: HelperConstants.plistName) }
    var status: SMAppService.Status { service.status }
    func register() throws { try service.register() }
    func unregister(completion: @escaping (Error?) -> Void) {
        service.unregister { error in DispatchQueue.main.async { completion(error) } }
    }
    func openSystemSettings() { SMAppService.openSystemSettingsLoginItems() }
}

/// What the app can transport to the helper; the manager depends only on this.
@MainActor
protocol SessionTransport: AnyObject {
    /// nil when new sessions may start; otherwise a reason for the user.
    var unavailableReason: String? { get }
    /// nil when sessions of this client may start (service ready and its copy approved).
    func unavailableReason(for kind: RuntimeKind) -> String?
    var capabilities: RuntimeCapabilities? { get }
    func start(_ request: ConnectionRequest, completion: @escaping (Result<(String, LaunchPlan), HelperFailure>) -> Void)
    func startOpenVPN(_ request: OpenVPNRequest, completion: @escaping (Result<(String, LaunchPlan), HelperFailure>) -> Void)
    func startWireGuard(_ request: WireGuardRequest, completion: @escaping (Result<(String, LaunchPlan), HelperFailure>) -> Void)
    func startGlobalProtect(_ request: GlobalProtectRequest, completion: @escaping (Result<(String, LaunchPlan), HelperFailure>) -> Void)
    func stop(_ token: String, completion: @escaping (HelperFailure?) -> Void)
}

/// Real state of the privileged service: registration (SMAppService) plus an
/// authenticated handshake. `enabled` alone never counts as healthy.
@MainActor
final class ServiceController: ObservableObject, SessionTransport {
    enum Health: Equatable {
        case checking
        case unsigned(String)
        case notRegistered
        case requiresApproval
        case notFound
        case unresponsive(String)
        case incompatible(String)
        case outdated(String)
        case runtimeMissing(String)
        case userNotAuthorized
        case ready

        var title: String {
            switch self {
            case .checking: return String(localized: "Verificando o serviço…")
            case .unsigned: return String(localized: "Assinatura necessária")
            case .notRegistered: return String(localized: "Serviço não ativado")
            case .requiresApproval: return String(localized: "Aprovação pendente em Ajustes")
            case .notFound: return String(localized: "Serviço não encontrado no app")
            case .unresponsive: return String(localized: "Serviço não responde")
            case .incompatible: return String(localized: "Serviço incompatível")
            case .outdated: return String(localized: "Atualização do serviço necessária")
            case .runtimeMissing: return String(localized: "Nenhum cliente VPN aprovado")
            case .userNotAuthorized: return String(localized: "Usuário não autorizado")
            case .ready: return String(localized: "Serviço pronto")
            }
        }
        var detail: String {
            switch self {
            case .checking: return String(localized: "Consultando o registro e o serviço privilegiado.")
            case .unsigned(let reason): return reason + String(localized: " Veja o guia de ativação no README.")
            case .notRegistered: return String(localized: "Use Ativar serviço e aprove em Ajustes do Sistema › Itens de Início.")
            case .requiresApproval: return String(localized: "Ligue o TunnelMac em Ajustes do Sistema › Itens de Início › Permitir em segundo plano.")
            case .notFound: return String(localized: "O bundle não contém o LaunchDaemon esperado. Use o app gerado por scripts/build.sh.")
            case .unresponsive(let reason): return String(localized: "O serviço está habilitado, mas o handshake autenticado falhou: \(reason)")
            case .incompatible(let reason): return reason
            case .outdated(let version): return String(localized: "O serviço registrado é \(version); este app é \(HelperConstants.fullVersion). Use Atualizar serviço (desconecta antes).")
            case .runtimeMissing(let reason): return reason + String(localized: " Aprove o cliente VPN que você usa.")
            case .userNotAuthorized: return String(localized: "Aprove um cliente VPN (pede senha de administrador).")
            case .ready: return String(localized: "Conectar não pede senha de administrador.")
            }
        }
        var symbol: String {
            switch self {
            case .ready: return "checkmark.shield"
            case .checking: return "hourglass"
            case .requiresApproval, .notRegistered, .runtimeMissing, .userNotAuthorized, .outdated: return "exclamationmark.shield"
            default: return "xmark.shield"
            }
        }
    }

    @Published private(set) var health: Health = .checking
    /// After an in-app update the previous helper may still be running: its binary was
    /// replaced, so its code signature no longer validates and the handshake fails. It exits
    /// 30 s after its last client leaves, so the first failed handshake of this launch drops
    /// the connection and tries once more after that, without reconnecting meanwhile.
    private var helperRestart: Task<Void, Never>?
    private var helperRestartTried = false
    var helperRestartDelay: Duration = .seconds(35)
    @Published private(set) var status: HelperStatus?
    @Published private(set) var busy = false
    @Published var message: String?
    @Published var inspection: RuntimeInspection?
    /// Client of the pending inspection (approve sends the matching request).
    var inspectionKind: RuntimeKind { inspection?.kind ?? .openfortivpn }
    @Published private(set) var blockNewSessions = false
    let policy: CodeTrust.Policy
    let registrar: ServiceRegistrar?
    let client: HelperClient?
    weak var manager: VPNManager?
    /// Poll interval/limit while waiting for sessions to end before unregistering.
    var cleanupPoll: TimeInterval = 0.3
    var cleanupLimit: TimeInterval = 120
    /// macOS reports a daemon that was never registered as notFound, like a missing one.
    /// The bundle tells them apart: with its LaunchDaemon plist it only needs activating.
    var daemonPlistInBundle: () -> Bool = {
        FileManager.default.fileExists(atPath: Bundle.main.bundleURL
            .appendingPathComponent("Contents/Library/LaunchDaemons/\(HelperConstants.plistName)").path)
    }

    init(policy: CodeTrust.Policy, registrar: ServiceRegistrar?, client: HelperClient?) {
        self.policy = policy
        self.registrar = registrar
        self.client = client
        client?.onStatus = { [weak self] status in self?.apply(status) }
        client?.onLost = { [weak self] in
            guard let self else { return }
            self.manager?.transportLost()
            if self.health == .ready { self.health = .unresponsive(String(localized: "conexão perdida; use Verificar novamente.")) }
        }
        client?.onEvents = { [weak self] batch in self?.manager?.receive(batch) }
    }

    /// Production wiring; local checks never reach the Mach service.
    static func production() -> ServiceController {
        let policy = CodeTrust.localPolicy()
        if MenuBarCoordinator.isLocalChecks {
            return ServiceController(policy: .unavailable(reason: String(localized: "Executor de verificações locais: serviço real desativado.")), registrar: nil, client: nil)
        }
        if case .trusted(let team) = policy {
            return ServiceController(policy: policy, registrar: DaemonRegistrar(), client: .production(team: team))
        }
        return ServiceController(policy: policy, registrar: DaemonRegistrar(), client: nil)
    }

    var canConnect: Bool { unavailableReason == nil }
    var isRegistered: Bool {
        guard let registrar else { return false }
        return [.enabled, .requiresApproval].contains(registrar.status)
    }
    var unavailableReason: String? {
        if blockNewSessions { return String(localized: "O serviço está sendo removido ou atualizado; novas conexões aguardam.") }
        if health == .ready, status?.anyRuntime == true { return nil }
        return "\(health.title). \(health.detail)"
    }
    func unavailableReason(for kind: RuntimeKind) -> String? {
        if let reason = unavailableReason { return reason }
        guard status?.runtime(kind) == nil else { return nil }
        let problem = status?.runtimeProblem(kind) ?? String(localized: "Nenhum \(kind.title) aprovado para o serviço.")
        return String(localized: "\(problem) Em Configurações › Serviço privilegiado, use Aprovar \(kind.title)… (requer administrador).")
    }
    var capabilities: RuntimeCapabilities? { status?.runtime?.capabilities }

    var bundleLocationWarning: String? {
        let path = Bundle.main.bundleURL.path
        return path.hasPrefix("/Applications/") ? nil :
            String(localized: "O app está em \(path). Para uso real, instale-o em /Applications antes de ativar o serviço (o registro aponta para este bundle).")
    }

    // MARK: Status

    func refresh() {
        if case .unavailable(let reason) = policy { health = .unsigned(reason); status = nil; return }
        guard let registrar else { health = .notFound; return }
        switch registrar.status {
        case .notRegistered: health = .notRegistered; status = nil
        case .requiresApproval: health = .requiresApproval; status = nil
        case .notFound: health = daemonPlistInBundle() ? .notRegistered : .notFound; status = nil
        case .enabled: handshake()
        @unknown default: health = .unresponsive(String(localized: "estado de registro desconhecido")); status = nil
        }
    }

    private func handshake() {
        guard let client else { health = .unresponsive(String(localized: "cliente indisponível")); return }
        if helperRestart != nil { return } // Waiting for the previous helper to exit.
        if health != .ready { health = .checking }
        client.request(.status) { [weak self] result in
            guard let self else { return }
            switch result {
            case .success(.status(let status)): self.apply(status)
            case .success(.failure(let failure)), .failure(let failure):
                self.status = nil
                if failure.code != .incompatibleProtocol, !self.helperRestartTried {
                    self.waitForHelperRestart()
                    return
                }
                self.health = failure.code == .incompatibleProtocol ? .incompatible(failure.message) : .unresponsive(failure.message)
            case .success: self.health = .unresponsive(String(localized: "resposta inesperada"))
            }
        }
    }

    private func waitForHelperRestart() {
        helperRestartTried = true
        client?.invalidate()
        health = .checking
        helperRestart = Task { [weak self] in
            try? await Task.sleep(for: self?.helperRestartDelay ?? .zero)
            guard let self, !Task.isCancelled else { return }
            self.helperRestart = nil
            self.refresh()
        }
    }

    func apply(_ status: HelperStatus) {
        self.status = status
        if status.helperVersion != HelperConstants.fullVersion { health = .outdated(status.helperVersion) }
        else if !status.anyRuntime {
            health = .runtimeMissing(status.runtimeProblem ?? String(localized: "Nenhum cliente VPN aprovado."))
        }
        else if !status.userAuthorized { health = .userNotAuthorized }
        else { health = .ready }
    }

    // MARK: Actions (one attempt per click; never a register loop)

    /// openingSettings: false when the caller shows what to turn on first (first-run guide).
    func activate(openingSettings: Bool = true) {
        guard case .trusted = policy, let registrar else { refresh(); return }
        if registrar.status == .enabled { refresh(); return }
        // Same label installed the legacy way would conflict; never touch someone else's file.
        let legacy = "/Library/LaunchDaemons/\(HelperConstants.plistName)"
        if FileManager.default.fileExists(atPath: legacy) {
            message = String(localized: "Já existe \(legacy) com o mesmo identificador. Remova esse item manualmente antes de ativar; o app não altera arquivos que não registrou.")
            refresh()
            return
        }
        let approval = String(localized: "Serviço registrado. Ligue o TunnelMac em Ajustes do Sistema › Itens de Início › Permitir em segundo plano.")
        do {
            try registrar.register()
            message = registrar.status == .requiresApproval ? approval : String(localized: "Serviço registrado.")
        } catch {
            let code = (error as NSError).code
            // The first registration of a daemon throws "Operation not permitted" while it
            // waits for the user's approval: that is the expected next step, not a failure.
            if registrar.status == .requiresApproval { message = approval }
            else if code == kSMErrorAlreadyRegistered { message = nil }
            else if code == kSMErrorLaunchDeniedByUser { message = String(localized: "O macOS aguarda sua aprovação em Ajustes do Sistema › Itens de Início.") }
            else if code == kSMErrorInvalidSignature { message = String(localized: "O macOS recusou a assinatura do app. Daemons exigem app assinado com Team ID e notarizado; veja o guia de ativação.") }
            else { message = String(localized: "Não foi possível registrar o serviço: \(error.localizedDescription)") }
        }
        refresh()
        // Straight to the switch the user has to turn on.
        if openingSettings, health == .requiresApproval { openSettings() }
    }

    func openSettings() { registrar?.openSystemSettings() }

    /// One click: the helper inventories the installation, then macOS asks for the
    /// administrator password and the helper freezes exactly the inspected bytes.
    func approveClient(_ kind: RuntimeKind) {
        approvingKind = kind
        inspect(candidate: BinaryLocator.defaultPath(for: kind), kind: kind, thenApprove: true)
    }
    /// Client whose approval is in progress (for the busy indicator).
    @Published private(set) var approvingKind: RuntimeKind?

    func inspect(candidate: String, kind: RuntimeKind = .openfortivpn, thenApprove: Bool = false) {
        guard let client, health != .checking else { return }
        busy = true
        inspection = nil
        let request: HelperRequest
        switch kind {
        case .openfortivpn: request = .inspectRuntime(path: candidate)
        case .openvpn: request = .inspectOpenVPNRuntime(path: candidate)
        case .wireguard: request = .inspectWireGuardRuntime(path: candidate)
        case .openconnect: request = .inspectOpenConnectRuntime(path: candidate)
        }
        client.request(request, timeout: 60) { [weak self] result in
            guard let self else { return }
            self.busy = false
            switch result {
            case .success(.inspection(let inspection)):
                self.inspection = inspection
                if thenApprove {
                    let alert = NSAlert()
                    alert.messageText = String(localized: "Aprovar código para execução como administrador?")
                    alert.informativeText = String(localized: "Origem: \(inspection.candidatePath)") + "\n\n" + Self.approvalSummary(inspection) + String(localized: "\n\nA cópia protegida não comprova a procedência do programa. Aprove somente uma instalação em que você confia.")
                    alert.addButton(withTitle: String(localized: "Aprovar"))
                    alert.addButton(withTitle: String(localized: "Cancelar"))
                    if alert.runModal() == .alertFirstButtonReturn { self.approve() }
                    else { self.inspection = nil; self.approvingKind = nil }
                }
            case .success(.failure(let failure)), .failure(let failure): self.message = failure.message; self.approvingKind = nil
            case .success: self.message = String(localized: "Resposta inesperada do serviço."); self.approvingKind = nil
            }
        }
    }

    /// One line for every file in a user-writable location (normal for Homebrew), plus the
    /// helper's other notes: one warning per file made the alert taller than the screen.
    static func approvalSummary(_ inspection: RuntimeInspection) -> String {
        let mutable = inspection.items.filter(\.mutableLocation).count
        let notes = inspection.warnings.filter { warning in !inspection.items.contains { warning.hasPrefix($0.sourcePath) } }
        var lines: [String] = []
        if mutable > 0 {
            lines.append(String(localized: "\(mutable) arquivo(s) (executável e bibliotecas) estão num local que seu usuário altera sem senha de administrador, como é normal no Homebrew. A aprovação congela exatamente estes bytes numa cópia protegida."))
        }
        return (lines + notes).joined(separator: "\n")
    }

    /// The administrator prompt is shown by macOS in this session; nothing is automated.
    func approve() {
        guard let client, let inspection else { approvingKind = nil; return }
        guard let authorization = AdminAuthorizationHandle() else {
            message = String(localized: "Não foi possível preparar a autorização do macOS."); approvingKind = nil; self.inspection = nil; return
        }
        busy = true
        let kind = inspection.kind
        let request: HelperRequest
        switch kind {
        case .openfortivpn:
            request = .approveRuntime(path: inspection.candidatePath, digest: inspection.digest, authorization: authorization.externalForm)
        case .openvpn:
            request = .approveOpenVPNRuntime(path: inspection.candidatePath, digest: inspection.digest, authorization: authorization.externalForm)
        case .wireguard:
            request = .approveWireGuardRuntime(path: inspection.candidatePath, digest: inspection.digest, authorization: authorization.externalForm)
        case .openconnect:
            request = .approveOpenConnectRuntime(path: inspection.candidatePath, digest: inspection.digest, authorization: authorization.externalForm)
        }
        client.request(request, timeout: 600) { [weak self] result in
            withExtendedLifetime(authorization) {}
            guard let self else { return }
            self.busy = false
            self.approvingKind = nil
            if case .success(.failure) = result { self.inspection = nil }
            if case .failure = result { self.inspection = nil }
            switch result {
            case .success(.status(let status)):
                self.inspection = nil
                self.apply(status)
                let version = status.runtime(kind)?.version ?? ""
                self.message = String(localized: "\(kind.title) \(version) aprovado e protegido.")
            case .success(.failure(let failure)), .failure(let failure): self.message = failure.message
            case .success: self.message = String(localized: "Resposta inesperada do serviço.")
            }
        }
    }

    /// Remove (or update) order: block new sessions → disconnect and wait for cleanup →
    /// confirm with the helper → optionally remove managed files → unregister.
    /// Unregister can kill the helper, so it is never used as a disconnect.
    func remove(includeManagedFiles: Bool, reRegister: Bool = false, completion: (() -> Void)? = nil) {
        guard let registrar else { completion?(); return }
        busy = true
        blockNewSessions = true
        manager?.disconnectAll()
        waitForCleanup(deadline: Date().addingTimeInterval(cleanupLimit)) { [weak self] cleaned in
            guard let self else { return }
            guard cleaned else {
                self.finishAction(String(localized: "As conexões ainda não confirmaram a limpeza; o serviço não foi removido."), completion)
                return
            }
            self.confirmHelperIdle { idle in
                guard idle else {
                    self.finishAction(String(localized: "A limpeza global não foi confirmada; o serviço não foi removido. Se o helper for antigo, remova o serviço pelo app anterior antes de atualizar."), completion)
                    return
                }
                self.removeFiles(includeManagedFiles) { note in
                    registrar.unregister { error in
                        if error != nil { self.client?.request(.cancelMaintenance) { _ in } }
                        else { self.client?.invalidate() }
                        var text = error.map { String(localized: "Falha ao remover o registro: \($0.localizedDescription)") } ?? String(localized: "Serviço removido. Cadastros e senhas foram preservados.")
                        if let note { text += " " + note }
                        if reRegister && error == nil {
                            do { try registrar.register(); text = String(localized: "Serviço atualizado. Se o macOS pedir, aprove novamente em Ajustes.") }
                            catch { text = String(localized: "Registro removido, mas o novo registro falhou: \(error.localizedDescription)") }
                        }
                        self.finishAction(text, completion)
                    }
                }
            }
        }
    }

    func update(completion: (() -> Void)? = nil) { remove(includeManagedFiles: false, reRegister: true, completion: completion) }

    private func finishAction(_ text: String, _ completion: (() -> Void)?) {
        busy = false
        blockNewSessions = false
        message = text
        refresh()
        completion?()
    }

    private func waitForCleanup(deadline: Date, _ done: @escaping (Bool) -> Void) {
        guard let manager, manager.anyActive else { done(true); return }
        guard Date() < deadline else { done(false); return }
        DispatchQueue.main.asyncAfter(deadline: .now() + cleanupPoll) { [weak self] in
            self?.waitForCleanup(deadline: deadline, done)
        }
    }

    private func confirmHelperIdle(_ done: @escaping (Bool) -> Void) {
        guard registrar?.status == .enabled else {
            done(registrar?.status == .notRegistered || registrar?.status == .requiresApproval); return
        }
        guard let client else { done(false); return }
        client.request(.prepareForMaintenance, timeout: 15) { [weak self] result in
            switch result {
            case .success(.done): done(true)
            case .failure(let failure) where [.transport, .timeout, .unavailable].contains(failure.code):
                // The helper cannot be reached at all (for example launchd refuses to start it
                // after the bundle changed). Its sessions would be visible as helper, supervisor
                // or managed client processes; with none running, removing the registration is
                // the way out. Any such process keeps the removal refused.
                let running = self?.privilegedProcesses() ?? []
                done(running.isEmpty)
            case .success(.failure(let failure)) where failure.code == .incompatibleProtocol,
                 .failure(let failure) where failure.code == .incompatibleProtocol:
                // A helper of another protocol answers but cannot be asked to pause. It is the
                // only process allowed to run: any supervisor or approved client keeps it refused.
                let running = (self?.privilegedProcesses() ?? []).filter { !$0.path.hasSuffix(".app/Contents/MacOS/VPNHelper") }
                done(running.isEmpty)
            default: done(false) // Other replies (busy, other users' sessions) fail closed.
            }
        }
    }

    private func removeFiles(_ include: Bool, _ done: @escaping (String?) -> Void) {
        guard include, let client, registrar?.status == .enabled else {
            done(include ? String(localized: "Arquivos gerenciados em \(HelperConstants.stateDirectory) não foram alterados (serviço inacessível).") : nil)
            return
        }
        guard let authorization = AdminAuthorizationHandle() else { done(String(localized: "Arquivos gerenciados preservados (autorização indisponível).")); return }
        client.request(.removeManagedFiles(authorization: authorization.externalForm), timeout: 600) { result in
            withExtendedLifetime(authorization) {}
            switch result {
            case .success(.done): done(String(localized: "Arquivos gerenciados do serviço removidos."))
            case .success(.failure(let failure)), .failure(let failure):
                done(String(localized: "Arquivos gerenciados preservados em \(HelperConstants.stateDirectory): \(failure.message)"))
            default: done(String(localized: "Arquivos gerenciados preservados."))
            }
        }
    }

    /// Injectable for local checks; production lists processes through libproc.
    var privilegedProcesses: () -> [(pid: pid_t, path: String)] = { Maintenance.runningPrivilegedProcesses() }

    // MARK: SessionTransport

    func start(_ request: ConnectionRequest, completion: @escaping (Result<(String, LaunchPlan), HelperFailure>) -> Void) {
        guard unavailableReason(for: .openfortivpn) == nil, let client else {
            completion(.failure(HelperFailure(.unavailable, unavailableReason(for: .openfortivpn) ?? String(localized: "Serviço indisponível.")))); return
        }
        client.request(.start(request), timeout: 30) { result in
            switch result {
            case .success(.started(let token, let plan)): completion(.success((token, plan)))
            case .success(.failure(let failure)), .failure(let failure): completion(.failure(failure))
            case .success: completion(.failure(HelperFailure(.invalidRequest, String(localized: "Resposta inesperada do serviço."))))
            }
        }
    }

    func startOpenVPN(_ request: OpenVPNRequest, completion: @escaping (Result<(String, LaunchPlan), HelperFailure>) -> Void) {
        guard unavailableReason(for: .openvpn) == nil, let client else {
            completion(.failure(HelperFailure(.unavailable, unavailableReason(for: .openvpn) ?? String(localized: "Serviço indisponível.")))); return
        }
        client.request(.startOpenVPN(request), timeout: 30) { result in
            switch result {
            case .success(.started(let token, let plan)): completion(.success((token, plan)))
            case .success(.failure(let failure)), .failure(let failure): completion(.failure(failure))
            case .success: completion(.failure(HelperFailure(.invalidRequest, String(localized: "Resposta inesperada do serviço."))))
            }
        }
    }

    func startWireGuard(_ request: WireGuardRequest, completion: @escaping (Result<(String, LaunchPlan), HelperFailure>) -> Void) {
        guard unavailableReason(for: .wireguard) == nil, let client else {
            completion(.failure(HelperFailure(.unavailable, unavailableReason(for: .wireguard) ?? String(localized: "Serviço indisponível.")))); return
        }
        client.request(.startWireGuard(request), timeout: 30) { result in
            switch result {
            case .success(.started(let token, let plan)): completion(.success((token, plan)))
            case .success(.failure(let failure)), .failure(let failure): completion(.failure(failure))
            case .success: completion(.failure(HelperFailure(.invalidRequest, String(localized: "Resposta inesperada do serviço."))))
            }
        }
    }

    func startGlobalProtect(_ request: GlobalProtectRequest, completion: @escaping (Result<(String, LaunchPlan), HelperFailure>) -> Void) {
        guard unavailableReason(for: .openconnect) == nil, let client else {
            completion(.failure(HelperFailure(.unavailable, unavailableReason(for: .openconnect) ?? String(localized: "Serviço indisponível.")))); return
        }
        client.request(.startGlobalProtect(request), timeout: 30) { result in
            switch result {
            case .success(.started(let token, let plan)): completion(.success((token, plan)))
            case .success(.failure(let failure)), .failure(let failure): completion(.failure(failure))
            case .success: completion(.failure(HelperFailure(.invalidRequest, String(localized: "Resposta inesperada do serviço."))))
            }
        }
    }

    func stop(_ token: String, completion: @escaping (HelperFailure?) -> Void) {
        guard let client else { completion(HelperFailure(.unavailable, String(localized: "Serviço indisponível."))); return }
        client.request(.stop(token: token), timeout: 15) { result in
            switch result {
            case .success(.stopped): completion(nil)
            case .success(.failure(let failure)), .failure(let failure): completion(failure)
            case .success: completion(HelperFailure(.invalidRequest, String(localized: "Resposta inesperada do serviço.")))
            }
        }
    }

    // MARK: Local checks

    /// Used only by the local checks to emulate a healthy service around a fixture helper.
    func useForLocalChecks(status: HelperStatus) { apply(status) }
}
