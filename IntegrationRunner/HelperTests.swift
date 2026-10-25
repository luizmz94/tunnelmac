@testable import VPNApp
import Foundation
import Darwin
import Security
import SwiftUI
import AppKit
import ServiceManagement
import VPNHelperCore
import VPNHelperShared

/// SPEC 04 local checks: real helper code (HelperCore, listener delegate, runtime store,
/// supervisor) driven over anonymous XPC listeners, unprivileged, with harmless children.
/// Nothing is registered, approved or installed in the system; no VPN or network is used.
@MainActor
enum HelperTests {
    /// Designated requirement of this test runner (ad hoc: its cdhash). Positive control.
    nonisolated static let ownRequirement: String = {
        var code: SecCode?
        var staticCode: SecStaticCode?
        var requirement: SecRequirement?
        var text: CFString?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code,
              SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode,
              SecCodeCopyDesignatedRequirement(staticCode, [], &requirement) == errSecSuccess, let requirement,
              SecRequirementCopyString(requirement, [], &text) == errSecSuccess, let text else { return "never" }
        return text as String
    }()
    nonisolated static let foreignTeam = "ABCDE12345"

    nonisolated static func readyStatus(help: String = SAMLCookieTests.help, authorized: Bool = true) -> HelperStatus {
        HelperStatus(protocolVersion: HelperConstants.protocolVersion, helperVersion: HelperConstants.fullVersion,
                     runtime: RuntimeSummary(id: "local", version: "1.24.1", approvedAt: Date(), capabilities: RuntimeCapabilities(help: help),
                                             sourcePath: "/fixture/openfortivpn", sourceSHA256: "0"),
                     runtimeProblem: nil, userAuthorized: authorized, activeSessions: 0, stoppingConnections: [])
    }

    /// Service marked ready for harness-based checks (no XPC behind it).
    static func readyService() -> ServiceController {
        let service = ServiceController(policy: .unavailable(reason: "verificações locais"), registrar: nil, client: nil)
        service.useForLocalChecks(status: readyStatus())
        return service
    }

    static func run() -> Int {
        var failures = 0
        func test(_ name: String, _ block: () throws -> Void) {
            do { try block(); print("PASS: Helper: \(name)") }
            catch { failures += 1; print("FAIL: Helper: \(name): \(error.localizedDescription)") }
        }
        let require = TestSupport.require
        let spin = TestSupport.spin
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("VPNGUI-helper-tests-\(UUID())")
        defer { try? FileManager.default.removeItem(at: root) }
        let passwords = PasswordStore(service: "com.luiz.vpngui.tests.helper-password.\(UUID())")
        let cookies = SAMLCookieStore(service: "com.luiz.vpngui.tests.helper-cookie.\(UUID())")
        var created: [UUID] = []
        defer { for id in created { try? passwords.delete(id); try? cookies.delete(id) } }

        func profile(_ name: String, host: String = "vpn.invalid", saml: Bool = false) -> Connection {
            let c = Connection(name: name, server: host, port: 443, username: saml ? "" : "user",
                               authentication: saml ? .saml : .password, trustedCertificate: "")
            created.append(c.id)
            return c
        }
        func model(_ name: String, service: ServiceController) throws -> AppModel {
            AppModel(store: try JSONStore(directory: root.appendingPathComponent(name)), passwords: passwords,
                     cookies: cookies, service: service)
        }
        /// App ↔ XPC ↔ HelperCore ↔ supervisor ↔ fixture script, end to end.
        func endToEnd(_ fixture: HelperFixture, _ name: String) throws -> (AppModel, ServiceController, FakeRegistrar) {
            let registrar = FakeRegistrar(.enabled)
            let service = ServiceController(policy: .trusted(team: "LOCALCHECK"), registrar: registrar, client: fixture.client())
            let model = try model(name, service: service)
            registrar.manager = model.manager
            service.refresh()
            try require(spin(10) { service.health == .ready }, "Serviço de teste não ficou pronto: \(service.health.title) \(service.health.detail)")
            return (model, service, registrar)
        }
        func connectRequest(_ id: UUID = UUID(), host: String = "vpn.invalid", password: String? = "fixturePASSvalue42",
                            authentication: Authentication = .password, mode: SAMLCookieMode = .none, cookie: String? = nil) -> ConnectionRequest {
            ConnectionRequest(connectionID: id, host: host, port: 443, username: authentication == .password ? "user" : "",
                              authentication: authentication, trustedCertificate: "", password: password, mode: mode, cookie: cookie)
        }

        // MARK: 1. Registration and status

        test("Registro: não registrado, aprovação pendente e ausente bloqueiam Conectar; ativar é uma tentativa por clique") {
            let registrar = FakeRegistrar(.notRegistered)
            let service = ServiceController(policy: .trusted(team: "LOCALCHECK"), registrar: registrar, client: nil)
            let model = try model("registration", service: service)
            service.refresh()
            try require(service.health == .notRegistered && !service.canConnect, "Não registrado tratado como pronto")
            let c = profile("Reg")
            try model.save(c, password: "fixturePASSvalue42")
            model.connect(c)
            try require(model.error?.contains("Serviço não ativado") == true && !model.manager.session(c.id).state.active,
                        "Conectar sem serviço não falhou localmente: \(model.error ?? "-")")
            for _ in 0..<5 { service.refresh() }
            try require(registrar.events.isEmpty, "Verificar status registrou o serviço")
            service.activate()
            try require(registrar.events == ["register"] && service.health == .requiresApproval, "Ativar não registrou uma vez")
            try require(service.message?.contains("Ajustes") == true, "Sem orientação de aprovação")
            service.refresh(); service.refresh()
            try require(registrar.events == ["register"], "Registro repetido sem clique")
            service.openSettings()
            try require(registrar.settingsOpened == 1, "Ajustes não abertos")
            registrar.status = .notFound
            service.refresh()
            try require(service.health == .notFound && !service.canConnect, "Helper ausente não detectado")
            registrar.status = .notRegistered
            registrar.registerError = NSError(domain: "SMAppServiceErrorDomain", code: Int(kSMErrorInvalidSignature))
            service.activate()
            try require(service.message?.contains("assinatura") == true && registrar.events.count == 2, "Erro de assinatura sem diagnóstico")
            let unsigned = ServiceController(policy: .unavailable(reason: "Build sem Team ID."), registrar: registrar, client: nil)
            unsigned.activate()
            try require(registrar.events.count == 2, "Build ad hoc tentou registrar")
            unsigned.refresh()
            if case .unsigned = unsigned.health {} else { throw TestSupport.Failure("Ad hoc não marcado como assinatura necessária") }
        }

        test("Status: habilitado sem resposta, protocolo/versão incompatíveis, runtime ausente, revogação e recuperação sem loop") {
            @MainActor func service(_ helper: FakeHelper?) -> (ServiceController, FakeRegistrar) {
                let registrar = FakeRegistrar(.enabled)
                let endpoint = helper?.listener.endpoint
                let client = HelperClient(requirement: ownRequirement) { endpoint.map { NSXPCConnection(listenerEndpoint: $0) } }
                return (ServiceController(policy: .trusted(team: "LOCALCHECK"), registrar: registrar, client: client), registrar)
            }
            let silent = FakeHelper(accept: false) { _ in .done }
            var (s, registrar) = service(silent)
            s.refresh()
            try require(spin(10) { if case .unresponsive = s.health { return true }; return false }, "Helper sem resposta tratado como saudável: \(s.health.title)")
            try require(!s.canConnect, "Conectar liberado sem handshake")
            let incompatible = FakeHelper { _ in .failure(HelperFailure(.incompatibleProtocol, "Protocolo diferente.")) }
            (s, registrar) = service(incompatible)
            s.refresh()
            try require(spin(10) { if case .incompatible = s.health { return true }; return false }, "Protocolo incompatível não detectado")
            // Atualizar serviço also works for a helper of another protocol: it cannot be asked to
            // pause, so only the helper itself may be running; a supervisor keeps it refused.
            s.privilegedProcesses = { [(1234, "/Applications/TunnelMac.app/Contents/MacOS/VPNHelper"),
                                       (1235, HelperConstants.stateDirectory + "/supervisor/VPNSupervisor-x")] }
            var finished = false
            s.update { finished = true }
            try require(spin(10) { finished } && !registrar.events.contains("unregister"), "Atualização com supervisor ativo não foi recusada")
            s.privilegedProcesses = { [(1234, "/Applications/TunnelMac.app/Contents/MacOS/VPNHelper")] }
            finished = false
            s.update { finished = true }
            try require(spin(10) { finished } && registrar.events.suffix(2) == ["unregister", "register"],
                        "Serviço de protocolo antigo não foi atualizado: \(registrar.events)")
            let old = readyStatus()
            var changed = old; changed.helperVersion = "0.1.0 (1)"
            let outdatedStatus = changed
            let outdated = FakeHelper { _ in .status(outdatedStatus) }
            (s, registrar) = service(outdated)
            s.refresh()
            try require(spin(10) { if case .outdated = s.health { return true }; return false } && !s.canConnect, "Versão antiga não exigiu atualização")
            var absent = old; absent.runtime = nil; absent.runtimeProblem = "Nenhum openfortivpn aprovado para o serviço."
            let missing = absent
            let noRuntime = FakeHelper { _ in .status(missing) }
            (s, registrar) = service(noRuntime)
            s.refresh()
            try require(spin(10) { if case .runtimeMissing = s.health { return true }; return false } && !s.canConnect, "Runtime ausente liberou Conectar")
            let notAuthorized = FakeHelper { _ in .status(readyStatus(authorized: false)) }
            (s, registrar) = service(notAuthorized)
            s.refresh()
            try require(spin(10) { s.health == .userNotAuthorized } && !s.canConnect, "Usuário não autorizado liberou Conectar")
            let healthy = FakeHelper { _ in .status(readyStatus()) }
            (s, registrar) = service(healthy)
            s.refresh()
            try require(spin(10) { s.health == .ready } && s.canConnect, "Helper saudável não ficou pronto")
            registrar.status = .requiresApproval // Revoked in System Settings.
            s.refresh()
            try require(s.health == .requiresApproval && !s.canConnect, "Revogação não propagada")
            registrar.status = .enabled
            s.refresh()
            try require(spin(10) { s.health == .ready } && registrar.events.isEmpty, "Recuperação exigiu novo registro ou loop")
        }

        // MARK: 2. IPC authentication (real code-signing checks by the system)

        test("XPC: helper recusa cliente com mesmo identificador e Team diferente; requisito correto é aceito") {
            let identifier = Bundle.main.bundleIdentifier ?? "com.luiz.vpngui.local-checks"
            let wrong = CodeTrust.requirement(identifier: identifier, team: foreignTeam)
            let strict = try HelperFixture(listenerRequirement: wrong, delegateRequirement: wrong)
            defer { strict.tearDown() }
            var result: Result<HelperStatus, HelperFailure>?
            let rejected = strict.client()
            rejected.hello { result = $0 }
            try require(spin(10) { result != nil }, "Sem resposta")
            if case .success = result { throw TestSupport.Failure("Cliente com assinatura errada foi aceito") }
            try require(strict.core.sessionCount == 0 && strict.recorder.connections.isEmpty, "Conexão rejeitada chegou ao delegate")
            let good = try HelperFixture(listenerRequirement: ownRequirement, delegateRequirement: ownRequirement)
            defer { good.tearDown() }
            result = nil
            let accepted = good.client() // Retained: pending replies belong to a live client.
            accepted.hello { result = $0 }
            try require(spin(10) { result != nil }, "Sem resposta do helper correto")
            guard case .success(let status) = result, status.protocolVersion == HelperConstants.protocolVersion else {
                throw TestSupport.Failure("Requisito correto recusado: \(String(describing: result))")
            }
        }

        test("XPC: app recusa helper falso que não satisfaz o requisito do helper") {
            let fake = FakeHelper { _ in .status(readyStatus()) }
            let endpoint = fake.listener.endpoint
            let expected = CodeTrust.requirement(identifier: HelperConstants.helperIdentifier, team: foreignTeam)
            let client = HelperClient(requirement: expected) { NSXPCConnection(listenerEndpoint: endpoint) }
            var result: Result<HelperStatus, HelperFailure>?
            client.hello { result = $0 }
            try require(spin(10) { result != nil }, "Sem resposta")
            if case .success = result { throw TestSupport.Failure("App aceitou helper falso") }
            let control = HelperClient(requirement: ownRequirement) { NSXPCConnection(listenerEndpoint: endpoint) }
            result = nil
            control.hello { result = $0 }
            try require(spin(10) { result != nil }, "Sem resposta do controle")
            if case .failure = result { throw TestSupport.Failure("Controle positivo falhou") }
        }

        test("XPC: assinatura ad hoc falha fechada; requisição antes do handshake e mensagens inválidas são recusadas") {
            if case .trusted = CodeTrust.localPolicy() { throw TestSupport.Failure("Runner ad hoc tratado como assinado com Team") }
            let closed = try HelperFixture(listenerRequirement: nil, delegateRequirement: nil)
            defer { closed.tearDown() }
            var result: Result<HelperStatus, HelperFailure>?
            let refused = closed.client()
            refused.hello { result = $0 }
            try require(spin(10) { result != nil }, "Sem resposta")
            if case .success = result { throw TestSupport.Failure("Listener sem política aceitou conexão") }
            let fixture = try HelperFixture(listenerRequirement: ownRequirement, delegateRequirement: ownRequirement)
            defer { fixture.tearDown() }
            try fixture.installFixtureRuntime()
            let raw = RawClient(endpoint: fixture.listener.endpoint)
            defer { raw.invalidate() }
            guard case .failure(let early)? = raw.send(.start(connectRequest())), early.code == .handshakeRequired else {
                throw TestSupport.Failure("Start antes do handshake não foi recusado")
            }
            guard case .failure(let status)? = raw.send(.status), status.code == .handshakeRequired else { throw TestSupport.Failure("Status sem handshake") }
            guard case .failure(let malformed)? = raw.send(Data("{not json".utf8)), malformed.code == .invalidRequest else { throw TestSupport.Failure("Mensagem malformada aceita") }
            guard case .failure(let huge)? = raw.send(Data(repeating: 0x41, count: HelperConstants.maximumRequestSize + 1)), huge.code == .invalidRequest else { throw TestSupport.Failure("Mensagem acima do limite aceita") }
            guard case .failure(let version)? = raw.send(.hello(HelloRequest(protocolVersion: 99, appVersion: "x"))), version.code == .incompatibleProtocol else { throw TestSupport.Failure("Protocolo incompatível aceito") }
            guard case .failure(let still)? = raw.send(.status), still.code == .handshakeRequired else { throw TestSupport.Failure("Handshake incompatível habilitou operações") }
            guard case .status? = raw.send(.hello(HelloRequest(appVersion: HelperConstants.fullVersion))) else { throw TestSupport.Failure("Handshake válido falhou") }
            try require(fixture.core.sessionCount == 0, "Algo iniciou antes do handshake")
        }

        test("Usuário: não autorizado e root são recusados; outro cliente não para nem recebe eventos da sessão") {
            let fixture = try HelperFixture(listenerRequirement: ownRequirement, delegateRequirement: ownRequirement)
            defer { fixture.tearDown() }
            try fixture.installFixtureRuntime(authorizedUsers: [])
            let a = RawClient(endpoint: fixture.listener.endpoint)
            defer { a.invalidate() }
            _ = a.send(.hello(HelloRequest(appVersion: HelperConstants.fullVersion)))
            guard case .failure(let denied)? = a.send(.start(connectRequest())), denied.code == .userNotAuthorized else {
                throw TestSupport.Failure("Usuário não autorizado iniciou sessão")
            }
            try fixture.installFixtureRuntime()
            // Root client (the listener refuses euid 0 before this; the core refuses too).
            let rootClient = fixture.core.connect(uid: 0, auditSession: 0) { _, ack in ack() }
            let box = ResponseBox()
            fixture.core.handle(MessageCodec.encode(HelperRequest.hello(HelloRequest(appVersion: HelperConstants.fullVersion))), from: rootClient) { _ in }
            fixture.core.handle(MessageCodec.encode(HelperRequest.start(connectRequest())), from: rootClient) {
                box.set(try? MessageCodec.decode(HelperResponse.self, from: $0, limit: 1 << 20))
            }
            _ = spin(5) { box.done }
            guard case .failure(let rootDenied)? = box.value, rootDenied.code == .userNotAuthorized else { throw TestSupport.Failure("Cliente root aceito") }
            fixture.core.disconnect(rootClient)
            guard case .started(let token, _)? = a.send(.start(connectRequest())) else { throw TestSupport.Failure("Sessão autorizada não iniciou") }
            let b = RawClient(endpoint: fixture.listener.endpoint)
            defer { b.invalidate() }
            _ = b.send(.hello(HelloRequest(appVersion: HelperConstants.fullVersion)))
            guard case .failure(let foreign)? = b.send(.stop(token: token)), foreign.code == .unknownSession else {
                throw TestSupport.Failure("Outro cliente parou a sessão")
            }
            try require(spin(5) { a.received.flatMap(\.events).contains { if case .line(let l) = $0.kind { return l.contains("Tunnel is up") }; return false } },
                        "Dono não recebeu eventos")
            try require(b.received.isEmpty, "Outro cliente recebeu eventos/logs da sessão")
            guard case .stopped? = a.send(.stop(token: token)) else { throw TestSupport.Failure("Dono não conseguiu parar") }
            try require(spin(10) { fixture.core.sessionCount == 0 }, "Sessão não terminou")
        }

        // MARK: 3. Inputs and runtime policy

        test("Entrada: injeção, opções proibidas, segredos fora do lugar e modos incoerentes são recusados no helper") {
            let caps = RuntimeCapabilities(help: SAMLCookieTests.help)
            let bad: [ConnectionRequest] = [
                connectRequest(host: "vpn.invalid\npppd-plugin = /tmp/x.so"),
                connectRequest(host: "-oProxy"),
                connectRequest(host: "https://vpn.invalid"),
                connectRequest(password: "secret\npppd-call = evil"),
                connectRequest(password: " leading"),
                connectRequest(password: nil),
                ConnectionRequest(connectionID: UUID(), host: "vpn.invalid", port: 0, username: "u", authentication: .password,
                                  trustedCertificate: "", password: "p", mode: .none, cookie: nil),
                ConnectionRequest(connectionID: UUID(), host: "vpn.invalid", port: 443, username: "u\nset-dns = 0", authentication: .password,
                                  trustedCertificate: "", password: "p", mode: .none, cookie: nil),
                ConnectionRequest(connectionID: UUID(), host: "vpn.invalid", port: 443, username: "u", authentication: .password,
                                  trustedCertificate: "zz", password: "p", mode: .none, cookie: nil),
                connectRequest(mode: .reuse, cookie: "SVPNCOOKIE=abc"),
                connectRequest(password: "p", authentication: .saml, mode: .capture),
                connectRequest(password: nil, authentication: .saml, mode: .reuse, cookie: "SVPNCOOKIE=a b"),
                connectRequest(password: nil, authentication: .saml, mode: .capture, cookie: "SVPNCOOKIE=abc"),
                connectRequest(password: nil, authentication: .saml, mode: .none)]
            for (index, request) in bad.enumerated() {
                try require((try? request.validatedPlan(capabilities: caps)) == nil, "Requisição inválida #\(index) aceita")
            }
            let legacy = RuntimeCapabilities(help: SAMLCookieTests.legacyHelp)
            try require((try? connectRequest(password: nil, authentication: .saml, mode: .reuse, cookie: "SVPNCOOKIE=abc").validatedPlan(capabilities: legacy)) == nil,
                        "Cookie aceito por versão sem --cookie-on-stdin")
            let good = try connectRequest(password: nil, authentication: .saml, mode: .capture).validatedPlan(capabilities: caps)
            try require(good.clientArguments == ["--saml-login=8020", "-v"], "Plano SAML inesperado")
            let config = try ConfigRenderer.render(host: "vpn.invalid", port: 443, username: "u", password: "p", trustedCertificate: String(repeating: "a", count: 64))
            let keys = Set(config.split(separator: "\n").map { $0.split(separator: "=").first!.trimmingCharacters(in: .whitespaces) })
            try require(keys.isSubset(of: ["host", "port", "username", "password", "trusted-cert"]), "Configuração com opção não permitida: \(keys)")
            // Over XPC, the same refusal comes back as a structured error and nothing starts.
            let fixture = try HelperFixture(listenerRequirement: ownRequirement, delegateRequirement: ownRequirement)
            defer { fixture.tearDown() }
            try fixture.installFixtureRuntime()
            let raw = RawClient(endpoint: fixture.listener.endpoint)
            defer { raw.invalidate() }
            _ = raw.send(.hello(HelloRequest(appVersion: HelperConstants.fullVersion)))
            guard case .failure(let failure)? = raw.send(.start(bad[0])), failure.code == .invalidRequest else { throw TestSupport.Failure("Helper aceitou injeção") }
            try require(fixture.core.sessionCount == 0, "Sessão iniciada com entrada inválida")
        }

        test("Runtime: caminho relativo, outro nome, script, link para outro nome e diretório gravável por todos são recusados") {
            let base = try HelperFixture.temporaryRoot()
            defer { try? FileManager.default.removeItem(atPath: base) }
            let uid = getuid()
            try require((try? RuntimeInspector.inspect(candidate: "openfortivpn", requester: uid)) == nil, "Caminho relativo aceito")
            try require((try? RuntimeInspector.inspect(candidate: "/bin/sh", requester: uid)) == nil, "Outro executável aceito")
            mkdir(base + "/script", 0o755)
            FileManager.default.createFile(atPath: base + "/script/openfortivpn", contents: Data("#!/bin/sh\necho hi\n".utf8), attributes: [.posixPermissions: 0o755])
            try require((try? RuntimeInspector.inspect(candidate: base + "/script/openfortivpn", requester: uid)) == nil, "Script aceito")
            mkdir(base + "/link", 0o755)
            symlink("/bin/sh", base + "/link/openfortivpn")
            try require((try? RuntimeInspector.inspect(candidate: base + "/link/openfortivpn", requester: uid)) == nil, "Link para outro executável aceito")
            let real = URL(fileURLWithPath: BinaryLocator.defaultPath).resolvingSymlinksInPath().path
            mkdir(base + "/open", 0o755)
            chmod(base + "/open", 0o777)
            try FileManager.default.copyItem(atPath: real, toPath: base + "/open/openfortivpn")
            do { _ = try RuntimeInspector.inspect(candidate: base + "/open/openfortivpn", requester: uid); throw TestSupport.Failure("Diretório gravável por todos aceito") }
            catch let failure as HelperFailure { try require(failure.message.contains("qualquer usuário"), "Motivo inesperado: \(failure.message)") }
            try require((try? RuntimeInspector.inspect(candidate: base + "/script/../open/openfortivpn", requester: 501_999)) == nil,
                        "Arquivo de outro usuário aceito")
        }

        let runtimeRoot = try? HelperFixture.temporaryRoot()
        defer { if let runtimeRoot { try? FileManager.default.removeItem(atPath: runtimeRoot) } }
        var installedStore: RuntimeStore?
        test("Runtime real: inventário fechado do Homebrew, cópia gerenciada e nenhum código carregado do prefixo gravável") {
            guard let runtimeRoot else { throw TestSupport.Failure("Raiz indisponível") }
            let candidate = BinaryLocator.defaultPath
            let inventory = try RuntimeInspector.inspect(candidate: candidate, requester: getuid())
            let report = inventory.report
            let libraries = report.items.filter { $0.role == .library }.map { ($0.sourcePath as NSString).lastPathComponent }
            try require(report.items.first?.role == .executable && libraries.contains { $0.hasPrefix("libssl") } && libraries.contains { $0.hasPrefix("libcrypto") },
                        "Dependências transitivas não encontradas: \(libraries)")
            try require(report.systemLibraries.contains("/usr/lib/libSystem.B.dylib"), "Bibliotecas do sistema não listadas")
            try require(report.items.allSatisfy(\.mutableLocation) && !report.warnings.isEmpty, "Local alterável do Homebrew não sinalizado")
            let store = RuntimeStore(root: runtimeRoot + "/state", ownership: TrustedOwnership(owners: [getuid()], anchor: runtimeRoot), probeIdentity: nil)
            let summary = try store.install(inventory, approvedBy: getuid())
            installedStore = store
            try require(summary.version == "1.24.1" && summary.capabilities.cookieOnStdin && summary.capabilities.samlPort, "Versão/capacidades: \(summary)")
            let active = try store.loadActive()
            for file in active.files where file.hasSuffix(".dylib") || file == "bin/openfortivpn" {
                let image = try MachOImage(file: try Data(contentsOf: URL(fileURLWithPath: active.root + "/" + file)))
                for dependency in image.dependencies {
                    try require(dependency.hasPrefix("@executable_path/../lib/") || dependency.hasPrefix("/usr/lib/") || dependency.hasPrefix("/System/"),
                                "\(file) ainda referencia \(dependency)")
                }
                try require(image.rpaths.allSatisfy { $0 == "@executable_path/../lib" }, "rpath mutável em \(file)")
            }
            try require(FileManager.default.fileExists(atPath: active.root + "/licenses"), "Licenças/proveniência não preservadas")
            // dyld reports every image it loads: none may come from the Homebrew prefix.
            let process = Process()
            process.executableURL = URL(fileURLWithPath: active.executable)
            process.arguments = ["--help"]
            var environment = active.environment
            environment["DYLD_PRINT_LIBRARIES"] = "1"
            process.environment = environment
            let pipe = Pipe()
            process.standardOutput = pipe; process.standardError = pipe
            try process.run()
            let output = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            process.waitUntilExit()
            let loaded = output.split(separator: "\n").compactMap { line -> String? in
                // "dyld[pid]: <UUID> /path" (the UUID is present on recent systems).
                guard line.hasPrefix("dyld["), let range = line.range(of: "]: ") else { return nil }
                var path = String(line[range.upperBound...])
                if path.hasPrefix("<"), let end = path.range(of: "> ") { path = String(path[end.upperBound...]) }
                // Loaded images are absolute paths; other dyld lines are diagnostics
                // (macOS 26 prints "move loaded to delayed: XPCSupport").
                return path.hasPrefix("/") ? path : nil
            }
            try require(loaded.contains { $0.hasPrefix(active.root + "/lib/libcrypto") }, "dyld não mostrou a libcrypto gerenciada: \(loaded.prefix(5))")
            for path in loaded where !(path.hasPrefix(active.root) || path.hasPrefix("/usr/lib/") || path.hasPrefix("/System/")) {
                throw TestSupport.Failure("Imagem carregada fora da cópia/sistema: \(path)")
            }
            try require(!loaded.contains { $0.contains("/opt/homebrew") }, "Algo do prefixo Homebrew foi carregado")
            try require(RuntimeCapabilities.looksLikeOpenFortiVPN(output), "Cópia gerenciada não executou --help")
        }

        test("Runtime: alteração, biblioteca extra, link simbólico, permissão de grupo e módulo OpenSSL invalidam a aprovação") {
            guard let store = installedStore else { throw TestSupport.Failure("Runtime real não instalado no teste anterior") }
            let active = try store.loadActive()
            let library = active.root + "/" + active.files.first { $0.hasPrefix("lib/libssl") }!
            let original = try Data(contentsOf: URL(fileURLWithPath: library))
            func expectRejected(_ what: String) throws {
                do { _ = try store.loadActive(); throw TestSupport.Failure("\(what) não foi detectado") }
                catch is HelperFailure {}
            }
            chmod(library, 0o644)
            var changed = original; changed.append(0)
            try changed.write(to: URL(fileURLWithPath: library))
            chmod(library, 0o444)
            try expectRejected("Biblioteca alterada")
            chmod(library, 0o644); try original.write(to: URL(fileURLWithPath: library)); chmod(library, 0o444)
            _ = try store.loadActive()
            FileManager.default.createFile(atPath: active.root + "/lib/libevil.dylib", contents: Data([0]))
            try expectRejected("Biblioteca extra")
            unlink(active.root + "/lib/libevil.dylib")
            let saved = active.root + "/../saved-libssl"
            rename(library, saved)
            symlink(saved, library)
            try expectRejected("Link simbólico")
            unlink(library); rename(saved, library)
            _ = try store.loadActive()
            chmod(active.root + "/bin", 0o775)
            try expectRejected("Diretório gravável pelo grupo")
            chmod(active.root + "/bin", 0o755)
            FileManager.default.createFile(atPath: active.root + "/lib/ossl-modules/legacy.dylib", contents: Data([0]))
            try expectRejected("Módulo OpenSSL")
            unlink(active.root + "/lib/ossl-modules/legacy.dylib")
            _ = try store.loadActive()
        }

        test("Aprovação: alteração após a inspeção (TOCTOU), recusa do administrador e Conectar não atualizam o runtime") {
            let fixture = try HelperFixture(listenerRequirement: ownRequirement, delegateRequirement: ownRequirement)
            defer { fixture.tearDown() }
            let source = fixture.root + "/source"
            mkdir(source, 0o755)
            let candidate = source + "/openfortivpn"
            try FileManager.default.copyItem(atPath: URL(fileURLWithPath: BinaryLocator.defaultPath).resolvingSymlinksInPath().path, toPath: candidate)
            let raw = RawClient(endpoint: fixture.listener.endpoint)
            defer { raw.invalidate() }
            _ = raw.send(.hello(HelloRequest(appVersion: HelperConstants.fullVersion)))
            guard case .inspection(let first)? = raw.send(.inspectRuntime(path: candidate)) else { throw TestSupport.Failure("Inspeção falhou") }
            chmod(candidate, 0o755)
            let pristine = try Data(contentsOf: URL(fileURLWithPath: candidate))
            let handle = try FileHandle(forWritingTo: URL(fileURLWithPath: candidate))
            try handle.seekToEnd(); try handle.write(contentsOf: Data([0])); try handle.close()
            guard case .failure(let toctou)? = raw.send(.approveRuntime(path: candidate, digest: first.digest, authorization: Data(count: 32))),
                  toctou.code == .runtimeRejected else { throw TestSupport.Failure("Alteração depois da inspeção foi aprovada") }
            try require(fixture.authorizer.calls == 0, "Administrador consultado para inventário divergente")
            try pristine.write(to: URL(fileURLWithPath: candidate)) // Back to the inspected bytes.
            guard case .inspection(let second)? = raw.send(.inspectRuntime(path: candidate)) else { throw TestSupport.Failure("Nova inspeção falhou") }
            fixture.authorizer.allow = false
            guard case .failure(let denied)? = raw.send(.approveRuntime(path: candidate, digest: second.digest, authorization: Data(count: 32))),
                  denied.code == .authorizationDenied else { throw TestSupport.Failure("Recusa do administrador ignorada") }
            guard case .status(let none)? = raw.send(.status), none.runtime == nil else { throw TestSupport.Failure("Runtime instalado sem aprovação") }
            fixture.authorizer.allow = true
            let approval = raw.send(MessageCodec.encode(HelperRequest.approveRuntime(path: candidate, digest: second.digest, authorization: Data(count: 32))), timeout: 180)
            guard case .status(let approved)? = approval, let runtime = approved.runtime, approved.userAuthorized else {
                throw TestSupport.Failure("Aprovação válida falhou: \(String(describing: approval))")
            }
            // A later change to the source never reaches the approved copy, not even through Connect.
            let more = try FileHandle(forWritingTo: URL(fileURLWithPath: candidate))
            try more.seekToEnd(); try more.write(contentsOf: Data([1])); try more.close()
            guard case .started(let token, _)? = raw.send(.start(connectRequest())) else { throw TestSupport.Failure("Runtime aprovado não iniciou") }
            try require(spin(15) { raw.received.flatMap(\.events).contains { $0.isTerminal } }, "Cliente sem root não terminou")
            let lines = raw.received.flatMap(\.events).compactMap { event -> String? in if case .line(let l) = event.kind { return l }; return nil }
            try require(lines.contains { $0.contains("root privileges") }, "Cópia aprovada não chegou à checagem de root: \(lines.suffix(3))")
            guard case .status(let after)? = raw.send(.status), after.runtime?.id == runtime.id else { throw TestSupport.Failure("Conectar alterou o runtime aprovado") }
            _ = token
        }

        test("Autorização de administrador: o direito precisa ser exatamente authenticate-admin; formulário inválido não pede nada") {
            try require(!SystemAdminAuthorizer.definitionIsExpected(nil), "Direito ausente aceito")
            try require(!SystemAdminAuthorizer.definitionIsExpected(["class": "allow"]), "Regra allow aceita")
            try require(!SystemAdminAuthorizer.definitionIsExpected(["class": "allow", "rule": "authenticate-admin"]), "Classe allow aceita pelo nome da regra")
            try require(!SystemAdminAuthorizer.definitionIsExpected(["rule": "authenticate-admin"]), "Regra sem classe aceita")
            try require(!SystemAdminAuthorizer.definitionIsExpected(["class": "rule", "rule": ["authenticate-admin"], "kofn": 0]), "Regra zero-de-N aceita")
            try require(SystemAdminAuthorizer.definitionIsExpected(["class": "rule", "rule": ["authenticate-admin"], "kofn": 1]), "Regra um-de-um recusada")
            try require(!SystemAdminAuthorizer.definitionIsExpected(["class": "rule", "rule": ["is-root", "authenticate-admin"]]), "Regra composta aceita")
            try require(SystemAdminAuthorizer.definitionIsExpected(["class": "rule", "rule": ["authenticate-admin"]]), "Regra esperada recusada")
            try require(!SystemAdminAuthorizer().authorize(Data(count: 3)), "Formulário de tamanho errado aceito")
        }

        test("Supervisor gerenciado: cópia protegida validada por assinatura; requisito de outro Team é recusado") {
            let base = try HelperFixture.temporaryRoot()
            defer { try? FileManager.default.removeItem(atPath: base) }
            let store = RuntimeStore(root: base + "/state", ownership: TrustedOwnership(owners: [getuid()], anchor: base), probeIdentity: nil)
            let wrong = CodeTrust.requirement(identifier: HelperConstants.supervisorIdentifier, team: foreignTeam)
            try require((try? store.preparedSupervisor(source: SupervisorLocator.path, requirement: wrong)) == nil, "Supervisor com assinatura errada aceito")
            var code: SecStaticCode?
            var requirement: SecRequirement?
            var text: CFString?
            SecStaticCodeCreateWithPath(URL(fileURLWithPath: SupervisorLocator.path) as CFURL, [], &code)
            SecCodeCopyDesignatedRequirement(code!, [], &requirement)
            SecRequirementCopyString(requirement!, [], &text)
            let copy = try store.preparedSupervisor(source: SupervisorLocator.path, requirement: text! as String)
            try require(copy.hasPrefix(store.supervisors + "/") && copy != SupervisorLocator.path, "Supervisor executado do bundle")
            let attributes = try FileManager.default.attributesOfItem(atPath: copy)
            try require((attributes[.posixPermissions] as? Int) == 0o555, "Cópia do supervisor gravável")
            try require(try Data(contentsOf: URL(fileURLWithPath: copy)) == Data(contentsOf: URL(fileURLWithPath: SupervisorLocator.path)), "Cópia diferente")
        }

        // MARK: 4–7. Sessions end to end

        let sharedFixture = try? HelperFixture(listenerRequirement: ownRequirement, delegateRequirement: ownRequirement)
        defer { sharedFixture?.tearDown() }
        try? sharedFixture?.installFixtureRuntime()

        test("Sessões: duas conexões independentes via helper; parar uma não afeta a outra; parada idempotente") {
            guard let fixture = sharedFixture else { throw TestSupport.Failure("Fixture indisponível") }
            let (model, _, _) = try endToEnd(fixture, "two")
            defer { model.manager.disconnectAll(); _ = spin(15) { fixture.core.sessionCount == 0 } }
            let a = profile("A", host: "a.invalid"), b = profile("B", host: "b.invalid")
            try model.save(a, password: "fixturePASSvalue42"); try model.save(b, password: "fixturePASSvalue42")
            model.connect(a); model.connect(b)
            let sa = model.manager.session(a.id), sb = model.manager.session(b.id)
            try require(spin(15) { sa.state == .connected && sb.state == .connected }, "Túneis fictícios não conectaram: \(sa.state) \(sb.state) \(sa.logs.suffix(3))")
            try require(fixture.core.sessionCount == 2 && sa.pid != sb.pid, "Sessões não independentes")
            let oldToken = sa.token
            model.manager.disconnect(a.id)
            model.manager.disconnect(a.id) // Repeated click: no second request.
            try require(spin(15) { sa.state == .disconnected }, "A não desconectou")
            try require(sa.logs.contains { $0.contains("Logged out") } && sa.logs.contains { $0.contains("código 0") }, "Saída/cleanup não informados")
            // The helper drops a session after the app acknowledged its final events.
            try require(spin(5) { fixture.core.sessionCount == 1 } && sb.state == .connected, "Parar A afetou B")
            if let oldToken {
                var result: HelperFailure?
                model.service.stop(oldToken) { result = $0 }
                try require(spin(5) { result != nil } && result?.code == .unknownSession, "Stop repetido não foi tratado como sessão já encerrada")
            }
            model.manager.disconnect(b.id)
            try require(spin(15) { sb.state == .disconnected && fixture.core.sessionCount == 0 }, "B não desconectou")
            try require(sa.reconnectTask == nil && sb.reconnectTask == nil, "Desconectar agendou reconexão")
        }

        test("Sessões: cancelar durante o início não deixa sessão nem processo") {
            guard let fixture = sharedFixture else { throw TestSupport.Failure("Fixture indisponível") }
            let (model, _, _) = try endToEnd(fixture, "cancel")
            defer { model.manager.disconnectAll(); _ = spin(15) { fixture.core.sessionCount == 0 } }
            let c = profile("Cancel")
            try model.save(c, password: "fixturePASSvalue42")
            model.connect(c)
            model.manager.disconnect(c.id) // Before the helper replied with a token.
            let session = model.manager.session(c.id)
            try require(spin(15) { session.state == .disconnected && fixture.core.sessionCount == 0 }, "Cancelamento deixou sessão: \(session.state) \(fixture.core.sessionCount)")
            try require(session.reconnectTask == nil, "Cancelamento agendou reconexão")
        }

        test("Sessões: helper recusa duplicata do mesmo perfil e entrega saída natural com código") {
            guard let fixture = sharedFixture else { throw TestSupport.Failure("Fixture indisponível") }
            let raw = RawClient(endpoint: fixture.listener.endpoint)
            defer { raw.invalidate() }
            _ = raw.send(.hello(HelloRequest(appVersion: HelperConstants.fullVersion)))
            let id = UUID()
            guard case .started(let token, _)? = raw.send(.start(connectRequest(id))) else { throw TestSupport.Failure("Não iniciou") }
            guard case .failure(let duplicate)? = raw.send(.start(connectRequest(id))), duplicate.code == .duplicateSession else {
                throw TestSupport.Failure("Duplicata aceita")
            }
            _ = raw.send(.stop(token: token))
            try require(spin(10) { fixture.core.sessionCount == 0 }, "Sessão não terminou")
            guard case .started? = raw.send(.start(connectRequest(UUID(), host: "exit.invalid"))) else { throw TestSupport.Failure("Saída natural não iniciou") }
            try require(spin(10) { raw.received.flatMap(\.events).contains { $0.kind == .exited(code: 0) } }, "Código de saída não entregue")
        }

        test("Sessões: início logo após a saída, antes da confirmação do evento final, não é duplicata (fallback SAML)") {
            guard let fixture = sharedFixture else { throw TestSupport.Failure("Fixture indisponível") }
            let raw = RawClient(endpoint: fixture.listener.endpoint)
            defer { raw.releaseAcks(); raw.invalidate() }
            _ = raw.send(.hello(HelloRequest(appVersion: HelperConstants.fullVersion)))
            raw.holdTerminalAcks = true
            let id = UUID()
            guard case .started? = raw.send(.start(connectRequest(id, host: "exit.invalid"))) else { throw TestSupport.Failure("Não iniciou") }
            try require(spin(10) { raw.received.flatMap(\.events).contains { $0.kind == .exited(code: 0) } }, "Saída não entregue")
            // The app reacts to the exit before acknowledging it, exactly like the cookie fallback.
            guard case .started(let token, _)? = raw.send(.start(connectRequest(id))) else { throw TestSupport.Failure("Sessão encerrada bloqueou o novo início") }
            guard case .failure(let duplicate)? = raw.send(.start(connectRequest(id))), duplicate.code == .duplicateSession else {
                throw TestSupport.Failure("Duplicata da sessão nova aceita")
            }
            raw.releaseAcks()
            _ = raw.send(.stop(token: token))
            try require(spin(10) { fixture.core.sessionCount == 0 }, "Sessão não terminou")
        }

        test("Eventos: ordem estrita, buffer limitado e descarte contabilizado com cliente lento") {
            var batches: [EventBatch] = []
            var acks: [() -> Void] = []
            let pump = EventPump(token: "t") { batch, ack in batches.append(batch); acks.append(ack) }
            pump.enqueue(.started(pid: 42))
            pump.enqueue(.cookie("SVPNCOOKIE=keepZq9"))
            for index in 0..<5000 { pump.enqueue(.line("INFO:   linha \(index) " + String(repeating: "x", count: 200))) }
            pump.enqueue(.exited(code: 0))
            try require(pump.queuedCount <= EventPump.maximumEvents, "Fila sem limite: \(pump.queuedCount)")
            var guardCount = 0
            while !acks.isEmpty && guardCount < 1000 { acks.removeFirst()(); guardCount += 1 }
            let events = batches.flatMap(\.events)
            try require(events.map(\.sequence) == Array(1...UInt64(events.count)), "Sequência com lacuna ou fora de ordem")
            let lines = events.filter { if case .line = $0.kind { return true }; return false }.count
            let dropped = events.reduce(0) { if case .dropped(let n) = $1.kind { return $0 + n }; return $0 }
            try require(lines + dropped == 5000 && dropped > 0, "Contagem de descarte incorreta: \(lines) + \(dropped)")
            try require(events.contains { $0.kind == .cookie("SVPNCOOKIE=keepZq9") } && events.contains { $0.kind == .started(pid: 42) }, "Evento essencial descartado")
            try require(events.last?.kind == .exited(code: 0), "Saída não foi o último evento")
            guard let fixture = sharedFixture else { throw TestSupport.Failure("Fixture indisponível") }
            let (model, _, _) = try endToEnd(fixture, "flood")
            defer { model.manager.disconnectAll(); _ = spin(15) { fixture.core.sessionCount == 0 } }
            let c = profile("Flood", host: "flood.invalid")
            try model.save(c, password: "fixturePASSvalue42")
            model.connect(c)
            let session = model.manager.session(c.id)
            try require(spin(20) { session.state == .disconnected }, "Saída com muitas linhas não concluiu: \(session.state)")
            try require(session.logs.count <= 1500 && session.logs.contains { $0.contains("linha") || $0.contains("line 2999") || $0.contains("descartada") }, "Logs não limitados")
        }

        test("DNS da internet: troca no serviço principal ao subir o túnel e volta ao anterior quando a última VPN sai") {
            try require(try ConnectionRules.internetDNS([" 1.1.1.1", "2606:4700:4700:0:0:0:0:1111", "1.1.1.1"]) == ["1.1.1.1", "2606:4700:4700::1111"], "Servidores não normalizados")
            for bad in [[], ["vpn.invalid"], ["0.0.0.0"], ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9"], ["1.1.1.1\nx"]] {
                try require((try? ConnectionRules.internetDNS(bad)) == nil, "DNS inválido aceito: \(bad)")
            }
            let host = RecordingWireGuardHost()
            let original: [String: Any] = ["ServerAddresses": ["192.0.2.53"], "__CONFIGURATION_ID__": "Default: SERVICE-A 0"]
            host.dns["SERVICE-A"] = original
            let directory = FileManager.default.temporaryDirectory.appendingPathComponent("tunnelmac-idns-\(UUID())").path
            try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
            defer { try? FileManager.default.removeItem(atPath: directory) }
            let record = directory + "/internet-dns.json"
            var owned = false
            let controller = InternetDNS(host: host, recordPath: record)
            controller.otherOwner = { owned }
            controller.interval = 0.1
            func current() -> [String] { host.dns["SERVICE-A"]?["ServerAddresses"] as? [String] ?? [] }
            try require(controller.acquire(token: "a", servers: ["1.1.1.1", "1.0.0.1"]).contains("1.1.1.1, 1.0.0.1"), "Sem log")
            try require(current() == ["1.1.1.1", "1.0.0.1"] && host.dns["SERVICE-A"]?["__CONFIGURATION_ID__"] as? String == "Default: SERVICE-A 0"
                        && FileManager.default.fileExists(atPath: record), "DNS não aplicado ou chaves perdidas")
            _ = controller.acquire(token: "b", servers: ["1.1.1.1", "1.0.0.1"])
            try require(controller.release(token: "a") == nil && current() == ["1.1.1.1", "1.0.0.1"], "Primeira saída restaurou cedo")
            // configd rewrote the key (network change): the monitor applies it again.
            host.dns["SERVICE-A"] = original
            try require(TestSupport.spin(3) { current() == ["1.1.1.1", "1.0.0.1"] }, "Monitor não reaplicou")
            try require(controller.release(token: "b")?.contains("restaurado") == true && current() == ["192.0.2.53"]
                        && !FileManager.default.fileExists(atPath: record), "Último não restaurou: \(current())")
            // The user changed the DNS meanwhile: their value is kept.
            _ = controller.acquire(token: "c", servers: ["8.8.8.8"])
            owned = true // keeps the monitor from re-applying while the user changes the DNS
            host.dns["SERVICE-A"] = ["ServerAddresses": ["9.9.9.9"]]
            _ = controller.release(token: "c")
            owned = false
            try require(TestSupport.spin(3) { !controller.active } && current() == ["9.9.9.9"], "DNS do usuário foi trocado: \(current())")
            // A WireGuard profile with its own DNS: nothing is applied while it owns the DNS.
            host.dns["SERVICE-A"] = original
            owned = true
            try require(controller.acquire(token: "d", servers: ["1.1.1.1"]).contains("WireGuard") && current() == ["192.0.2.53"], "Brigou com o WireGuard")
            _ = controller.release(token: "d")
            owned = false
            // Crash: a new helper process finds the record and restores the previous DNS.
            let crashed = InternetDNS(host: host, recordPath: record)
            crashed.otherOwner = { false }
            _ = crashed.acquire(token: "e", servers: ["94.140.14.14"])
            try require(current() == ["94.140.14.14"], "Não aplicou antes da queda")
            let restarted = InternetDNS(host: host, recordPath: record)
            restarted.recover()
            try require(current() == ["192.0.2.53"] && !FileManager.default.fileExists(atPath: record), "Recuperação não restaurou: \(current())")
            _ = crashed.release(token: "e")
            try require(current() == ["192.0.2.53"], "Sessão antiga mexeu depois da recuperação")
            // End to end: the app sends the choice; the helper applies it once the tunnel is up.
            host.dns["SERVICE-A"] = original
            let fixture = try HelperFixture(listenerRequirement: ownRequirement, delegateRequirement: ownRequirement, wireGuardHost: host)
            defer { fixture.tearDown() }
            try fixture.installFixtureRuntime()
            let (model, _, _) = try endToEnd(fixture, "internet-dns")
            defer { model.manager.disconnectAll(); _ = spin(15) { fixture.core.sessionCount == 0 } }
            model.manager.internetDNS = { ["94.140.14.14", "94.140.15.15"] }
            let c = profile("InternetDNS")
            try model.save(c, password: "fixturePASSvalue42")
            model.connect(c)
            let session = model.manager.session(c.id)
            try require(spin(15) { session.state == .connected && current() == ["94.140.14.14", "94.140.15.15"] }, "DNS da internet não aplicado: \(session.logs.suffix(3))")
            try require(spin(5) { session.logs.contains { $0.hasPrefix("[#] DNS da internet: 94.140.14.14") } }, "Sem linha no log")
            model.manager.disconnect(c.id)
            try require(spin(15) { session.state == .disconnected } && spin(5) { current() == ["192.0.2.53"] }, "Não restaurou ao desconectar: \(current())")
        }

        test("DNS Fortinet: domínios do gateway viram DNS por domínio no sistema enquanto o túnel existe") {
            let parsed = FortinetDNS.parse("INFO:   Got addresses: [172.29.0.7], ns [172.16.25.63, 10.1.4.100], ns_suffix [corp.example]")
            try require(parsed?.servers == ["172.16.25.63", "10.1.4.100"] && parsed?.domains == ["corp.example"], "Linha com um domínio não lida")
            let several = FortinetDNS.parse("INFO:   Got addresses: [10.0.106.6], ns [10.0.2.102, 10.0.0.91], ns_suffix [corp.example;parts.example]")
            try require(several?.domains == ["corp.example", "parts.example"], "Vários domínios não separados")
            let hostile = FortinetDNS.parse("INFO:   Got addresses: [1.2.3.4], ns [0.0.0.0, 999.1.1.1, 10.0.0.1], ns_suffix [a b;-bad.com;ok.com;x..y]")
            try require(hostile?.servers == ["10.0.0.1"] && hostile?.domains == ["a", "b", "ok.com"], "Valores do gateway não filtrados: \(String(describing: hostile))")
            try require(FortinetDNS.parse("INFO:   Tunnel is up and running.") == nil, "Linha comum lida como DNS")
            guard let fixture = sharedFixture else { throw TestSupport.Failure("Fixture indisponível") }
            let (model, _, _) = try endToEnd(fixture, "fortinet-dns")
            defer { model.manager.disconnectAll(); _ = spin(15) { fixture.core.sessionCount == 0 } }
            let c = profile("DNS")
            try model.save(c, password: "fixturePASSvalue42")
            model.connect(c)
            let session = model.manager.session(c.id)
            try require(spin(15) { session.state == .connected && fixture.dns.published.count == 1 }, "DNS não publicado: \(session.logs.suffix(3))")
            let value = fixture.dns.published.values.first ?? [:]
            try require(value["ServerAddresses"] as? [String] == ["10.9.0.53"] && value["SupplementalMatchDomains"] as? [String] == ["corp.invalid", "lab.invalid"],
                        "DNS publicado inesperado: \(value)")
            try require(spin(5) { session.logs.contains { $0.contains("DNS da VPN (10.9.0.53) para corp.invalid, lab.invalid") } }, "DNS não registrado no log")
            model.manager.disconnect(c.id)
            try require(spin(15) { session.state == .disconnected }, "Não desconectou")
            try require(spin(5) { fixture.dns.published.isEmpty }, "DNS ficou no sistema após desconectar")
            // A resolver left by an earlier helper process is removed at the next start.
            let leftover = FakeSupplementalDNS()
            _ = leftover.set(token: UUID().uuidString, value: ["ServerAddresses": ["10.0.0.1"]])
            let restarted = try HelperFixture(listenerRequirement: nil, delegateRequirement: nil, dns: leftover)
            defer { restarted.tearDown() }
            try require(spin(5) { leftover.published.isEmpty && leftover.flushes == 1 }, "DNS antigo não removido ao iniciar")
        }

        test("Certificado do cliente: arquivos 0600 do helper durante a sessão, senha da chave fora dos logs, removidos ao desconectar") {
            guard let fixture = sharedFixture else { throw TestSupport.Failure("Fixture indisponível") }
            let (model, _, _) = try endToEnd(fixture, "client-cert")
            defer { model.manager.disconnectAll(); _ = spin(15) { fixture.core.sessionCount == 0 } }
            var c = profile("Cert")
            c.clientCertificate = ClientCertificateReference(sha1: ClientCertificateTests.fixtureSHA1, name: "fixture")
            try model.save(c, password: "fixturePASSvalue42")
            model.manager.certificateExporter = { _ in ClientCertificateTests.stub }
            model.connect(c)
            let session = model.manager.session(c.id)
            try require(spin(15) { session.state == .connected }, "Não conectou com certificado: \(session.logs.suffix(3))")
            guard let line = session.logs.first(where: { $0.hasPrefix("CERTFILES=") }) else { throw TestSupport.Failure("Certificado não chegou ao cliente") }
            let parts = line.dropFirst("CERTFILES=".count).split(separator: " ").map(String.init)
            try require(parts.count >= 4 && parts[0].hasPrefix(fixture.store.clientCertificates + "/") && parts[2] == "600"
                        && line.contains("-----BEGIN CERTIFICATE----- -----BEGIN ENCRYPTED PRIVATE KEY-----"), "Arquivos inesperados: \(line)")
            try require(FileManager.default.fileExists(atPath: parts[0]) && FileManager.default.fileExists(atPath: parts[1]), "Arquivos sumiram durante a sessão")
            try require(!session.logs.joined().contains(ClientCertificateTests.passphrase), "Senha da chave nos logs")
            model.manager.disconnect(c.id)
            try require(spin(15) { session.state == .disconnected }, "Não desconectou")
            try require(spin(5) { (try? FileManager.default.contentsOfDirectory(atPath: fixture.store.clientCertificates))?.isEmpty == true },
                        "Arquivos do certificado ficaram no helper")
        }

        test("Segredos: senha e cookie fora de argv, ambiente, logs e arquivos; ambiente e descritores reduzidos") {
            guard let fixture = sharedFixture else { throw TestSupport.Failure("Fixture indisponível") }
            let (model, _, _) = try endToEnd(fixture, "secrets")
            defer { model.manager.disconnectAll(); _ = spin(15) { fixture.core.sessionCount == 0 } }
            let password = "fixturePASSvalue42"
            let c = profile("Secret")
            try model.save(c, password: password)
            model.connect(c)
            let session = model.manager.session(c.id)
            try require(spin(15) { session.state == .connected }, "Não conectou: \(session.logs.suffix(3))")
            let logs = session.logs.joined(separator: "\n")
            try require(logs.contains("ARGS=-c /dev/fd/3") && !logs.contains(password), "Senha em argv/log: \(session.logs.filter { $0.hasPrefix("ARGS") })")
            let envLine = session.logs.first { $0.hasPrefix("ENVKEYS=") } ?? ""
            let keys = Set(envLine.dropFirst("ENVKEYS=".count).split(separator: " ").map(String.init))
            let allowed: Set<String> = ["PATH", "LANG", "OPENSSL_CONF", "OPENSSL_MODULES", "OPENSSL_ENGINES", "SSL_CERT_FILE", "SSL_CERT_DIR", "PWD", "SHLVL", "_"]
            try require(!keys.isEmpty && keys.isSubset(of: allowed), "Ambiente não reduzido: \(keys.subtracting(allowed))")
            try require(session.logs.contains { $0.hasPrefix("OPENFDS=") && $0.trimmingCharacters(in: .whitespaces) == "OPENFDS=" }, "Descritores extras herdados")
            try require(try FileManager.default.contentsOfDirectory(atPath: fixture.store.work).isEmpty, "Arquivo temporário com senha ficou no helper")
            for file in [fixture.store.registryPath, fixture.store.statePath] {
                if let text = try? String(contentsOfFile: file) { try require(!text.contains(password), "Segredo em \(file)") }
            }
            model.manager.disconnect(c.id)
            try require(spin(15) { session.state == .disconnected }, "Não desconectou")
            // SAML: a saved cookie goes only through the dedicated stdin; capture never shows it.
            let s = profile("SAML", saml: true)
            try model.save(s, password: "")
            let cookie = "SVPNCOOKIE=fixtureReuseZq9\(UUID().uuidString.prefix(8))"
            try cookies.save(cookie, for: s)
            model.connect(s)
            let saml = model.manager.session(s.id)
            try require(spin(15) { saml.state == .connected }, "SAML com cookie não conectou: \(saml.logs.suffix(3))")
            try require(saml.logs.contains("STDIN_MD5=\(TestSupport.md5(cookie))"), "Cookie não chegou exatamente pelo stdin")
            try require(!saml.logs.joined().contains("fixtureReuse"), "Cookie apareceu nos logs")
            model.manager.disconnect(s.id)
            try require(spin(15) { saml.state == .disconnected }, "SAML não desconectou")
            try cookies.delete(s.id)
            model.connect(s) // Capture mode: one -v; the DEBUG cookie line is filtered in the helper.
            try require(spin(15) { saml.state == .connected }, "SAML captura não conectou")
            try require(!saml.logs.joined().contains("fixturecapture") && !saml.logs.contains { $0.hasPrefix("DEBUG") }, "DEBUG/cookie chegou aos logs")
            // The capture is written to the Keychain on the persistence queue.
            _ = spin(5) { if case .cookie = cookies.lookup(s) { return true }; return false }
            guard case .cookie(let saved) = cookies.lookup(s), saved == "SVPNCOOKIE=fixturecaptureZq9" else { throw TestSupport.Failure("Cookie capturado não foi para o Keychain") }
            model.manager.disconnect(s.id)
            try require(spin(15) { saml.state == .disconnected }, "SAML captura não desconectou")
        }

        test("Queda do XPC: helper encerra as sessões do cliente e o app marca falha sem reconectar") {
            guard let fixture = sharedFixture else { throw TestSupport.Failure("Fixture indisponível") }
            let (model, service, _) = try endToEnd(fixture, "drop")
            defer { model.manager.disconnectAll(); _ = spin(15) { fixture.core.sessionCount == 0 } }
            let c = profile("Drop")
            try model.save(c, password: "fixturePASSvalue42")
            model.connect(c)
            let session = model.manager.session(c.id)
            try require(spin(15) { session.state == .connected }, "Não conectou")
            fixture.dropConnections() // Helper crash/exit as seen by both sides.
            try require(spin(15) { session.state == .failed && fixture.core.sessionCount == 0 }, "Queda não limpou: \(session.state) \(fixture.core.sessionCount)")
            try require(session.reconnectTask == nil && session.logs.contains { $0.contains("Canal com o serviço privilegiado perdido") }, "App presumiu túnel ou reconectou")
            try require(!service.canConnect || service.health == .ready, "Estado inconsistente")
            service.refresh()
            try require(spin(10) { service.health == .ready }, "Não reconectou ao helper após verificar novamente")
        }

        test("Reinício do helper: supervisor anterior vivo bloqueia duplicata até terminar; PID reutilizado não conta") {
            let fixtureRoot = try HelperFixture.temporaryRoot()
            defer { try? FileManager.default.removeItem(atPath: fixtureRoot) }
            let previous = try TestSupport.spawn(arguments: ["/bin/sh", "-c", "trap 'exit 0' TERM; while :; do /bin/sleep 1; done", "old"])
            defer { TestSupport.finish(previous) }
            let id = UUID()
            let first = try HelperFixture(root: fixtureRoot, listenerRequirement: ownRequirement, delegateRequirement: ownRequirement)
            try first.installFixtureRuntime()
            try SessionRegistry(path: first.store.registryPath).add(token: "old", uid: getuid(), connectionID: id, pid: previous.pid)
            first.tearDown(removeFiles: false)
            let restarted = try HelperFixture(root: fixtureRoot, listenerRequirement: ownRequirement, delegateRequirement: ownRequirement)
            defer { restarted.tearDown(removeFiles: false) }
            let raw = RawClient(endpoint: restarted.listener.endpoint)
            defer { raw.invalidate() }
            guard case .status(let status)? = raw.send(.hello(HelloRequest(appVersion: HelperConstants.fullVersion))),
                  status.stoppingConnections == [id] else { throw TestSupport.Failure("Sessão anterior não reconhecida") }
            guard case .failure(let busy)? = raw.send(.start(connectRequest(id))), busy.code == .busy else { throw TestSupport.Failure("Duplicata criada durante limpeza anterior") }
            try TestSupport.stop(previous)
            _ = try TestSupport.transcript(previous)
            var exitStatus: Int32 = 0
            waitpid(previous.pid, &exitStatus, 0)
            guard case .status(let clean)? = raw.send(.status), clean.stoppingConnections.isEmpty else { throw TestSupport.Failure("Registro não liberou após saída") }
            guard case .started(let token, _)? = raw.send(.start(connectRequest(id))) else { throw TestSupport.Failure("Perfil continuou bloqueado") }
            _ = raw.send(.stop(token: token))
            try require(spin(10) { restarted.core.sessionCount == 0 }, "Sessão não terminou")
            let me = SessionRegistry.Entry(token: "x", uid: getuid(), connectionID: id, pid: getpid(), startSeconds: 1, startMicroseconds: 2)
            try require(!SessionRegistry.alive(me), "PID reutilizado tratado como o mesmo processo")
        }

        test("Encerramento do helper (SIGTERM do launchd): para e aguarda os próprios filhos") {
            let fixture = try HelperFixture(listenerRequirement: ownRequirement, delegateRequirement: ownRequirement)
            try fixture.installFixtureRuntime()
            let raw = RawClient(endpoint: fixture.listener.endpoint)
            _ = raw.send(.hello(HelloRequest(appVersion: HelperConstants.fullVersion)))
            guard case .started? = raw.send(.start(connectRequest())) else { throw TestSupport.Failure("Não iniciou") }
            try require(spin(10) { raw.received.flatMap(\.events).contains { if case .line(let l) = $0.kind { return l.contains("Tunnel is up") }; return false } }, "Não subiu")
            let started = Date()
            fixture.core.shutdown(timeout: 15)
            try require(fixture.core.sessionCount == 0 || spin(2) { fixture.core.sessionCount == 0 }, "Shutdown deixou sessão")
            try require(Date().timeIntervalSince(started) < 14, "Shutdown esperou o limite inteiro")
            raw.invalidate()
            fixture.tearDown()
        }

        // MARK: 8–9. Lifecycle and removal

        test("Remoção/atualização: unregister só depois da limpeza; novas conexões bloqueadas; cadastros e senhas preservados") {
            let registrar = FakeRegistrar(.enabled)
            let idleStatus = readyStatus()
            let helper = FakeHelper { request in
                switch request {
                case .hello, .status: return .status(idleStatus)
                case .prepareForMaintenance, .cancelMaintenance: return .done
                default: return .stopped(remaining: 0)
                }
            }
            let endpoint = helper.listener.endpoint
            let client = HelperClient(requirement: ownRequirement) { NSXPCConnection(listenerEndpoint: endpoint) }
            let service = ServiceController(policy: .trusted(team: "LOCALCHECK"), registrar: registrar, client: client)
            service.useForLocalChecks(status: readyStatus())
            service.cleanupPoll = 0.05
            let model = try model("removal", service: service)
            registrar.manager = model.manager
            let launched = SAMLCookieTests.harness(model)
            let c = profile("Keep")
            try model.save(c, password: "fixturePASSvalue42")
            model.connect(c)
            let session = model.manager.session(c.id)
            session.accept("INFO:   Tunnel is up and running.", connection: c) { _ in }
            try require(session.state == .connected && launched.plans.count == 1, "Sessão de teste não ativa")
            var finished = false
            service.remove(includeManagedFiles: false) { finished = true }
            _ = spin(0.5) { false }
            try require(registrar.events.isEmpty && session.state == .disconnecting, "Unregister antes da limpeza")
            let other = profile("Blocked")
            try model.save(other, password: "fixturePASSvalue42")
            model.connect(other)
            try require(model.error?.contains("removido ou atualizado") == true && launched.plans.count == 1, "Nova conexão durante a remoção")
            model.manager.end(session, exit: 0) // Supervisor confirmed cleanup.
            try require(spin(5) { finished }, "Remoção não concluiu")
            try require(registrar.events == ["unregister"] && registrar.activeAtUnregister == [false], "Ordem incorreta: \(registrar.events)")
            try require(try passwords.read(c.id) == "fixturePASSvalue42" && model.data.connections.contains { $0.id == c.id }, "Dados perdidos")
            let reopened = try AppModel(store: JSONStore(directory: root.appendingPathComponent("removal")), passwords: passwords, cookies: cookies, service: readyService())
            try require(reopened.data.connections.contains { $0.id == c.id }, "JSON perdido")
            registrar.status = .enabled
            registrar.afterRegister = .enabled
            finished = false
            service.update { finished = true }
            try require(spin(5) { finished } && registrar.events == ["unregister", "unregister", "register"], "Atualização fora de ordem: \(registrar.events)")
        }

        test("Menubar e janela: serviço indisponível bloqueia Conectar, mantém Desconectar e orienta Gerenciar") {
            let service = ServiceController(policy: .unavailable(reason: "ad hoc"), registrar: nil, client: nil)
            service.refresh()
            let model = try model("menubar-service", service: service)
            let c = profile("Menu")
            try model.save(c, password: "fixturePASSvalue42")
            let menuBar = MenuBarCoordinator(model: model)
            var connects = 0, disconnects = 0
            menuBar.connectAction = { _ in connects += 1 }
            menuBar.disconnectAction = { _ in disconnects += 1 }
            try require(menuBar.action(for: c) == .unavailable, "Conectar disponível sem serviço")
            menuBar.perform(c)
            try require(connects == 0, "Menu conectou sem serviço")
            model.manager.session(c.id).state = .connected
            try require(menuBar.action(for: c) == .disconnect, "Desconectar bloqueado sem serviço")
            menuBar.perform(c)
            try require(disconnects == 1, "Desconectar não encaminhado")
            model.manager.session(c.id).state = .disconnected
            menuBar.activateApp = {}
            var policies: [NSApplication.ActivationPolicy] = []
            menuBar.setActivationPolicy = { policies.append($0) }
            var settingsOpened = 0
            menuBar.openSettingsFallback = { settingsOpened += 1 }
            menuBar.settingsTab = .general
            menuBar.showServiceManagement()
            try require(menuBar.settingsTab == .service && settingsOpened == 1 && policies.last == .regular,
                        "Gerenciar não abriu Configurações › Serviço privilegiado")
        }

        test("UI: área do serviço e orientação renderizam fora da tela (sem abrir o app real)") {
            let output = Bundle.main.bundleURL.deletingLastPathComponent()
            @MainActor func render<V: View>(_ view: V, size: NSSize, name: String) throws {
                let window = NSWindow(contentRect: NSRect(x: -20000, y: -20000, width: size.width, height: size.height),
                                      styleMask: [.borderless], backing: .buffered, defer: false)
                window.isReleasedWhenClosed = false
                let host = NSHostingView(rootView: view.frame(width: size.width, height: size.height)
                    .background(Color(nsColor: .windowBackgroundColor)))
                host.appearance = NSAppearance(named: .aqua)
                window.appearance = NSAppearance(named: .aqua)
                host.frame = NSRect(origin: .zero, size: size)
                window.contentView = host
                window.orderFrontRegardless()
                _ = spin(0.3) { false }
                host.layoutSubtreeIfNeeded()
                guard let bitmap = host.bitmapImageRepForCachingDisplay(in: host.bounds) else { throw TestSupport.Failure("Sem bitmap") }
                host.cacheDisplay(in: host.bounds, to: bitmap)
                window.orderOut(nil)
                guard let png = bitmap.representation(using: .png, properties: [:]), png.count > 2000 else { throw TestSupport.Failure("Render vazio: \(name)") }
                try png.write(to: output.appendingPathComponent("ui-preview-\(name).png"))
            }
            let registrar = FakeRegistrar(.notRegistered)
            let pending = ServiceController(policy: .trusted(team: "LOCALCHECK"), registrar: registrar, client: nil)
            pending.refresh()
            let pendingModel = try model("ui", service: pending)
            try render(ServicePanel(model: pendingModel).padding(20), size: NSSize(width: 620, height: 330), name: "service-not-registered")
            try render(ServiceStatusRow(service: pending) {}, size: NSSize(width: 300, height: 40), name: "service-row")
            let ready = readyService()
            ready.inspection = RuntimeInspection(candidatePath: "/opt/homebrew/bin/openfortivpn", resolvedPath: "/opt/homebrew/Cellar/openfortivpn/1.24.1_1/bin/openfortivpn",
                                                 digest: "d", items: [InventoryItem(role: .executable, sourcePath: "/opt/homebrew/Cellar/openfortivpn/1.24.1_1/bin/openfortivpn",
                                                                                    sha256: String(repeating: "a", count: 64), size: 1, ownerUID: 501, mutableLocation: true)],
                                                 systemLibraries: ["/usr/lib/libSystem.B.dylib"], packageVersion: "openfortivpn 1.24.1_1",
                                                 warnings: ["Exemplo de aviso de local alterável."])
            let readyModel = try model("ui-ready", service: ready)
            try render(ServicePanel(model: readyModel).padding(20), size: NSSize(width: 620, height: 600), name: "service-approval")
            let c = profile("Exemplo")
            try pendingModel.save(c, password: "fixturePASSvalue42")
            try render(ConnectionDetail(connection: c, session: pendingModel.manager.session(c.id), model: pendingModel, edit: {}, delete: {}),
                       size: NSSize(width: 620, height: 260), name: "detail-unavailable")
        }

        test("LaunchDaemon: plist do bundle sem RunAtLoad/KeepAlive, programa relativo ao app e Mach service exclusivo") {
            let app = Bundle.main.bundleURL.deletingLastPathComponent().appendingPathComponent("TunnelMac.app")
            let plistURL = app.appendingPathComponent("Contents/Library/LaunchDaemons/\(HelperConstants.plistName)")
            let data = try Data(contentsOf: plistURL)
            guard let plist = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else { throw TestSupport.Failure("Plist ilegível") }
            try require(plist["Label"] as? String == HelperConstants.helperIdentifier, "Label")
            try require(plist["BundleProgram"] as? String == "Contents/MacOS/VPNHelper", "BundleProgram")
            try require((plist["MachServices"] as? [String: Bool])?[HelperConstants.machServiceName] == true, "MachServices")
            try require(plist["AssociatedBundleIdentifiers"] as? [String] == [HelperConstants.appIdentifier], "AssociatedBundleIdentifiers")
            for key in ["RunAtLoad", "KeepAlive", "Program", "ProgramArguments", "StartInterval", "WatchPaths", "UserName"] {
                try require(plist[key] == nil, "Chave proibida: \(key)")
            }
            try require(FileManager.default.isExecutableFile(atPath: app.appendingPathComponent("Contents/MacOS/VPNHelper").path), "Helper ausente no bundle")
            try require(!FileManager.default.fileExists(atPath: "/Library/LaunchDaemons/\(HelperConstants.plistName)"), "Plist instalado manualmente em /Library/LaunchDaemons")
        }

        test("Maintenance: global idle gates starts, ignores untrusted peer and releases on cancellation") {
            let fixture = try HelperFixture(listenerRequirement: ownRequirement, delegateRequirement: ownRequirement)
            defer { fixture.tearDown() }
            try fixture.installFixtureRuntime()
            let first = RawClient(endpoint: fixture.listener.endpoint)
            let second = RawClient(endpoint: fixture.listener.endpoint)
            defer { first.invalidate(); second.invalidate() }
            _ = first.send(.hello(HelloRequest(appVersion: HelperConstants.fullVersion)))
            _ = second.send(.hello(HelloRequest(appVersion: HelperConstants.fullVersion)))
            guard case .started(let token, _) = first.send(.start(connectRequest())) else { throw TestSupport.Failure("Fixture did not start") }
            guard case .failure(let busy) = second.send(.prepareForMaintenance), busy.code == .busy else {
                throw TestSupport.Failure("Maintenance accepted another client's active session")
            }
            _ = first.send(.stop(token: token))
            try require(spin(10) { fixture.core.sessionCount == 0 }, "Cleanup did not finish")
            try require(second.send(.prepareForMaintenance) == .done, "Idle helper refused maintenance")
            guard case .failure(let blocked) = first.send(.start(connectRequest())), blocked.code == .busy else {
                throw TestSupport.Failure("New session entered during maintenance")
            }
            _ = first.send(.cancelMaintenance)
            guard case .failure = first.send(.start(connectRequest())) else { throw TestSupport.Failure("Another client cancelled the lease") }
            _ = second.send(.cancelMaintenance)
            guard case .started(let newToken, _) = first.send(.start(connectRequest())) else { throw TestSupport.Failure("Cancellation did not restore starts") }
            _ = first.send(.stop(token: newToken))
            try require(spin(10) { fixture.core.sessionCount == 0 }, "Final cleanup did not finish")
        }

        test("Homebrew sandbox: maintenance keeps the registration, sees running product processes without mach-lookup") {
            for path in ["/Applications/TunnelMac.app/Contents/MacOS/VPNGUI", "/x/VPNGUI.app/Contents/MacOS/VPNSupervisor",
                         "/Applications/OpenFortiDesk.app/Contents/MacOS/VPNGUI",
                         HelperConstants.stateDirectory + "/supervisor/VPNSupervisor-0", HelperConstants.stateDirectory + "/runtime/0/bin/openfortivpn"] {
                try require(Maintenance.isProductExecutable(path), "Product process missed: \(path)")
            }
            for path in ["/Applications/TunnelMac.app/Contents/MacOS/VPNHelper", "/x/VPNGUILocalChecks.app/Contents/MacOS/VPNGUI",
                         "/opt/homebrew/bin/openfortivpn", HelperConstants.stateDirectory + "-other/x"] {
                try require(!Maintenance.isProductExecutable(path), "Unrelated process matched: \(path)")
            }
            let root = FileManager.default.temporaryDirectory.appendingPathComponent("VPNGUI-sandbox-\(UUID())")
            defer { try? FileManager.default.removeItem(at: root) }
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
            let (template, origin) = try HomebrewSandbox.template()
            let profile = root.appendingPathComponent("cask.sb")
            try HomebrewSandbox.profile(template).write(to: profile, atomically: true, encoding: .utf8)
            guard let command = Bundle.main.executableURL?.path else { throw TestSupport.Failure("Runner executable") }
            func sandboxed(_ argument: String) throws -> (status: Int32, errors: String) {
                let process = Process()
                let errors = Pipe()
                process.executableURL = URL(fileURLWithPath: "/usr/bin/sandbox-exec")
                process.arguments = ["-f", profile.path, command, argument]
                process.environment = ["PATH": "/usr/bin:/bin", "HOME": root.path]
                process.standardOutput = FileHandle.nullDevice
                process.standardError = errors
                try process.run()
                let output = errors.fileHandleForReading.readDataToEndOfFile()
                process.waitUntilExit()
                return (process.terminationStatus, String(decoding: output, as: UTF8.self))
            }
            // Real product processes cannot be hidden from a global scan: expect what the scan sees outside.
            let real = Maintenance.runningProductProcesses()
            let clean = try sandboxed(Maintenance.argument)
            if real.isEmpty {
                try require(clean.status == 0, "Absent app refused in the sandbox (\(origin)): \(clean.errors)")
            } else {
                try require(clean.status == 1 && real.allSatisfy { clean.errors.contains("\($0.pid) \($0.path)") },
                            "Sandbox scan differs from the real one: \(clean.errors)")
                print("NOTE: TunnelMac is running on this Mac; the exit-0 case runs only when it is closed")
            }
            try require(!clean.errors.contains("signed app"), "Restricted mode not detected in the sandbox")
            // Harmless stand-in at an app path: a copy of /bin/sleep, ended by this test.
            let fakeURL = root.appendingPathComponent("TunnelMac.app/Contents/MacOS/VPNGUI")
            try FileManager.default.createDirectory(at: fakeURL.deletingLastPathComponent(), withIntermediateDirectories: true)
            try FileManager.default.copyItem(atPath: "/bin/sleep", toPath: fakeURL.path)
            // A copied platform binary is killed at exec; an ad hoc signature lets it run.
            let sign = Process()
            sign.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
            sign.arguments = ["--force", "--sign", "-", fakeURL.path]
            sign.standardOutput = FileHandle.nullDevice
            sign.standardError = FileHandle.nullDevice
            try sign.run()
            sign.waitUntilExit()
            try require(sign.terminationStatus == 0, "Stand-in not signed")
            let fake = Process()
            fake.executableURL = fakeURL
            fake.arguments = ["60"]
            try fake.run()
            defer { if fake.isRunning { fake.terminate() }; fake.waitUntilExit() }
            _ = spin(0.5) { false }
            try require(fake.isRunning && Maintenance.runningProductProcesses().contains { $0.pid == fake.processIdentifier }, "Stand-in not running")
            for argument in [Maintenance.argument, Maintenance.legacyMigrationArgument] {
                let busy = try sandboxed(argument)
                try require(busy.status == 1 && busy.errors.contains("\(fake.processIdentifier) ")
                            && busy.errors.contains("/TunnelMac.app/Contents/MacOS/VPNGUI") && busy.errors.contains(Maintenance.quitAndRetry),
                            "Running app not refused by \(argument): \(busy.errors)")
            }
        }

        return failures
    }
}
