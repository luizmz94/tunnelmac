@testable import VPNApp
import Foundation
import Darwin
import CryptoKit
import ProcessBridge
import VPNHelperCore
import VPNHelperShared

// SPEC 01 local checks. Synthetic cookies only: no VPN, no browser, no privileges,
// no network. Keychain items use a disposable service and are deleted at the end.
@MainActor
enum SAMLCookieTests {
    nonisolated static let help = "Usage: openfortivpn [--cookie=<cookie>] [--cookie-on-stdin] [--saml-login]\n --saml-login[=port]\n [-c <file>] [-v|-q] --config --trusted-cert openfortivpn"
    nonisolated static let legacyHelp = "Usage: openfortivpn [--saml-login]\n --saml-login[=port]\n [-c <file>] [-v|-q] --config --trusted-cert openfortivpn"

    /// Records launches instead of reaching the helper (no process, no privilege, no network).
    static func harness(_ model: AppModel, help: String = help) -> LaunchRecorder {
        let launches = LaunchRecorder()
        model.manager.harness = VPNManager.LaunchHarness(help: help) { session, request, plan in
            launches.plans.append((session.id, plan))
            launches.requests.append(request)
            session.state = .connecting
        }
        return launches
    }

    static func run() -> Int {
        var failures = 0
        func test(_ name: String, _ block: () throws -> Void) {
            do { try block(); print("PASS: SAML/cookie: \(name)") }
            catch { failures += 1; print("FAIL: SAML/cookie: \(name): \(error.localizedDescription)") }
        }
        func require(_ condition: @autoclosure () throws -> Bool, _ message: String) throws {
            if try !condition() { throw AppFailure(message) }
        }
        let cookies = SAMLCookieStore(service: "com.luiz.vpngui.tests.saml-cookie.\(UUID())")
        let passwords = PasswordStore(service: "com.luiz.vpngui.tests.saml-password.\(UUID())")
        let testRoot = FileManager.default.temporaryDirectory.appendingPathComponent("VPNGUI-saml-tests-\(UUID())")
        defer { try? FileManager.default.removeItem(at: testRoot) }
        var created: [UUID] = []
        defer { for id in created { try? cookies.delete(id); try? passwords.delete(id) } }
        func profile(_ name: String = "SAML local") -> Connection {
            let value = Connection(name: name, server: "vpn.invalid", port: 443, username: "",
                                   authentication: .saml, trustedCertificate: "")
            created.append(value.id)
            return value
        }
        func synthetic(_ tag: String = UUID().uuidString) -> String {
            "SVPNCOOKIE=synthetic\(tag.replacingOccurrences(of: "-", with: ""))Zq9"
        }

        // MARK: Capture

        test("Captura estrita, fragmentada byte a byte, sem expor DEBUG") {
            let cookie = synthetic()
            let output = "INFO:   Connected to gateway.\nINFO:   Authenticated.\nDEBUG:  Cookie: \(cookie)\nINFO:   Remote gateway has allocated a VPN.\n"
            var filter = OutputLineFilter(captureCookie: true)
            var events: [OutputLineFilter.Event] = []
            for byte in Data(output.utf8) { events += filter.feed(Data([byte])) }
            events += filter.finish()
            try require(events.filter { $0 == .cookie(cookie) }.count == 1, "Cookie não capturado uma única vez")
            let lines = events.compactMap { if case .line(let line) = $0 { return line } else { return nil } }
            try require(lines == ["INFO:   Connected to gateway.", "INFO:   Authenticated.", "INFO:   Remote gateway has allocated a VPN."], "Linhas alteradas: \(lines)")
            try require(!lines.joined().contains("synthetic") && !lines.joined().contains("DEBUG"), "DEBUG ou cookie vazou")
        }
        test("Captura rejeita formatos malformados e não captura sem modo de captura") {
            for line in ["DEBUG:  Cookie: SVPNCOOKIE=", "DEBUG:  Cookie: SVPNCOOKIE=a b", "DEBUG:  Cookie: SVPNCOOKIE=ab;c",
                         "DEBUG:  Cookie: OTHER=abc", "DEBUG: Cookie:SVPNCOOKIE=abc", "INFO:   Cookie: SVPNCOOKIE=abc",
                         "DEBUG:  Cookie: SVPNCOOKIE=" + String(repeating: "a", count: 4096), "xDEBUG:  Cookie: SVPNCOOKIE=abc"] {
                try require(SAMLCookieRules.capture(line) == nil, "Formato inválido aceito: \(line.prefix(40))")
            }
            try require(SAMLCookieRules.capture("DEBUG:  Cookie: SVPNCOOKIE=" + String(repeating: "a", count: 4085)) != nil, "Tamanho máximo recusado")
            var disabled = OutputLineFilter(captureCookie: false)
            let events = disabled.feed(Data("DEBUG:  Cookie: \(synthetic())\n".utf8))
            try require(events.isEmpty, "Cookie extraído/exibido fora do modo de captura")
        }
        test("Continuação multilinha de DEBUG e segredo sem rótulo são descartados") {
            let cookie = synthetic()
            let bare = String(cookie.dropFirst(SAMLCookieRules.prefix.count))
            var filter = OutputLineFilter(captureCookie: true)
            var events = filter.feed(Data("DEBUG:  http_receive:\nHTTP/1.1 200 OK\r\nSet-Cookie: x=secret-continuation\n".utf8))
            events += filter.feed(Data("INFO:   Authenticated.\nDEBUG:  Cookie: \(cookie)\n".utf8))
            events += filter.feed(Data("unlabelled \(bare) value\nERROR:  plain error\nunlabelled after error \(bare)\nunlabelled harmless\n".utf8))
            let lines = events.compactMap { if case .line(let line) = $0 { return line } else { return nil } }
            try require(!lines.joined().contains("secret-continuation") && !lines.joined().contains("HTTP/1.1"), "Continuação DEBUG vazou")
            try require(!lines.joined().contains(bare), "Segredo sem rótulo vazou")
            try require(lines == ["INFO:   Authenticated.", "ERROR:  plain error", "unlabelled harmless"], "Filtro removeu linhas legítimas: \(lines)")
        }
        test("Linha longa: descarte inclui o restante, sem reaparecer como linha nova") {
            var filter = OutputLineFilter(captureCookie: true)
            var events = filter.feed(Data(("INFO:   " + String(repeating: "x", count: OutputLineFilter.maximumLine + 10)).utf8))
            events += filter.feed(Data("tail-of-long-line\nINFO:   next\n".utf8))
            try require(events == [.overflow, .line("INFO:   next")], "Resto da linha longa reapareceu: \(events)")
        }
        test("Cookie conhecido nunca entra nos logs, mesmo sem rótulo") {
            let cookie = synthetic()
            var filter = OutputLineFilter(captureCookie: false, secrets: [cookie])
            let events = filter.feed(Data("INFO:   echo \(cookie)\nraw \(cookie.dropFirst(11))\nINFO:   ok\n".utf8))
            try require(events == [.line("INFO:   ok")], "Cookie fornecido vazou: \(events.count)")
            let session = Session(id: UUID())
            session.log("value \(cookie)")
            try require(!session.logs.joined().contains(cookie.dropFirst(11)), "OutputRules expôs cookie")
        }

        // MARK: Keychain cache

        test("Keychain real: criar, ler, atualizar e excluir em serviço descartável") {
            let c = profile()
            let first = synthetic(), second = synthetic()
            try cookies.save(first, for: c)
            guard case .cookie(let read) = cookies.lookup(c), read == first else { throw AppFailure("Leitura diferente") }
            try cookies.save(second, for: c)
            guard case .cookie(let updated) = cookies.lookup(c), updated == second else { throw AppFailure("Atualização diferente") }
            try cookies.delete(c.id)
            guard case .none = cookies.lookup(c) else { throw AppFailure("Cookie ainda existe") }
            try require(try passwords.read(c.id) == nil, "Cookie gravado no serviço de senhas")
        }
        test("Expiração: 30 minutos, expiração anterior conhecida e leitura sem renovar") {
            let c = profile()
            let now = Date()
            try cookies.save(synthetic(), for: c, capturedAt: now.addingTimeInterval(-29 * 60))
            let before = try cookies.read(c.id)?.expiresAt
            guard case .cookie = cookies.lookup(c, now: now) else { throw AppFailure("Cookie dentro do prazo recusado") }
            try require(try cookies.read(c.id)?.expiresAt == before, "Leitura renovou o prazo")
            guard case .none = cookies.lookup(c, now: now.addingTimeInterval(61)) else { throw AppFailure("Cookie vencido aceito") }
            try require(try cookies.read(c.id) == nil, "Cookie vencido não foi removido")
            try cookies.save(synthetic(), for: c, capturedAt: now, knownExpiry: now.addingTimeInterval(120))
            guard case .none = cookies.lookup(c, now: now.addingTimeInterval(121)) else { throw AppFailure("Expiração anterior ignorada") }
            try cookies.save(synthetic(), for: c, capturedAt: now.addingTimeInterval(600))
            guard case .none = cookies.lookup(c, now: now) else { throw AppFailure("Captura no futuro aceita") }
        }
        test("Identidade: host, porta, usuário, autenticação, certificado e UUID; renomear mantém") {
            let c = profile()
            try cookies.save(synthetic(), for: c)
            var renamed = c; renamed.name = "Outro nome"
            guard case .cookie = cookies.lookup(renamed) else { throw AppFailure("Renomear invalidou") }
            var variants: [Connection] = []
            var v = c; v.server = "other.invalid"; variants.append(v)
            v = c; v.port = 10443; variants.append(v)
            v = c; v.username = "someone"; variants.append(v)
            v = c; v.trustedCertificate = String(repeating: "c", count: 64); variants.append(v)
            for variant in variants {
                try cookies.save(synthetic(), for: c)
                guard case .none = cookies.lookup(variant) else { throw AppFailure("Cookie cruzou identidade diferente") }
            }
            try cookies.save(synthetic(), for: c)
            v = c; v.authentication = .password
            guard case .none = cookies.lookup(v) else { throw AppFailure("Perfil por senha usou cookie") }
            var twin = profile(); twin.name = c.name
            guard case .none = cookies.lookup(twin) else { throw AppFailure("Conexão homônima recebeu cookie") }
            var upper = c; upper.server = "VPN.INVALID"
            try cookies.save(synthetic(), for: c)
            guard case .cookie = cookies.lookup(upper) else { throw AppFailure("Host não normalizado") }
        }
        test("Cadastro: salvar alteração/certificado/exclusão invalida; renomear preserva") {
            let store = try JSONStore(directory: testRoot.appendingPathComponent("model"))
            let model = AppModel(store: store, passwords: passwords, cookies: cookies)
            var c = profile()
            try model.save(c, password: "")
            let cookie = synthetic()
            try cookies.save(cookie, for: c)
            c.name = "Renomeada"; try model.save(c, password: "")
            guard case .cookie = cookies.lookup(c) else { throw AppFailure("Renomear apagou o cache") }
            let json = try String(contentsOf: store.file)
            try require(!json.contains("synthetic") && !json.contains("SVPNCOOKIE"), "Cookie em JSON")
            c.port = 8443; try model.save(c, password: "")
            try require(try cookies.read(c.id) == nil, "Mudança de porta não invalidou")
            try cookies.save(synthetic(), for: c)
            try model.delete(c)
            try require(try cookies.read(c.id) == nil, "Exclusão não invalidou")
            let defaults = UserDefaults.standard.dictionaryRepresentation().description
            try require(!defaults.contains(cookie), "Cookie em UserDefaults")
        }

        // MARK: Launch plan and transport

        test("Plano: cookie por canal protegido, nunca em argv; SAML com um único -v; senha inalterada") {
            let reuse = LaunchPlan.make(authentication: .saml, help: help, cookieAvailable: true)
            try require(reuse.mode == .reuse && reuse.clientArguments.isEmpty, "Reaproveitamento iniciou SAML")
            let args = reuse.supervisorArguments(binary: "/bin/ofv")
            try require(args == ["--cookie-fd", "/bin/ofv"], "Argumentos inesperados: \(args)")
            let saml = LaunchPlan.make(authentication: .saml, help: help, cookieAvailable: false)
            try require(saml.mode == .capture && saml.clientArguments == ["--saml-login=8020", "-v"], "Captura sem -v único")
            try require(!saml.supervisorArguments(binary: "b").contains("--cookie-fd"), "Login SAML recebeu cookie")
            let legacy = LaunchPlan.make(authentication: .saml, help: legacyHelp, cookieAvailable: true)
            try require(legacy.mode == .none && legacy.clientArguments == ["--saml-login=8020"], "Versão incompatível tratada como funcional")
            let password = LaunchPlan.make(authentication: .password, help: help, cookieAvailable: true)
            try require(password.mode == .none && password.clientArguments.isEmpty, "Perfil por senha mudou")
            let cookie = synthetic()
            let conf = try ConfigRenderer.render(host: "vpn.invalid", port: 443, username: "user", password: nil, trustedCertificate: "")
            try require(!conf.contains("synthetic") && !conf.lowercased().contains("cookie"), "Cookie no vpn.conf")
            let fd = try ProtectedDescriptor.pipe(Data(cookie.utf8))
            defer { close(fd) }
            var buffer = [UInt8](repeating: 0, count: 8192)
            var data = Data()
            while true { let n = Darwin.read(fd, &buffer, buffer.count); if n <= 0 { break }; data.append(contentsOf: buffer.prefix(n)) }
            try require(String(decoding: data, as: UTF8.self) == cookie, "Conteúdo do cookie alterado (sem quebra de linha) ou sem EOF")
            let request = ConnectionRequest(connectionID: UUID(), host: "vpn.invalid", port: 443, username: "", authentication: .saml,
                                            trustedCertificate: "", password: nil, mode: .reuse, cookie: "SVPNCOOKIE=a\nb")
            try require((try? request.validatedPlan(capabilities: RuntimeCapabilities(help: help))) == nil, "Cookie com quebra de linha aceito")
        }

        func spawn(cookie: String?, _ client: [String], config: String = "host = vpn.invalid\nport = 443\nusername = local\n") throws -> TestSupport.Run {
            try TestSupport.spawn(configText: config, cookie: cookie.map { Data($0.utf8) },
                                  arguments: (cookie != nil ? ["--cookie-fd"] : []) + client)
        }
        func transcript(_ run: TestSupport.Run) throws -> String { try TestSupport.transcript(run) }
        func finish(_ run: TestSupport.Run) { TestSupport.finish(run) }
        func md5(_ text: String) -> String { TestSupport.md5(text) }
        let readStdin = "/sbin/md5 -q; for f in 4 5 6 7 8 9 10 11 12 13 14 15; do [ -e /dev/fd/$f ] && echo OPENFD=$f; done; echo ARGS=\"$*\"; echo DONE"

        test("Supervisor: stdin dedicado com EOF, nenhum arquivo temporário e só descritores necessários") {
            let cookie = synthetic()
            let run = try spawn(cookie: cookie, ["/bin/sh", "-c", readStdin, "fixture"])
            defer { finish(run) }
            let output = try transcript(run)
            try require(output.contains(md5(cookie)), "Filho não recebeu exatamente o cookie pelo stdin: \(output)")
            try require(output.contains("DONE") && output.contains("__VPNGUI_EXIT__=0"), "EOF ausente ou saída sem confirmação")
            try require(!output.contains("OPENFD="), "Descritor extra herdado: \(output)")
            try require(output.contains("ARGS=--cookie-on-stdin -c /dev/fd/3"), "Argumentos do cliente inesperados")
            try require(!output.contains("synthetic"), "Cookie apareceu na saída")
        }
        test("Supervisor: sem cookie, stdin continua /dev/null e o descritor 4 não é herdado") {
            let run = try spawn(cookie: nil, ["/bin/sh", "-c", "/bin/cat; [ -e /dev/fd/4 ] && echo FD4; echo EMPTY", "fixture"])
            defer { finish(run) }
            let output = try transcript(run)
            try require(output.contains("EMPTY") && output.contains("__VPNGUI_EXIT__=0") && !output.contains("--cookie") && !output.contains("FD4"), "stdin padrão alterado: \(output)")
        }
        test("Supervisor: STOP antes e durante a leitura do cookie encerra e limpa") {
            for script in ["trap 'exit 0' TERM; while :; do /bin/sleep 1; done",
                           "/usr/bin/head -c 4 >/dev/null; trap 'exit 0' TERM; while :; do /bin/sleep 1; done"] {
                let run = try spawn(cookie: synthetic(), ["/bin/sh", "-c", script, "fixture"])
                defer { finish(run) }
                try TestSupport.stop(run) // Sent immediately: may arrive while the supervisor loads the cookie.
                let output = try transcript(run)
                try require(output.contains("__VPNGUI_EXIT__="), "Sem confirmação após STOP")
                try require(!output.contains("synthetic"), "Cookie vazou após STOP")
            }
        }
        test("Supervisor: duas conexões recebem somente o próprio cookie") {
            let first = synthetic(), second = synthetic()
            let r1 = try spawn(cookie: first, ["/bin/sh", "-c", readStdin, "fixture"])
            defer { finish(r1) }
            let r2 = try spawn(cookie: second, ["/bin/sh", "-c", readStdin, "fixture"])
            defer { finish(r2) }
            let o1 = try transcript(r1), o2 = try transcript(r2)
            try require(o1.contains(md5(first)) && !o1.contains(md5(second)), "Primeira conexão recebeu cookie errado")
            try require(o2.contains(md5(second)) && !o2.contains(md5(first)), "Segunda conexão recebeu cookie errado")
        }
        test("Supervisor: configuração nomeada/legível, cookie inválido ou --cookie em argv não iniciam o cliente") {
            let work = try TestSupport.workDirectory()
            defer { try? FileManager.default.removeItem(atPath: work) }
            // A config that still has a directory entry (not anonymous) is refused.
            let namedFD = open(work + "/named.conf", O_RDWR | O_CREAT | O_EXCL, 0o600)
            _ = "host = vpn.invalid\n".withCString { Darwin.write(namedFD, $0, 19) }
            var run = try TestSupport.spawn(configFD: namedFD, arguments: ["/bin/sh", "-c", "echo STARTED", "fixture"])
            close(namedFD)
            var output = try transcript(run); finish(run)
            try require(output.contains("__VPNGUI_EXIT__=125") && !output.contains("STARTED") && !output.contains("__VPNGUI_PID__"), "Configuração com nome aceita")
            // A readable (0644) anonymous config is refused.
            let loose = try ProtectedDescriptor.anonymousFile(Data("host = vpn.invalid\n".utf8), directory: work)
            fchmod(loose, 0o644)
            run = try TestSupport.spawn(configFD: loose, arguments: ["/bin/sh", "-c", "echo STARTED", "fixture"])
            close(loose)
            output = try transcript(run); finish(run)
            try require(output.contains("__VPNGUI_EXIT__=125") && !output.contains("STARTED"), "Configuração 0644 aceita")
            run = try spawn(cookie: "SVPNCOOKIE=abc\n", ["/bin/sh", "-c", "echo STARTED", "fixture"])
            output = try transcript(run); finish(run)
            try require(output.contains("__VPNGUI_EXIT__=125") && !output.contains("STARTED") && !output.contains("abc"), "Formato inválido aceito")
            run = try spawn(cookie: nil, ["/bin/sh", "--cookie=SVPNCOOKIE=abc"])
            output = try transcript(run); finish(run)
            try require(output.contains("__VPNGUI_EXIT__=125") && !output.contains("abc"), "--cookie em argv aceito")
        }

        test("openfortivpn instalado lê o stdin dedicado e para antes da rede (sem root)") {
            // 1.24.1 reads --cookie-on-stdin while parsing arguments and exits at its root check,
            // before resolving the host or opening any socket. Never run this as root.
            guard geteuid() != 0 else { throw AppFailure("Teste não deve rodar como root") }
            let binary = URL(fileURLWithPath: BinaryLocator.defaultPath).resolvingSymlinksInPath().path
            let cookie = synthetic()
            let run = try spawn(cookie: cookie, [binary, "-v"])
            defer { finish(run) }
            let output = try transcript(run)
            try require(output.contains("not spawned with root privileges"), "Cliente não chegou à verificação de root: \(output.suffix(300))")
            try require(!output.contains("Could not read the cookie"), "Cliente não leu o stdin dedicado")
            try require(!output.contains("synthetic"), "Cookie apareceu na saída do cliente")
            var filter = OutputLineFilter(captureCookie: true, secrets: [cookie])
            let shown = (filter.feed(Data(output.utf8)) + filter.finish()).compactMap { event -> String? in
                if case .line(let line) = event { return line } else { return nil }
            }
            try require(!shown.contains { $0.hasPrefix("DEBUG") }, "Linhas DEBUG chegariam aos logs")
        }

        // MARK: Connection flow (harness: no executable, no authorization, no browser)

        func harnessed(_ model: AppModel, help: String = help) -> LaunchRecorder { harness(model, help: help) }
        func feed(_ model: AppModel, _ c: Connection, _ lines: [String]) {
            let session = model.manager.session(c.id)
            for line in lines {
                model.manager.receive(.line(line), session: session, connection: c, generation: session.generation)
            }
        }
        func newModel(_ name: String) throws -> AppModel {
            AppModel(store: try JSONStore(directory: testRoot.appendingPathComponent(name)), passwords: passwords, cookies: cookies)
        }

        test("Cookie válido sintético: caminho sem navegador, sem fila nem porta 8020") {
            let model = try newModel("valid")
            let launches = harnessed(model)
            let c = profile()
            try model.save(c, password: "")
            try cookies.save(synthetic(), for: c)
            let other = profile()
            try model.save(other, password: "")
            model.connect(other) // Holds the SAML gate: the cookie path must not wait for it.
            model.connect(c)
            let session = model.manager.session(c.id)
            try require(launches.plans.count == 2 && launches.plans[1].0 == c.id && launches.plans[1].1.mode == .reuse, "Cookie não selecionado")
            try require(!launches.plans[1].1.clientArguments.contains { $0.hasPrefix("--saml-login") }, "Caminho com cookie iniciou SAML")
            try require(session.state != .waitingForSAML && session.samlPort == nil, "Caminho com cookie reservou callback")
            feed(model, c, ["INFO:   Connected to gateway.", "INFO:   Authenticated.", "INFO:   Remote gateway has allocated a VPN.", "INFO:   Tunnel is up and running."])
            try require(session.state == .connected && session.state != .authenticating, "Túnel não refletido")
            model.manager.disconnect(c.id)
            feed(model, c, ["INFO:   Logged out."])
            model.manager.end(session, exit: 0)
            try require(session.state == .disconnected && launches.plans.count == 2, "Desconectar iniciou nova tentativa")
            guard case .cookie = cookies.lookup(c) else { throw AppFailure("Desconectar descartou o candidato para o próximo Conectar") }
            model.manager.disconnect(other.id); model.manager.end(model.manager.session(other.id), exit: 0)
        }
        test("Cookie recusado: exatamente um fallback SAML após a saída, sem trava de credenciais") {
            let model = try newModel("rejected")
            let launches = harnessed(model)
            let c = profile()
            try model.save(c, password: "")
            try cookies.save(synthetic(), for: c)
            model.connect(c)
            let session = model.manager.session(c.id)
            feed(model, c, ["INFO:   Connected to gateway.", "INFO:   Authenticated.", "INFO:   Remote gateway has allocated a VPN.",
                            "ERROR:  Could not get VPN configuration (HTTP status code).", "INFO:   Closed connection to gateway.", "INFO:   Logged out."])
            try require(launches.plans.count == 1, "Fallback antes da saída do processo")
            model.manager.end(session, exit: 1)
            try require(launches.plans.count == 2 && launches.plans[1].1.mode == .capture, "Fallback SAML não iniciado uma única vez")
            try require(launches.plans[1].1.clientArguments.contains("--saml-login=8020"), "Fallback sem SAML")
            try require(!session.authenticationRejected, "Cookie recusado acionou a trava de credenciais")
            try require(try cookies.read(c.id) == nil, "Cookie recusado continuou no cache")
            // The SAML fallback is a real login: its refusal keeps the existing protection.
            feed(model, c, ["ERROR:  Could not authenticate to gateway. Please check the password, client certificate, etc."])
            model.manager.end(session, exit: 1)
            try require(launches.plans.count == 2 && session.state == .failed, "Recusa no SAML gerou outra tentativa")
            try require(session.authenticationRejected, "Recusa SAML real não acionou a proteção")
            model.connect(c)
            try require(launches.plans.count == 2 && model.error != nil, "Trava de credenciais foi removida")
        }
        test("TLS, rede, autorização e cancelamento não causam fallback nem invalidam") {
            let model = try newModel("transport")
            let launches = harnessed(model)
            let c = profile()
            try model.save(c, password: "")
            let session = model.manager.session(c.id)
            let cases: [(String, [String], Int?, Bool)] = [
                ("TLS", ["ERROR:  Gateway certificate validation failed, and the certificate digest is not in the local whitelist. If you trust it, rerun with:"], 1, false),
                ("rede", ["ERROR:  getaddrinfo: nodename nor servname provided, or not known"], 1, false),
                ("TLS na alocação", ["INFO:   Connected to gateway.", "INFO:   Authenticated.", "ERROR:  VPN allocation request failed (TLS error)."], 1, false),
                ("autorização", [], nil, false),
                ("cancelamento", ["INFO:   Connected to gateway."], 143, true)]
            for (name, lines, exit, cancel) in cases {
                try cookies.save(synthetic(), for: c)
                let before = launches.plans.count
                model.connect(c)
                try require(launches.plans.count == before + 1 && launches.plans.last!.1.mode == .reuse, "\(name): cookie não tentado")
                feed(model, c, lines)
                if cancel { model.manager.disconnect(c.id) }
                model.manager.end(session, exit: exit, error: exit == nil ? "Autorização cancelada." : nil)
                try require(launches.plans.count == before + 1, "\(name): fallback indevido")
                guard case .cookie = cookies.lookup(c) else { throw AppFailure("\(name): cookie invalidado indevidamente") }
                try require(!session.authenticationRejected && !session.state.active, "\(name): estado incorreto")
            }
        }
        test("Captura promovida somente após túnel; falha não substitui cache; múltiplos cookies descartados") {
            let model = try newModel("capture")
            let launches = harnessed(model)
            let c = profile()
            try model.save(c, password: "")
            let session = model.manager.session(c.id)
            let original = synthetic()
            try cookies.save(original, for: c)
            try cookies.delete(c.id)
            // Failed login: candidate must never reach the cache.
            model.connect(c)
            try require(launches.plans.last!.1.mode == .capture, "Login SAML sem captura")
            model.manager.receive(.cookie(synthetic()), session: session, connection: c, generation: session.generation)
            feed(model, c, ["ERROR:  Could not get VPN configuration (HTTP status code)."])
            model.manager.end(session, exit: 1)
            try require(try cookies.read(c.id) == nil, "Candidato de tentativa malsucedida foi guardado")
            // Successful login: promoted only at "Tunnel is up".
            session.authenticationRejected = false
            model.connect(c)
            let good = synthetic()
            model.manager.receive(.cookie(good), session: session, connection: c, generation: session.generation)
            model.manager.receive(.cookie(good), session: session, connection: c, generation: session.generation)
            try require(try cookies.read(c.id) == nil, "Cookie guardado antes do túnel")
            feed(model, c, ["INFO:   Tunnel is up and running."])
            guard case .cookie(let saved) = cookies.lookup(c), saved == good else { throw AppFailure("Cookie não promovido após túnel") }
            try require(session.cookieCandidate == nil && !session.logs.joined().contains("synthetic"), "Candidato ficou em memória ou nos logs")
            model.manager.disconnect(c.id); model.manager.end(session, exit: 0)
            // A failed capture attempt must not replace the existing cache either.
            try cookies.delete(c.id)
            try cookies.save(original, for: c)
            session.begin()
            session.cookieMode = .capture
            model.manager.receive(.cookie(synthetic()), session: session, connection: c, generation: session.generation)
            model.manager.end(session, exit: 1)
            guard case .cookie(let kept) = cookies.lookup(c), kept == original else { throw AppFailure("Tentativa falha substituiu o cache") }
            // Two different values in one process: ambiguous, nothing stored.
            try cookies.delete(c.id)
            model.connect(c)
            if session.cookieMode == .reuse { throw AppFailure("Cache inesperado") }
            model.manager.receive(.cookie(synthetic()), session: session, connection: c, generation: session.generation)
            model.manager.receive(.cookie(synthetic()), session: session, connection: c, generation: session.generation)
            feed(model, c, ["INFO:   Tunnel is up and running."])
            try require(try cookies.read(c.id) == nil, "Cookies conflitantes foram guardados")
            model.manager.disconnect(c.id); model.manager.end(session, exit: 0)
        }
        test("Reconexão: cookie recusado faz fallback sem reiniciar o orçamento de tentativas") {
            let model = try newModel("reconnect")
            let launches = harnessed(model)
            let c = profile()
            try model.save(c, password: "")
            let session = model.manager.session(c.id)
            model.connect(c)
            let captured = synthetic()
            model.manager.receive(.cookie(captured), session: session, connection: c, generation: session.generation)
            feed(model, c, ["INFO:   Tunnel is up and running."])
            model.manager.end(session, exit: 1) // Drop after a working tunnel.
            try require(session.state == .reconnecting && session.reconnectAttempts == 1, "Queda não agendou reconexão")
            session.reconnectTask?.perform()
            try require(launches.plans.last!.1.mode == .reuse, "Reconexão não tentou o cookie")
            feed(model, c, ["ERROR:  VPN allocation request failed (HTTP status code)."])
            model.manager.end(session, exit: 1)
            try require(launches.plans.last!.1.mode == .capture && session.reconnectAttempts == 1 && session.wasConnected,
                        "Fallback reiniciou ou consumiu o orçamento de reconexão")
            model.manager.disconnect(c.id)
            model.manager.end(session, exit: 143)
            try require(session.state == .disconnected && session.reconnectTask == nil, "Desconectar não cancelou o fallback")
            let count = launches.plans.count
            session.reconnectTask?.perform()
            try require(launches.plans.count == count, "Reconexão após Desconectar voluntário")
        }
        test("Versão incompatível: SAML normal, sem cache apresentado como funcional") {
            let model = try newModel("legacy")
            let launches = harnessed(model, help: legacyHelp)
            let c = profile()
            try model.save(c, password: "")
            try cookies.save(synthetic(), for: c)
            model.connect(c)
            let session = model.manager.session(c.id)
            try require(launches.plans.count == 1 && launches.plans[0].1.mode == .none &&
                        launches.plans[0].1.clientArguments == ["--saml-login=8020"], "Versão incompatível usou cookie ou -v")
            try require(session.logs.contains { $0.contains("não lê a sessão SAML") }, "Sem diagnóstico seguro")
            try require(!session.logs.contains { $0.contains("ocultada") }, "Diagnóstico de versão foi ocultado")
            model.manager.disconnect(c.id); model.manager.end(session, exit: 0)
        }
        test("Perfil por senha mantém o comportamento atual") {
            let model = try newModel("password")
            let launches = harnessed(model)
            var c = profile(); c.authentication = .password; c.username = "user"
            try model.save(c, password: "local-secret")
            model.connect(c)
            try require(launches.plans.count == 1 && launches.plans[0].1 == LaunchPlan(clientArguments: [], mode: .none), "Plano de senha mudou")
            let session = model.manager.session(c.id)
            feed(model, c, ["ERROR:  Could not authenticate to gateway. Please check the password, client certificate, etc."])
            model.manager.end(session, exit: 1)
            try require(session.authenticationRejected && launches.plans.count == 1, "Proteção de senha alterada")
        }
        return failures
    }
}

final class LaunchRecorder { var plans: [(UUID, LaunchPlan)] = []; var requests: [ConnectionRequest] = [] }
