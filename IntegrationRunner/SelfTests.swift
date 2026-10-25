@testable import VPNApp
import Foundation
import Darwin
import ProcessBridge
import VPNHelperCore
import VPNHelperShared

@MainActor
enum SelfTests {
    static func run() -> Int32 {
        setbuf(stdout, nil)
        var failures = 0
        func test(_ name: String, _ block: () throws -> Void) {
            do { try block(); print("PASS: \(name)") }
            catch { failures += 1; print("FAIL: \(name): \(error.localizedDescription)") }
        }
        func require(_ condition: @autoclosure () throws -> Bool, _ message: String) throws {
            if try !condition() { throw AppFailure(message) }
        }
        let testRoot = FileManager.default.temporaryDirectory.appendingPathComponent("VPNGUI-tests-\(UUID())")
        defer { try? FileManager.default.removeItem(at: testRoot) }
        let passwords = PasswordStore(service: "com.luiz.vpngui.tests.\(UUID())")
        var c = Connection(name: "Teste local", server: "vpn.invalid", port: 443, username: "test")
        defer { try? passwords.delete(c.id) }
        test("Executável automático: locais comuns, PATH absoluto e cadastro legado") {
            let candidates = BinaryLocator.candidates(environment: ["PATH": "/custom/tools:/opt/local/bin:.:relative:/custom/tools"])
            try require(candidates.contains("/custom/tools/openfortivpn") && candidates.contains("/opt/local/bin/openfortivpn"), "Busca não inclui PATH e MacPorts")
            try require(candidates.filter { $0 == "/custom/tools/openfortivpn" }.count == 1, "Diretórios repetidos")
            try require(!candidates.contains { $0.contains("/relative/") || $0 == "./openfortivpn" }, "PATH relativo aceito")
            let legacy = try JSONEncoder().encode(SavedData(connections: [c]))
            var object = try JSONSerialization.jsonObject(with: legacy) as! [String: Any]
            object["binaryPath"] = "/old/install/openfortivpn"
            let decoded = try JSONDecoder().decode(SavedData.self, from: JSONSerialization.data(withJSONObject: object))
            try require(decoded.connections == [c], "Cadastro anterior foi perdido")
        }
        test("Limpar logs afeta somente a conexão escolhida e preserva estado e cronômetro") {
            let first = Session(id: UUID()), second = Session(id: UUID())
            first.begin(); second.begin()
            first.accept("INFO: Tunnel is up and running.", connection: c) { _ in }
            let start = first.connectedAt
            first.clearLogs()
            try require(first.logs.isEmpty && !second.logs.isEmpty, "Logs compartilhados ou não limpos")
            try require(first.state == .connected && first.connectedAt == start, "Limpeza alterou a sessão")
            first.log("Nova linha após limpeza")
            try require(first.logs == ["Nova linha após limpeza"], "Novos logs não apareceram")
        }
        test("Host e porta: separar colagem sem confundir IPv6 ou aceitar porta inválida") {
            let input = HostPortInput.split(" gateway.example.invalid:4434 ")
            try require(input?.host == "gateway.example.invalid" && input?.port == 4434, "Host/porta não separados")
            let ipv6 = HostPortInput.split("[2001:db8::1]:10443")
            try require(ipv6?.host == "[2001:db8::1]" && ipv6?.port == 10443, "IPv6 com porta não separado")
            for invalid in ["2001:db8::443", "vpn.invalid", "vpn.invalid:0", "vpn.invalid:65536", "https://vpn.invalid:443", "vpn.invalid:abc"] {
                try require(HostPortInput.split(invalid) == nil, "Entrada ambígua foi separada: \(invalid)")
            }
        }
        test("Servidor Fortinet: host, host:porta e host:porta/realm num só campo, como no FortiClient") {
            func parse(_ text: String) -> (String, Int, String)? { (try? GatewayAddress.parse(text)).map { ($0.host, $0.port, $0.realm) } }
            try require(parse(" vpn.exemplo.invalid ")! == ("vpn.exemplo.invalid", 443, ""), "Host sem porta")
            try require(parse("vpn.example.invalid:10443")! == ("vpn.example.invalid", 10443, ""), "Porta custom")
            try require(parse("vpn.example.test:443/realm1")! == ("vpn.example.test", 443, "realm1"), "Realm")
            try require(parse("https://vpn.exemplo.invalid:4443/")! == ("vpn.exemplo.invalid", 4443, ""), "Prefixo https")
            try require(parse("[2001:db8::1]:10443")! == ("[2001:db8::1]", 10443, ""), "IPv6 com porta")
            try require(parse("2001:db8::1")! == ("2001:db8::1", 443, ""), "IPv6 sem porta")
            for invalid in ["", "vpn.invalid:0", "vpn.invalid:abc", "vpn.invalid:65536", "vpn.invalid:443/a b", "vpn.invalid/-x", "ftp://vpn.invalid", "vpn.invalid:443/a/b"] {
                try require(parse(invalid) == nil, "Endereço inválido aceito: \(invalid)")
            }
            try require(GatewayAddress.display(host: "vpn.exemplo.invalid", port: 443, realm: "") == "vpn.exemplo.invalid", "443 exibido")
            try require(GatewayAddress.display(host: "vpn.exemplo.invalid", port: 10443, realm: "") == "vpn.exemplo.invalid:10443", "Porta custom não exibida")
            try require(GatewayAddress.display(host: "vpn.exemplo.invalid", port: 443, realm: "r1") == "vpn.exemplo.invalid:443/r1", "Realm não exibido")
            let config = try ConfigRenderer.render(host: "vpn.invalid", port: 443, username: "u", password: nil, trustedCertificate: "", realm: "realm1")
            try require(config.contains("realm = realm1\n"), "Realm fora da configuração")
            try require((try? ConfigRenderer.render(host: "vpn.invalid", port: 443, username: "u", password: nil, trustedCertificate: "", realm: "x\nset-dns = 0")) == nil, "Realm com quebra aceito")
        }
        test("Cronômetro começa somente com túnel ativo e reinicia entre execuções") {
            let session = Session(id: UUID())
            session.begin()
            session.accept("INFO: Authenticated.", connection: c) { _ in }
            try require(session.connectedAt == nil, "Cronômetro começou antes do túnel")
            session.accept("INFO: Tunnel is up and running.", connection: c) { _ in }
            guard let start = session.connectedAt else { throw AppFailure("Cronômetro ausente") }
            try require(Session.duration(since: start, at: start.addingTimeInterval(3661)) == "01:01:01", "Duração incorreta")
            session.accept("INFO: Tunnel is up and running.", connection: c) { _ in }
            try require(session.connectedAt == start, "Linha repetida reiniciou o cronômetro")
            session.finish(exit: 1)
            try require(session.connectedAt == nil, "Cronômetro continuou após saída")
        }
        test("Reconexão: somente após túnel real, com limite, bloqueio de TLS/senha e cancelamento") {
            let manager = VPNManager()
            var retries = 0
            manager.retry = { _ in retries += 1 }
            let session = manager.session(UUID())
            session.begin()
            try require(session.retryDelay == nil, "Falha inicial dispararia repetição")
            session.accept("INFO: Tunnel is up and running.", connection: c) { _ in }
            try require(session.retryDelay == 10, "Primeira espera incorreta")
            session.reconnectAttempts = 1
            try require(session.retryDelay == 20, "Espera não cresceu")
            session.reconnectAttempts = 3
            try require(session.retryDelay == nil, "Limite ignorado")
            session.reconnectAttempts = 0
            session.authenticationRejected = true
            try require(session.retryDelay == nil, "Senha recusada repetiria automaticamente")
            session.authenticationRejected = false
            session.certificateValidationFailed = true
            try require(session.retryDelay == nil, "TLS inválido repetiria automaticamente")
            session.certificateValidationFailed = false
            manager.end(session, exit: 1)
            let pending = session.reconnectTask
            try require(session.state == .reconnecting && pending != nil, "Queda não agendou reconexão")
            manager.disconnect(session.id)
            pending?.perform()
            try require(retries == 0 && session.state == .disconnected && pending?.isCancelled == true, "Desconectar não cancelou a tentativa pendente")
        }
        test("Certificado detectado não é salvo nem aceito sem confirmação explícita") {
            let store = try JSONStore(directory: testRoot.appendingPathComponent("certificate"))
            let model = AppModel(store: store, passwords: passwords)
            var profile = c; profile.id = UUID()
            defer { try? passwords.delete(profile.id) }
            try model.save(profile, password: "certificate-test-secret")
            let session = model.manager.session(profile.id)
            let digest = String(repeating: "a", count: 64)
            session.begin()
            session.accept("ERROR: --trusted-cert \(digest)", connection: profile) { _ in }
            try require(session.suggestedCertificate == nil, "Digest fora de falha TLS foi aceito")
            session.accept("ERROR: Gateway certificate validation failed", connection: profile) { _ in }
            session.accept("ERROR:     --trusted-cert \(digest)", connection: profile) { _ in }
            session.finish(exit: 1)
            try require(session.suggestedCertificate == digest, "Digest não detectado")
            try require(try store.load().connections[0].trustedCertificate.isEmpty, "Digest salvo automaticamente")
            try require((try? model.trustCertificate(profile, digest: String(repeating: "b", count: 64))) == nil, "Digest diferente foi aprovado")
            try require(try passwords.read(profile.id) == "certificate-test-secret", "Detecção alterou Keychain")
            session.accept("ERROR: trusted-cert = \(String(repeating: "b", count: 64))", connection: profile) { _ in }
            try require(session.suggestedCertificate == nil, "Digests conflitantes foram oferecidos")
            try require(OutputRules.certificateDigest("ERROR: --trusted-cert \(digest)extra") == nil, "Digest malformado aceito")
        }
        test("Validação de cadastro e proteção contra injeção em configuração") {
            _ = try c.validated()
            var invalid = c
            invalid.server = "vpn.invalid\nset-dns = 0"
            do { _ = try invalid.validated(); throw AppFailure("Servidor inválido foi aceito.") }
            catch is AppFailure { try require((try? invalid.validated()) == nil, "Injeção aceita") }
            invalid = c; invalid.port = 0
            try require((try? invalid.validated()) == nil, "Porta zero aceita")
            invalid = c; invalid.trustedCertificate = "abcd"
            try require((try? invalid.validated()) == nil, "Digest inválido aceito")
            try require((try? Connection.checkConfigValue("secret\npppd-call = evil", label: "Senha")) == nil,
                        "Quebra de linha aceita")
        }
        test("JSON: criar, editar, excluir e preservar arquivo corrompido") {
            let store = try JSONStore(directory: testRoot)
            var data = SavedData(connections: [c])
            try store.save(data)
            try require(try store.load().connections == [c], "Cadastro não persistido")
            data.connections[0].name = "Editada"
            try store.save(data)
            try require(try store.load().connections[0].name == "Editada", "Edição não persistida")
            data.connections = []; try store.save(data)
            try require(try store.load().connections.isEmpty, "Exclusão não persistida")
            try Data("invalid-json".utf8).write(to: store.file)
            try require((try? store.load()) == nil, "Corrupção não detectada")
            try require(try String(contentsOf: store.file) == "invalid-json", "Arquivo corrompido sobrescrito")
            try store.save(SavedData())
        }
        test("Keychain real: criar, ler, atualizar e excluir senha isolada") {
            try passwords.write("secret-one", id: c.id)
            try require(try passwords.read(c.id) == "secret-one", "Leitura diferente")
            try passwords.write("secret-two", id: c.id)
            try require(try passwords.read(c.id) == "secret-two", "Atualização diferente")
            try passwords.delete(c.id)
            try require(try passwords.read(c.id) == nil, "Senha ainda existe")
        }
        test("Cadastro integrado: JSON e Keychain consistentes em criar, editar e excluir") {
            let store = try JSONStore(directory: testRoot.appendingPathComponent("model"))
            let model = AppModel(store: store, passwords: passwords)
            try model.save(c, password: "first-secret")
            try require(model.data.connections == [c], "Cadastro ausente na interface")
            try require(try passwords.read(c.id) == "first-secret", "Senha ausente")
            let persisted = try String(contentsOf: store.file)
            try require(!persisted.contains("first-secret") && !persisted.contains("password ="), "Senha foi salva no JSON")
            var edited = c; edited.name = "Alterada"
            try model.save(edited, password: "second-secret")
            let reopened = AppModel(store: store, passwords: passwords)
            try require(reopened.data.connections == [edited], "Reabertura perdeu edição")
            try require(try passwords.read(c.id) == "second-secret", "Senha não atualizada")
            reopened.manager.session(c.id).begin()
            try require((try? reopened.delete(edited)) == nil, "Exclusão ativa permitida")
            reopened.manager.session(c.id).finish(exit: 0)
            try reopened.delete(edited)
            try require(try store.load().connections.isEmpty, "JSON não excluído")
            try require(try passwords.read(c.id) == nil, "Senha não excluída")
        }
        test("Configuração protegida: descritor anônimo 0600, conteúdo exato e nenhum arquivo restante") {
            let work = try TestSupport.workDirectory()
            defer { rmdir(work) }
            let text = try ConfigRenderer.render(host: c.server, port: c.port, username: c.username,
                                                 password: "s3cret#=value", trustedCertificate: "")
            let fd = try ProtectedDescriptor.anonymousFile(Data(text.utf8), directory: work)
            defer { close(fd) }
            var info = stat()
            try require(fstat(fd, &info) == 0 && info.st_mode & 0o777 == 0o600 && info.st_nlink == 0, "Descritor não é anônimo 0600")
            try require(try FileManager.default.contentsOfDirectory(atPath: work).isEmpty, "Arquivo com senha ficou no diretório")
            var buffer = [UInt8](repeating: 0, count: 512)
            let count = Darwin.read(fd, &buffer, buffer.count)
            try require(String(decoding: buffer.prefix(max(0, count)), as: UTF8.self).contains("password = s3cret#=value\n"), "Senha alterada")
            try require(fcntl(fd, F_GETFD) & FD_CLOEXEC != 0, "Descritor herdável por qualquer exec")
        }
        test("Logs: ocultar senha, cookie, token, bearer e URL com sessão") {
            for line in ["password = hidden", "SVPNCOOKIE=hidden", "token: hidden", "Authorization: Bearer hidden", "SAMLResponse=hidden"] {
                try require(!OutputRules.safe(line, secret: nil).contains("hidden"), "Credencial vazou")
            }
            try require(!OutputRules.safe("value: my-secret", secret: "my-secret").contains("my-secret"), "Senha conhecida vazou")
            try require(!OutputRules.safe("Authenticate at 'https://vpn.invalid/remote/saml/start?x=sessionvalue'", secret: nil).contains("sessionvalue"), "URL vazou")
        }
        test("Logs mantêm diagnóstico de autenticação sem revelar credenciais") {
            let original = "ERROR:   Could not authenticate to gateway. Please check the password, client certificate, etc."
            let safe = OutputRules.safe(original, secret: "test-secret")
            try require(safe.contains("Falha na autenticação"), "Erro de autenticação foi ocultado")
            try require(!safe.contains("ocultada"), "Mensagem genérica de senha descartou o diagnóstico")
            let injected = OutputRules.safe(original + " password=test-secret; token=hidden", secret: "test-secret")
            try require(!injected.contains("test-secret") && !injected.contains("hidden"), "Diagnóstico preservou conteúdo secreto")
            let saml = OutputRules.safe("ERROR: Failed to retrieve SAML cookie hidden", secret: nil)
            try require(saml.contains("Falha ao concluir") && !saml.contains("hidden"), "Erro SAML ocultado ou exposto")
        }
        test("SAML: abrir somente URL HTTPS do gateway esperado") {
            let good = "INFO: Authenticate at 'https://vpn.invalid/remote/saml/start?redirect=1'"
            try require(OutputRules.authenticationURL(good, connection: c) != nil, "URL SAML válida rejeitada")
            for bad in ["https://other.invalid/remote/saml/start", "http://vpn.invalid/remote/saml/start", "https://vpn.invalid:444/remote/saml/start", "https://vpn.invalid/other"] {
                try require(OutputRules.authenticationURL("Authenticate at '\(bad)'", connection: c) == nil, "URL fora do gateway aceita")
            }
        }
        test("Estados independentes; gateway autenticado não significa túnel conectado") {
            let first = Session(id: c.id)
            let second = Session(id: UUID())
            first.begin(); second.begin()
            first.state = .connecting; second.state = .connecting
            first.accept("INFO: Connected to gateway.", connection: c) { _ in }
            try require(first.state == .connecting, "Estado conectado anunciado cedo")
            first.accept("INFO: Tunnel is up and running.", connection: c) { _ in }
            try require(first.state == .connected && second.state == .connecting, "Estados compartilhados")
            first.wantsDisconnect = true; first.state = .disconnecting
            first.accept("INFO: Tunnel is up and running.", connection: c) { _ in }
            try require(first.state == .disconnecting, "Estado de desconexão revertido")
            first.finish(exit: 0)
            second.finish(exit: 1)
            try require(first.state == .disconnected && second.state == .failed, "Saída não refletida")
            c.authentication = .saml
            let saml = Session(id: UUID())
            saml.begin()
            var opens = 0
            for _ in 0..<2 { saml.accept("Authenticate at 'https://vpn.invalid/remote/saml/start?a=b'", connection: c) { _ in opens += 1 } }
            try require(opens == 1 && saml.state == .authenticating, "SAML abriu repetidamente")
            saml.finish(exit: 1)
            try require(saml.state == .failed && saml.token == nil, "Falha deixou recursos")
        }
        test("Recusa de autenticação exige revisar o cadastro antes de nova tentativa") {
            let store = try JSONStore(directory: testRoot.appendingPathComponent("auth-rejection"))
            let model = AppModel(store: store, passwords: passwords)
            var profile = c
            profile.id = UUID()
            profile.authentication = .password
            defer { try? passwords.delete(profile.id) }
            try model.save(profile, password: "dummy-account-secret")
            let session = model.manager.session(profile.id)
            session.begin()
            session.accept("ERROR: Could not authenticate to gateway. Please check the password, client certificate, etc.", connection: profile) { _ in }
            session.finish(exit: 1)
            try require(session.authenticationRejected, "Recusa não foi registrada")
            model.connect(profile) // Must fail locally, before any process/network/authorization.
            try require(model.error != nil && !session.state.active && session.pid == nil, "App permitiu nova tentativa após recusa")
            try model.save(profile, password: "confirmed-new-dummy-secret")
            try require(!session.authenticationRejected, "Revisão explícita não liberou o cadastro")
        }
        test("SAML: reutilizar callback após fechamento TCP sem aceitar listener concorrente") {
            var port: Int32 = 0
            var listener = vpn_reserve_port(&port)
            guard listener >= 0 else { throw AppFailure("Listener local indisponível") }
            var client: Int32 = -1, accepted: Int32 = -1
            defer {
                for fd in [listener, client, accepted] where fd >= 0 { close(fd) }
            }
            client = socket(AF_INET, SOCK_STREAM, 0)
            guard client >= 0 else { throw AppFailure("Socket local indisponível") }
            var address = sockaddr_in()
            address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            address.sin_family = sa_family_t(AF_INET)
            address.sin_addr.s_addr = inet_addr("127.0.0.1")
            address.sin_port = UInt16(port).bigEndian
            let connected = withUnsafePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.connect(client, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
            try require(connected == 0, "Conexão exclusivamente loopback falhou")
            accepted = accept(listener, nil, nil)
            try require(accepted >= 0, "Callback local não aceito")
            // The callback server actively closes first, leaving its local port in TIME_WAIT.
            shutdown(accepted, SHUT_WR)
            var descriptor = pollfd(fd: client, events: Int16(POLLIN | POLLHUP), revents: 0)
            try require(poll(&descriptor, 1, 3000) > 0, "EOF local não recebido")
            var byte: UInt8 = 0
            try require(Darwin.read(client, &byte, 1) == 0, "Callback não fechou a escrita")
            close(client); client = -1
            descriptor = pollfd(fd: accepted, events: Int16(POLLIN | POLLHUP), revents: 0)
            try require(poll(&descriptor, 1, 3000) > 0, "Cliente local não encerrou")
            try require(Darwin.read(accepted, &byte, 1) == 0, "Cliente não confirmou EOF")
            close(accepted); accepted = -1
            close(listener); listener = -1
            let legacy = socket(AF_INET, SOCK_STREAM, 0)
            guard legacy >= 0 else { throw AppFailure("Socket de comparação indisponível") }
            let legacyBind = withUnsafePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    bind(legacy, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
            let legacyError = errno
            close(legacy)
            try require(legacyBind < 0 && legacyError == EADDRINUSE, "Fixture não reproduziu o bloqueio antigo por TIME_WAIT")
            listener = vpn_reserve_port(&port)
            try require(listener >= 0, "Porta em TIME_WAIT continua sendo recusada")
            var same = port
            let conflict = vpn_reserve_port(&same)
            if conflict >= 0 { close(conflict) }
            try require(conflict < 0, "Listener concorrente foi aceito")
        }
        test("SAML: reservar duas portas locais diferentes, sem conectar à rede") {
            var p1: Int32 = 0, p2: Int32 = 0
            var fd1 = vpn_reserve_port(&p1)
            defer { if fd1 >= 0 { close(fd1) } }
            let fd2 = vpn_reserve_port(&p2)
            defer { if fd2 >= 0 { close(fd2) } }
            try require(fd1 >= 0 && fd2 >= 0 && p1 != p2 && p1 > 0, "Não foi possível reservar sockets locais (errno \(errno): \(String(cString: strerror(errno)))); portas \(p1), \(p2)")
            var same = p1
            let conflict = vpn_reserve_port(&same)
            if conflict >= 0 { close(conflict) }
            try require(conflict < 0, "Porta já reservada foi aceita por outra sessão")
            close(fd1)
            fd1 = -1
            let reuse = vpn_reserve_port(&same)
            if reuse >= 0 { close(reuse) }
            try require(reuse >= 0 && same == p1, "Porta exata não pôde ser reutilizada após a liberação")
        }
        test("SAML: fila libera o callback para o próximo login sem afetar túneis anteriores") {
            var gate = SAMLLoginGate()
            let first = UUID(), second = UUID(), cancelled = UUID(), third = UUID()
            try require(gate.acquire(first), "Primeiro login não iniciou")
            try require(!gate.acquire(second) && !gate.acquire(cancelled) && !gate.acquire(third), "Logins disputaram o callback")
            try require(!gate.acquire(second) && gate.waiting.count == 3, "Login duplicado na fila")
            try require(gate.release(cancelled) == nil && gate.owner == first, "Cancelar fila afetou o login atual")
            try require(gate.release(first) == second, "Próximo login não iniciou após callback")
            try require(gate.release(first) == nil && gate.owner == second, "Saída do túnel anterior interrompeu outro login")
            try require(gate.release(second) == third, "Fila perdeu ordem")
            try require(gate.release(third) == nil && gate.owner == nil && gate.waiting.isEmpty, "Fila deixou bloqueio")
        }
        let fixture = ["/bin/sh", "-c", "trap 'exit 0' TERM; while :; do /bin/sleep 1; done", "fixture"]
        test("Supervisor real: canal exclusivo, duas sessões e desconexão individual") {
            let first = try TestSupport.spawn(configText: "password = local-only-secret\n", arguments: fixture)
            defer { TestSupport.finish(first) }
            let second = try TestSupport.spawn(arguments: fixture)
            defer { TestSupport.finish(second) }
            let p1 = try TestSupport.transcript(first, until: "__VPNGUI_PID__="), p2 = try TestSupport.transcript(second, until: "__VPNGUI_PID__=")
            try require(p1 != p2, "Processos não independentes")
            try TestSupport.stop(first)
            let output = try TestSupport.transcript(first)
            try require(output.contains("__VPNGUI_EXIT__="), "Saída sem confirmação")
            var status: Int32 = 0
            try require(waitpid(first.pid, &status, 0) == first.pid, "Supervisor não encerrou")
            try require(waitpid(second.pid, &status, WNOHANG) == 0, "Desconexão afetou outra sessão")
            shutdown(second.fd, SHUT_WR) // EOF: the helper or its client went away.
            let secondOutput = try TestSupport.transcript(second)
            try require(secondOutput.contains("__VPNGUI_EXIT__="), "EOF não limpou o processo")
        }
        test("Supervisor mantém sessão ociosa por vários ciclos de espera, sem encerrar a VPN") {
            let run = try TestSupport.spawn(arguments: fixture)
            defer { TestSupport.finish(run) }
            _ = try TestSupport.transcript(run, until: "__VPNGUI_PID__=")
            var descriptor = pollfd(fd: run.fd, events: Int16(POLLIN | POLLHUP), revents: 0)
            // The old implementation killed the child after the first one-second timeout.
            try require(poll(&descriptor, 1, 3300) == 0, "Supervisor encerrou ou emitiu saída durante uma sessão ociosa")
            var status: Int32 = 0
            try require(waitpid(run.pid, &status, WNOHANG) == 0, "Sessão terminou sem comando STOP")
            try TestSupport.stop(run)
            try require(try TestSupport.transcript(run).contains("__VPNGUI_EXIT__="), "STOP não encerrou a sessão ociosa")
        }
        test("Supervisor confirma saída espontânea sem pedido de desconexão") {
            let run = try TestSupport.spawn(arguments: ["/usr/bin/true"])
            defer { TestSupport.finish(run) }
            let output = try TestSupport.transcript(run, until: "__VPNGUI_EXIT__=0")
            try require(output.contains("__VPNGUI_EXIT__=0"), "Supervisor não confirmou saída espontânea: \(output)")
        }
        test("openfortivpn instalado: Mach-O nativo e opções reais de --help (sem root)") {
            let image = try MachOImage(file: try Data(contentsOf: URL(fileURLWithPath: BinaryLocator.defaultPath).resolvingSymlinksInPath()))
            try require(image.fileType == 2 && !image.dependencies.isEmpty, "Executável não é Mach-O executável")
            let process = Process()
            process.executableURL = URL(fileURLWithPath: BinaryLocator.defaultPath)
            process.arguments = ["--help"]
            let pipe = Pipe()
            process.standardOutput = pipe; process.standardError = pipe
            try process.run()
            let help = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            process.waitUntilExit()
            try require(RuntimeCapabilities.looksLikeOpenFortiVPN(help) && RuntimeCapabilities(help: help).samlPort, "Versão não suporta porta SAML")
            try require((try? MachOImage(file: Data("#!/bin/sh\n".utf8))) == nil, "Script aceito como Mach-O")
        }
        MenuBarTests.run(test)
        failures += SAMLCookieTests.run()
        failures += HelperTests.run()
        failures += OpenVPNTests.run()
        failures += WireGuardTests.run()
        failures += ClientCertificateTests.run()
        failures += UIPreviewTests.run()
        failures += SettingsTests.run() // After UIPreviewTests, which recreates ui-review/.
        print("\(failures == 0 ? "OK" : "FAIL"): \(failures) falha(s). Nenhuma VPN foi acessada; nenhum privilégio foi solicitado; nenhum serviço foi registrado.")
        return failures == 0 ? 0 : 1
    }
}
