@testable import VPNApp
import Foundation
import AppKit
import SwiftUI
import ServiceManagement
import VPNHelperShared
import Sparkle

/// Canned update transport: records requests and answers synchronously, or never.
final class FakeUpdateTransport: UpdateTransport {
    var reply: Result<(Int, Data), Error> = .success((200, Data("[]".utf8)))
    /// Keep the completion instead of answering (a server that never responds).
    var hold = false
    private(set) var requests: [URLRequest] = []
    private(set) var held: [(Result<(Int, Data), Error>) -> Void] = []
    func fetch(_ request: URLRequest, limit: Int, completion: @escaping (Result<(Int, Data), Error>) -> Void) {
        requests.append(request)
        if hold { held.append(completion) } else { completion(reply) }
    }
    func releaseHeld() {
        let pending = held
        held = []
        for completion in pending { completion(reply) }
    }
}

/// Serves the update request in-process (the session has no other protocol): no network.
final class StubUpdateProtocol: URLProtocol {
    private static let lock = NSLock()
    private static var _status = 200, _chunks: [Data] = [], _contentLength: Int?, _seen: [URLRequest] = []
    static func configure(status: Int, chunks: [Data], contentLength: Int? = nil) {
        lock.withLock { _status = status; _chunks = chunks; _contentLength = contentLength; _seen = [] }
    }
    static var seen: [URLRequest] { lock.withLock { _seen } }
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        let (status, chunks, length) = Self.lock.withLock { () -> (Int, [Data], Int?) in
            Self._seen.append(request)
            return (Self._status, Self._chunks, Self._contentLength)
        }
        var headers = ["Content-Type": "application/json"]
        if let length { headers["Content-Length"] = String(length) }
        let response = HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: "HTTP/1.1", headerFields: headers)!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        for chunk in chunks { client?.urlProtocol(self, didLoad: chunk) }
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}

@MainActor
final class FakeLoginItem: LoginItemService {
    var status: SMAppService.Status = .notRegistered
    var afterRegister: SMAppService.Status = .enabled
    var error: Error?
    var events: [String] = []
    func register() throws { events.append("register"); if let error { throw error }; status = afterRegister }
    func unregister() throws { events.append("unregister"); if let error { throw error }; status = .notRegistered }
    func openSystemSettings() { events.append("settings") }
}

/// SPEC 08 local checks: preferences, Dock rule, update versions, selection, scheduling,
/// transport limits and the Configurações window. No network, no real preferences,
/// no login item or service registration.
@MainActor
enum SettingsTests {
    static func release(_ tag: String, prerelease: Bool = false, draft: Bool = false,
                        url: String? = nil, body: String = "Notas") -> [String: Any] {
        ["tag_name": tag, "html_url": url ?? "https://github.com/luizmz94/tunnelmac/releases/tag/\(tag)",
         "draft": draft, "prerelease": prerelease, "body": body, "published_at": "2026-10-23T12:00:00Z"]
    }
    static func json(_ releases: [[String: Any]]) -> Data { try! JSONSerialization.data(withJSONObject: releases) }

    static let fixture: [[String: Any]] = [
        release("v0.3.1", draft: true),
        release("v0.3.0"),
        release("v0.3.1-rc.1", prerelease: true, body: "## Novidades\n\n- **Configurações** novas\n- Veja [o guia](https://example.invalid)\n<script>alert(1)</script>"),
        release("v0.3.0-rc.5", prerelease: true),
        release("v0.4.0", url: "https://github.com/someone-else/tunnelmac/releases/tag/v0.4.0"),
        release("v0.4.1", url: "https://github.com/luizmz94/tunnelmac/releases/../../evil/x"),
        release("v0.4.2", url: "http://github.com/luizmz94/tunnelmac/releases/tag/v0.4.2"),
        release("v0.9", prerelease: false),
        release("0.9.0"),
        release("v0.9.0-beta.1", prerelease: true),
        ["tag_name": 42, "unexpected": true],
    ]

    static func run() -> Int {
        var failures = 0
        func test(_ name: String, _ block: () throws -> Void) {
            do { try block(); print("PASS: Configurações: \(name)") }
            catch { failures += 1; print("FAIL: Configurações: \(name): \(error.localizedDescription)") }
        }
        let require = TestSupport.require
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("VPNGUI-settings-tests-\(UUID())")
        defer { try? FileManager.default.removeItem(at: root) }
        let passwords = PasswordStore(service: "com.luiz.vpngui.tests.settings-password.\(UUID())")
        let cookies = SAMLCookieStore(service: "com.luiz.vpngui.tests.settings-cookie.\(UUID())")
        var created: [UUID] = []
        defer { for id in created { try? passwords.delete(id); try? cookies.delete(id) } }
        let rc4 = ReleaseVersion("0.3.0-rc.4")!

        test("DNS da internet: não alterar por padrão, presets, personalizado salvo e removido, e opção de não alterar") {
            let preferences = AppPreferences.disposable()
            try require(preferences.internetDNSServers == nil, "Padrão altera DNS sem escolha")
            try require(preferences.internetDNSOptions.map(\.label) == ["1.1.1.1 - Cloudflare", "8.8.8.8 - Google", "94.140.14.14 - AdGuard (bloqueia anúncios)"], "Lista inesperada")
            preferences.internetDNSSelection = "google"
            try require(preferences.internetDNSServers == ["8.8.8.8", "8.8.4.4"], "Google não aplicado")
            let mine = try InternetDNSOption.custom(name: "Meu DNS", servers: "192.0.2.53, 2001:db8::53")
            preferences.addCustomDNS(mine)
            try require(preferences.internetDNSServers == ["192.0.2.53", "2001:db8::53"], "Personalizado não selecionado")
            let reopened = AppPreferences(defaults: preferences.defaults)
            try require(reopened.internetDNSServers == ["192.0.2.53", "2001:db8::53"] && reopened.customInternetDNS.count == 1, "Personalizado não persistiu")
            preferences.removeCustomDNS(mine.id)
            try require(preferences.internetDNSServers == nil, "Remover não voltou a não alterar")
            preferences.internetDNSSelection = "sumiu"
            try require(preferences.internetDNSServers == nil, "Seleção inexistente ainda altera DNS")
            preferences.internetDNSSelection = InternetDNSOption.offID
            try require(preferences.internetDNSServers == nil, "Não alterar ainda envia DNS")
            for (name, servers) in [("", "1.1.1.1"), ("X", "dns.invalid"), ("X", ""), (String(repeating: "a", count: 41), "1.1.1.1")] {
                try require((try? InternetDNSOption.custom(name: name, servers: servers)) == nil, "Personalizado inválido aceito: \(name) \(servers)")
            }
        }
        test("ReleaseVersion: ordem com rc e parsing estrito das tags") {
            let ordered = ["0.3.0-rc.3", "0.3.0-rc.4", "0.3.0", "0.3.1-rc.1", "0.3.1", "0.10.0", "1.0.0-rc.1"].map { ReleaseVersion($0)! }
            for (a, b) in zip(ordered, ordered.dropFirst()) { try require(a < b && !(b < a), "\(a) deveria ser menor que \(b)") }
            try require(ReleaseVersion("0.3.0-rc.10")! > ReleaseVersion("0.3.0-rc.9")!, "rc numérico")
            try require(ReleaseVersion(tag: "v0.3.0-rc.4") == rc4 && rc4.description == "0.3.0-rc.4" && rc4.isPrerelease, "Tag rc válida")
            try require(ReleaseVersion(tag: "v1.2.3")?.description == "1.2.3", "Tag estável válida")
            for invalid in ["v0.3", "0.3.0", "v0.3.0-beta.1", "v0.3.0-rc.", "v0.3.0-rc", " v0.3.0", "v0.3.0 ", "v 0.3.0", "v0.3.0-rc.1 ",
                            "v0.3.0-rc.1.2", "v0..3", "v-1.0.0", "v0.3.0-RC.1", "v0.3.0+build", "v٣.0.0", "v0.3.0\n", "", "v"] {
                try require(ReleaseVersion(tag: invalid) == nil, "Tag inválida aceita: \(invalid.debugDescription)")
            }
            try require(ReleaseVersion.current.description == HelperConstants.releaseVersion, "Versão atual não interpretável")
        }

        test("Candidata: drafts, canal, repositório, maior versão, igual/menor e pulada") {
            let releases = try UpdateFeed.decode(json(fixture))
            try require(releases.count == fixture.count - 1, "Entrada malformada derrubou a lista inteira")
            let withRC = UpdateFeed.select(releases, current: rc4, includePrereleases: true, skipped: nil)
            try require(withRC?.version == "0.3.1-rc.1" && withRC?.prerelease == true, "Com rc: \(String(describing: withRC?.version))")
            try require(withRC?.notes.contains("<") == false && withRC?.notes.contains("**") == false
                        && withRC?.notes.contains("• Configurações novas") == true && withRC?.notes.contains("o guia") == true
                        && withRC?.notes.contains("example.invalid") == false && withRC?.notes.contains("alert") == false, "Notas não viraram texto simples: \(withRC?.notes ?? "")")
            let stable = UpdateFeed.select(releases, current: rc4, includePrereleases: false, skipped: nil)
            try require(stable?.version == "0.3.0" && stable?.prerelease == false, "Sem rc: \(String(describing: stable?.version))")
            try require(UpdateFeed.select(releases, current: ReleaseVersion("0.3.1-rc.1")!, includePrereleases: true, skipped: nil) == nil,
                        "Ofereceu versão igual")
            try require(UpdateFeed.select(releases, current: ReleaseVersion("0.3.1")!, includePrereleases: true, skipped: nil) == nil,
                        "Ofereceu versão menor ou draft")
            try require(UpdateFeed.select(releases, current: rc4, includePrereleases: true, skipped: "0.3.1-rc.1") == nil,
                        "Versão pulada (ou menor que ela) oferecida")
            let newer = try UpdateFeed.decode(json(fixture + [release("v0.3.1")]))
            try require(UpdateFeed.select(newer, current: rc4, includePrereleases: true, skipped: "0.3.1-rc.1")?.version == "0.3.1",
                        "Versão maior que a pulada não voltou")
            // A candidate tag marked as stable still counts as a test version.
            let mislabeled = try UpdateFeed.decode(json([release("v0.3.0-rc.9")]))
            try require(UpdateFeed.select(mislabeled, current: rc4, includePrereleases: false, skipped: nil) == nil, "rc sem canal de teste")
            for url in ["https://github.com/luizmz94/tunnelmac/releases/tag/v1.0.0"] {
                try require(UpdateFeed.isTrustedPage(url), "URL válida recusada")
            }
            for url in ["https://github.com/luizmz94/tunnelmac/issues/1", "https://github.com.evil.invalid/luizmz94/tunnelmac/releases/x",
                        "https://github.com/luizmz94/tunnelmac/releases/../../x", "javascript:alert(1)",
                        "https://github.com/luizmz94/tunnelmac/releases/ x"] {
                try require(!UpdateFeed.isTrustedPage(url), "URL fora do repositório aceita: \(url)")
            }
            let long = UpdateFeed.plainText((1...40).map { "- item \($0)" }.joined(separator: "\n"))
            try require(long.split(separator: "\n").count <= 12 && long.hasSuffix("…"), "Notas não foram limitadas")
        }

        test("Requisição: endpoint, cabeçalhos exatos, sem cookies nem cache") {
            let request = UpdateFeed.request(version: "0.3.0-rc.4")
            try require(request.url?.absoluteString == "https://api.github.com/repos/luizmz94/tunnelmac/releases?per_page=20", "Endpoint")
            try require(request.httpMethod == "GET" && !request.httpShouldHandleCookies && request.timeoutInterval == 15
                        && request.cachePolicy == .reloadIgnoringLocalAndRemoteCacheData, "Política da requisição")
            try require(request.allHTTPHeaderFields == ["Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
                                                        "User-Agent": "TunnelMac/0.3.0-rc.4"], "Cabeçalhos: \(request.allHTTPHeaderFields ?? [:])")
        }

        test("Agendamento: abertura, intervalo de 4 h no Conectar, falhas, automático desligado, manual e sem paralelo") {
            var clock = Date(timeIntervalSince1970: 1_800_000_000)
            let preferences = AppPreferences.disposable(currentVersion: "0.3.0-rc.4")
            let transport = FakeUpdateTransport()
            transport.reply = .success((200, json(fixture)))
            let checker = UpdateChecker(preferences: preferences, transport: transport, current: rc4, now: { clock })
            checker.checkOnLaunch()
            try require(transport.requests.count == 1 && checker.offer?.version == "0.3.1-rc.1" && checker.showsCard, "Abertura não verificou")
            try require(preferences.lastUpdateAttempt == clock && preferences.lastUpdateSuccess == clock, "Datas não guardadas")
            checker.checkIfDue()
            clock += 4 * 3600 - 60
            checker.checkIfDue()
            try require(transport.requests.count == 1, "Conectar dentro de 4 h verificou")
            clock += 61
            checker.checkIfDue()
            try require(transport.requests.count == 2, "Conectar depois de 4 h não verificou")
            transport.reply = .success((429, Data()))
            clock += 4 * 3600
            checker.checkIfDue()
            try require(transport.requests.count == 3 && checker.outcome == .failed && checker.offer?.version == "0.3.1-rc.1",
                        "Falha não virou estado de erro preservando a oferta")
            clock += 600
            checker.checkIfDue()
            try require(transport.requests.count == 3, "Falha não contou para o intervalo")
            try require(preferences.lastUpdateAttempt == clock - 600 && preferences.lastUpdateSuccess != preferences.lastUpdateAttempt,
                        "Última tentativa e último sucesso confundidos")
            preferences.checkForUpdates = false
            clock += 5 * 3600
            checker.checkOnLaunch(); checker.checkIfDue()
            try require(transport.requests.count == 3, "Automático desligado verificou sozinho")
            transport.reply = .success((200, json(fixture)))
            checker.checkNow()
            try require(transport.requests.count == 4 && checker.outcome == .available, "Manual não verificou")
            checker.checkNow()
            try require(transport.requests.count == 5, "Manual respeitou o intervalo")
            preferences.checkForUpdates = true
            transport.hold = true
            clock += 5 * 3600
            checker.checkNow(); checker.checkNow(); checker.checkIfDue(); checker.checkOnLaunch()
            try require(transport.requests.count == 6 && checker.checking, "Duas verificações em paralelo")
            transport.hold = false
            transport.releaseHeld()
            try require(!checker.checking, "Verificação não terminou")
            // Timer: hourly ticks only act when the interval passed.
            checker.startTimer(every: 0.05)
            _ = TestSupport.spin(0.3) { false }
            try require(transport.requests.count == 6, "Temporizador ignorou o intervalo")
            clock += 4 * 3600
            try require(TestSupport.spin(2) { transport.requests.count == 7 }, "Temporizador não verificou após o intervalo")
            checker.stopTimer()
        }

        test("Depois, pular, canal e versão alcançada") {
            var clock = Date(timeIntervalSince1970: 1_800_000_000)
            let preferences = AppPreferences.disposable(currentVersion: "0.3.0-rc.4")
            let transport = FakeUpdateTransport()
            transport.reply = .success((200, json(fixture)))
            let checker = UpdateChecker(preferences: preferences, transport: transport, current: rc4, now: { clock })
            checker.checkNow()
            checker.postpone()
            try require(checker.pending && !checker.showsCard, "Depois não escondeu o cartão (ou apagou o ponto)")
            clock += 5 * 3600
            checker.checkIfDue()
            try require(!checker.showsCard, "A mesma versão reapareceu antes da próxima abertura")
            transport.reply = .success((200, json(fixture + [release("v0.3.1")])))
            checker.checkNow()
            try require(checker.showsCard && checker.offer?.version == "0.3.1", "Versão maior não reapareceu")
            // A relaunch keeps the pending offer without a request, and shows the card again.
            let relaunched = UpdateChecker(preferences: preferences, transport: FakeUpdateTransport(), current: rc4, now: { clock })
            try require(relaunched.offer?.version == "0.3.1" && relaunched.showsCard, "Oferta pendente perdida ao reabrir")
            let upgraded = UpdateChecker(preferences: preferences, transport: FakeUpdateTransport(), current: ReleaseVersion("0.3.1")!, now: { clock })
            try require(!upgraded.pending && preferences.cachedOffer == nil, "Estado pendente não sumiu após atualizar")
            transport.reply = .success((200, json(fixture)))
            checker.checkNow()
            checker.skipOffer()
            try require(!checker.pending && preferences.skippedVersion == "0.3.1-rc.1", "Pular não registrou a versão")
            checker.checkNow()
            try require(!checker.pending && checker.outcome == .upToDate, "Versão pulada oferecida de novo")
            preferences.skippedVersion = nil
            checker.checkNow()
            try require(checker.offer?.version == "0.3.1-rc.1", "Oferta rc não voltou")
            preferences.includePrereleases = false
            transport.hold = true
            checker.channelChanged()
            try require(!checker.pending && transport.held.isEmpty, "Desligar o canal de teste manteve a oferta rc")
            transport.hold = false
            checker.checkNow()
            try require(checker.offer?.version == "0.3.0", "Canal estável não ofereceu a estável")
        }

        test("Atualização pelo app: feed da versão oferecida, aviso só na abertura e versões exibidas") {
            let arch = AppUpdater.architecture
            try require(["arm64", "x86_64"].contains(arch), "Arquitetura: \(arch)")
            try require(AppUpdater.feedURL(for: "0.5.0-rc.6")?.absoluteString
                        == "https://github.com/luizmz94/tunnelmac/releases/download/v0.5.0-rc.6/appcast-\(arch).xml", "Feed da rc")
            try require(AppUpdater.feedURL(for: "1.0.0")?.absoluteString
                        == "https://github.com/luizmz94/tunnelmac/releases/download/v1.0.0/appcast-\(arch).xml", "Feed da estável")
            for bad in ["", "v0.5.0", "0.5", "0.5.0/../x", "0.5.0-beta.1", "0.5.0 "] {
                try require(AppUpdater.feedURL(for: bad) == nil, "Feed aceito para \(bad.debugDescription)")
            }
            let preferences = AppPreferences.disposable(currentVersion: "0.3.0-rc.4")
            let transport = FakeUpdateTransport()
            transport.reply = .success((200, json(fixture)))
            let checker = UpdateChecker(preferences: preferences, transport: transport, current: rc4)
            var offered: [String] = []
            checker.onLaunchOffer = { offered.append($0.version) }
            checker.checkNow(); checker.checkIfDue()
            try require(offered.isEmpty && checker.pending, "Verificação manual ou periódica abriu a janela de atualização")
            checker.checkOnLaunch()
            try require(offered == [checker.offer?.version ?? "-"], "Abertura não ofereceu a atualização: \(offered)")
            checker.checkNow()
            try require(offered.count == 1, "Aviso repetido fora da abertura")
            checker.postpone()
            checker.checkOnLaunch()
            try require(offered.count == 1, "Depois não segurou o aviso")
            transport.reply = .success((200, json([])))
            let fresh = UpdateChecker(preferences: AppPreferences.disposable(currentVersion: "0.3.0-rc.4"), transport: transport, current: rc4)
            fresh.onLaunchOffer = { offered.append($0.version) }
            fresh.checkOnLaunch()
            try require(offered.count == 1 && fresh.outcome == .upToDate, "Aviso sem versão nova")
            // Off by default outside the app; never starts Sparkle in the runner.
            let disabled = AppUpdater(checker: checker, enabled: false)
            try require(!disabled.available && !disabled.canInstall, "Instalador ativo sem Sparkle")
            if let offer = checker.offer { disabled.install(offer); disabled.present(offer) }
            try require(!disabled.busy, "Instalador desativado iniciou uma sessão")
            try require(AppUpdater.production(checker: checker, activate: {}).available == false, "Executor de verificações iniciaria o Sparkle")
            // Sparkle shows CFBundleShortVersionString (no -rc): the release versions are shown instead.
            let display = ReleaseVersionDisplay(update: "0.5.0-rc.6", installed: "0.5.0-rc.5")
            var bundle: NSString = "0.5.0"
            let shown = withUnsafeMutablePointer(to: &bundle) { pointer in
                display.formatUpdateVersion(fromUpdate: SUAppcastItem.empty(), andBundleDisplayVersion: AutoreleasingUnsafeMutablePointer(pointer),
                                            withBundleVersion: "29")
            }
            try require(shown == "0.5.0-rc.6" && bundle == "0.5.0-rc.5", "Versões exibidas: \(shown) / \(bundle)")
            try require(display.formatBundleDisplayVersion("0.5.0", withBundleVersion: "29", matchingUpdate: nil) == "0.5.0-rc.5", "Versão instalada exibida")
        }

        test("Erros: 403, 429, timeout, rede, JSON inválido e corpo acima do limite não lançam nem oferecem") {
            let failures: [Result<(Int, Data), Error>] = [
                .success((403, Data("{\"message\":\"API rate limit exceeded\"}".utf8))),
                .success((429, Data())),
                .failure(URLError(.timedOut)),
                .failure(URLError(.notConnectedToInternet)),
                .success((200, Data("{not json".utf8))),
                .success((200, Data("{\"releases\":[]}".utf8))),
                .success((200, Data(count: UpdateFeed.maximumResponseSize + 1))),
            ]
            for (index, reply) in failures.enumerated() {
                let preferences = AppPreferences.disposable(currentVersion: "0.3.0-rc.4")
                let transport = FakeUpdateTransport()
                transport.reply = reply
                let checker = UpdateChecker(preferences: preferences, transport: transport, current: rc4)
                checker.checkNow()
                try require(checker.outcome == .failed && !checker.pending && !checker.checking && preferences.lastUpdateSuccess == nil
                            && preferences.lastUpdateAttempt != nil, "Resposta \(index) não virou erro")
            }
        }

        test("Transporte real com URLProtocol local: cabeçalhos, limite de tamanho e HTTPS") {
            @MainActor func fetch(_ transport: URLSessionUpdateTransport, _ request: URLRequest = UpdateFeed.request()) throws -> Result<(Int, Data), Error> {
                var result: Result<(Int, Data), Error>?
                transport.fetch(request, limit: UpdateFeed.maximumResponseSize) { result = $0 }
                try require(TestSupport.spin(10) { result != nil }, "Sem resposta do protocolo local")
                return result!
            }
            let transport = URLSessionUpdateTransport(protocolClasses: [StubUpdateProtocol.self])
            StubUpdateProtocol.configure(status: 200, chunks: [json(fixture)])
            guard case .success((200, let data)) = try fetch(transport), (try UpdateFeed.decode(data)).count > 3 else {
                throw TestSupport.Failure("Resposta válida não lida")
            }
            let seen = StubUpdateProtocol.seen.first
            try require(seen?.value(forHTTPHeaderField: "User-Agent") == "TunnelMac/\(HelperConstants.releaseVersion)"
                        && seen?.value(forHTTPHeaderField: "X-GitHub-Api-Version") == "2022-11-28"
                        && seen?.value(forHTTPHeaderField: "Cookie") == nil && seen?.value(forHTTPHeaderField: "Authorization") == nil,
                        "Cabeçalhos enviados: \(seen?.allHTTPHeaderFields ?? [:])")
            let chunk = Data(count: 256 * 1024)
            StubUpdateProtocol.configure(status: 200, chunks: Array(repeating: chunk, count: 5))
            guard case .failure(let streamed) = try fetch(transport), streamed as? UpdateTransportError == .tooLarge else {
                throw TestSupport.Failure("Corpo acima do limite não foi abortado")
            }
            StubUpdateProtocol.configure(status: 200, chunks: [Data("[]".utf8)], contentLength: 5 * 1024 * 1024)
            guard case .failure(let declared) = try fetch(transport), declared as? UpdateTransportError == .tooLarge else {
                throw TestSupport.Failure("Content-Length acima do limite aceito")
            }
            var plain = UpdateFeed.request()
            plain.url = URL(string: "http://api.github.com/repos/luizmz94/tunnelmac/releases")
            guard case .failure(let insecure) = try fetch(transport, plain), insecure as? UpdateTransportError == .notHTTPS else {
                throw TestSupport.Failure("HTTP sem TLS aceito")
            }
        }

        test("Conectar não espera a verificação (transporte que nunca responde)") {
            let store = try JSONStore(directory: root.appendingPathComponent("connect"))
            let model = AppModel(store: store, passwords: passwords, cookies: cookies, service: HelperTests.readyService())
            let launches = SAMLCookieTests.harness(model)
            let c = Connection(name: "Atualização", server: "vpn.invalid", port: 443, username: "user")
            created.append(c.id)
            try model.save(c, password: "fixturePASSvalue42")
            let transport = FakeUpdateTransport()
            transport.hold = true
            let checker = UpdateChecker(preferences: AppPreferences.disposable(), transport: transport, current: rc4)
            model.onUserConnect = { checker.checkIfDue() }
            let started = Date()
            model.connect(c)
            try require(launches.plans.count == 1 && Date().timeIntervalSince(started) < 0.5, "Conectar esperou a verificação")
            try require(transport.requests.count == 1 && checker.checking, "Conectar não disparou a verificação")
            try require(model.manager.session(c.id).state == .connecting && model.error == nil, "A verificação alterou a conexão")
            model.manager.disconnect(c.id); model.manager.end(model.manager.session(c.id), exit: 0)
            // Automatic reconnects never trigger a check.
            let fresh = FakeUpdateTransport()
            let other = UpdateChecker(preferences: AppPreferences.disposable(), transport: fresh, current: rc4)
            model.onUserConnect = { other.checkIfDue() }
            model.connect(c, retrying: true)
            try require(fresh.requests.isEmpty, "Reconexão automática verificou atualizações")
            model.manager.disconnect(c.id); model.manager.end(model.manager.session(c.id), exit: 0)
            transport.hold = false
            transport.releaseHeld()
        }

        test("Preferências: padrões, persistência isolada e invariante barra de menus/Dock") {
            let rc = AppPreferences.disposable(currentVersion: "0.3.0-rc.4")
            try require(rc.showMenuBarIcon && rc.hideDockOnClose && rc.hidesDockOnClose && rc.checkForUpdates && rc.includePrereleases
                        && rc.skippedVersion == nil && rc.lastUpdateAttempt == nil, "Padrões de uma rc")
            let stable = AppPreferences.disposable(currentVersion: "0.3.0")
            try require(!stable.includePrereleases, "Versão estável inclui rc por padrão")
            try require(rc.defaults !== UserDefaults.standard, "Testes usando as preferências reais")
            let date = Date(timeIntervalSince1970: 1_800_000_000)
            rc.showMenuBarIcon = false; rc.hideDockOnClose = true; rc.checkForUpdates = false; rc.includePrereleases = false
            rc.skippedVersion = "0.3.1"; rc.lastUpdateAttempt = date
            let reloaded = AppPreferences(defaults: rc.defaults, currentVersion: "0.3.0-rc.4")
            try require(!reloaded.showMenuBarIcon && reloaded.hideDockOnClose && !reloaded.checkForUpdates && !reloaded.includePrereleases
                        && reloaded.skippedVersion == "0.3.1" && reloaded.lastUpdateAttempt == date, "Preferências não persistiram")
            try require(!reloaded.hidesDockOnClose, "Sem ícone na barra de menus o app sumiria do Dock")
            rc.skippedVersion = nil
            try require(AppPreferences(defaults: rc.defaults).skippedVersion == nil, "Remoção não persistiu")
        }

        test("Barra de menus: o binding do ícone ignora o eco do SwiftUI e só publica mudanças reais") {
            let preferences = AppPreferences.disposable()
            var notifications = 0
            let token = preferences.objectWillChange.sink { notifications += 1 }
            defer { token.cancel() }
            let binding = preferences.menuBarIconBinding()
            for _ in 0..<5 { binding.wrappedValue = true }
            try require(notifications == 0 && preferences.defaults.object(forKey: AppPreferences.Key.showMenuBarIcon) == nil,
                        "Escrever o mesmo valor publicou mudança (recursão das cenas na rc.4)")
            binding.wrappedValue = false
            try require(notifications == 1 && !preferences.showMenuBarIcon && !binding.wrappedValue, "Mudança real não aplicada")
            let disabled = preferences.menuBarIconBinding(enabled: false)
            disabled.wrappedValue = true
            try require(!disabled.wrappedValue && !preferences.showMenuBarIcon && notifications == 1, "Executor de verificações inseriu o ícone")
        }

        test("Dock: política ao esconder cada janela em cada combinação, desligar o ícone e iniciar") {
            let store = try JSONStore(directory: root.appendingPathComponent("dock"))
            let model = AppModel(store: store, passwords: passwords, cookies: cookies, service: HelperTests.readyService())
            let preferences = AppPreferences.disposable()
            let menuBar = MenuBarCoordinator(model: model, preferences: preferences)
            var policies: [NSApplication.ActivationPolicy] = []
            menuBar.setActivationPolicy = { policies.append($0) }
            menuBar.activateApp = {}
            @MainActor func window() -> NSWindow {
                let w = NSWindow(contentRect: NSRect(x: -12000, y: -12000, width: 10, height: 10), styleMask: [.titled, .closable], backing: .buffered, defer: true)
                w.isReleasedWhenClosed = false
                return w
            }
            let main = window(), settings = window()
            menuBar.mainWindow = main
            for (icon, hide, settingsVisible, expected) in [
                (true, true, false, NSApplication.ActivationPolicy.accessory), (true, false, false, .regular),
                (false, true, false, .regular), (false, false, false, .regular),
                (true, true, true, .regular), (false, true, true, .regular)] {
                preferences.showMenuBarIcon = icon; preferences.hideDockOnClose = hide
                menuBar.settingsWindow = settings
                if settingsVisible { settings.orderFront(nil) } else { settings.orderOut(nil) }
                main.orderFront(nil)
                policies = []
                menuBar.hideMainWindow(main)
                try require(!main.isVisible && policies == [expected],
                            "Ícone \(icon), ocultar \(hide), Configurações \(settingsVisible): \(policies)")
            }
            // Closing Configurações: same rule, considering the main window.
            preferences.showMenuBarIcon = true; preferences.hideDockOnClose = true
            for (mainVisible, expected) in [(true, NSApplication.ActivationPolicy.regular), (false, .accessory)] {
                menuBar.settingsWindow = settings
                settings.orderFront(nil)
                if mainVisible { main.orderFront(nil) } else { main.orderOut(nil) }
                policies = []
                settings.performClose(nil)
                try require(policies == [expected] && menuBar.settingsWindow == nil, "Fechar Configurações (principal \(mainVisible)): \(policies)")
            }
            main.orderOut(nil)
            policies = []
            preferences.showMenuBarIcon = false
            try require(policies == [.regular], "Desligar o ícone com a janela fechada não pôs o app no Dock")
            policies = []
            menuBar.enforceVisibility()
            try require(policies == [.regular], "Inicialização sem ícone na barra de menus")
            preferences.showMenuBarIcon = true
            policies = []
            menuBar.enforceVisibility()
            try require(policies.isEmpty, "Inicialização padrão mudou a política")
        }

        test("Configurações: janela única na aba pedida, menus e Verificar atualizações…") {
            let store = try JSONStore(directory: root.appendingPathComponent("settings"))
            let model = AppModel(store: store, passwords: passwords, cookies: cookies, service: HelperTests.readyService())
            let transport = FakeUpdateTransport()
            let preferences = AppPreferences.disposable()
            let menuBar = MenuBarCoordinator(model: model, updates: UpdateChecker(preferences: preferences, transport: transport, current: rc4))
            try require(menuBar.preferences === preferences, "Preferências do verificador e do coordenador divergem")
            var policies: [NSApplication.ActivationPolicy] = [], opened = 0, activated = 0
            menuBar.setActivationPolicy = { policies.append($0) }
            menuBar.activateApp = { activated += 1 }
            menuBar.openSettingsFallback = { opened += 1 }
            menuBar.showSettings(.about)
            try require(opened == 1 && menuBar.settingsTab == .about && policies == [.regular] && activated == 1, "Abrir Configurações")
            let window = NSWindow(contentRect: NSRect(x: -12000, y: -12000, width: 10, height: 10), styleMask: [.titled, .closable], backing: .buffered, defer: true)
            window.isReleasedWhenClosed = false
            menuBar.settingsWindow = window
            window.orderFront(nil)
            menuBar.showServiceManagement()
            try require(opened == 1 && menuBar.settingsTab == .service && window.isVisible, "Reabrir criou outra janela")
            menuBar.checkForUpdates()
            try require(transport.requests.count == 1 && menuBar.settingsTab == .updates, "Verificar atualizações… não verificou nem abriu a aba")
            menuBar.settingsTab = .about
            menuBar.installUpdate()
            try require(menuBar.settingsTab == .updates && !menuBar.installer.available, "Atualizar sem Sparkle não mostrou como atualizar")
            window.orderOut(nil)
            try require(Set(SettingsTab.allCases.map(\.symbol)) == ["gearshape.fill", "arrow.triangle.2.circlepath", "lock.shield.fill", "archivebox.fill", "info"], "Ícones das abas")
            for symbol in SettingsTab.allCases.map(\.symbol) + ["menubar.rectangle", "dock.rectangle", "power", "rectangle.portrait.and.arrow.right",
                           "shippingbox", "clock.arrow.circlepath", "testtube.2", "wifi.exclamationmark", "checkmark.circle", "arrow.up.right.square",
                           "doc.on.doc", "terminal", "arrow.down.circle", "chevron.left.forwardslash.chevron.right", "doc.text", "checkmark.seal",
                           "list.bullet.rectangle", "doc.text.magnifyingglass", "chevron.right", "checkmark",
                           "square.and.arrow.up", "square.and.arrow.down", "plus.circle.fill", "arrow.triangle.2.circlepath.circle.fill",
                           "key.fill", "person.badge.key.fill", "info.circle.fill", "checkmark.circle.fill", "exclamationmark.circle.fill",
                           "exclamationmark.triangle.fill"] {
                try require(NSImage(systemSymbolName: symbol, accessibilityDescription: nil) != nil, "SF Symbol inexistente: \(symbol)")
            }
        }

        test("Abrir ao iniciar sessão: estado real, aprovação e indisponível sem registrar") {
            let unavailable = LoginItemController(service: nil, unavailableReason: "ad hoc")
            unavailable.setEnabled(true)
            try require(!unavailable.available && !unavailable.enabled && unavailable.detail == "ad hoc", "Indisponível")
            let fake = FakeLoginItem()
            let controller = LoginItemController(service: fake)
            fake.afterRegister = .requiresApproval
            controller.setEnabled(true)
            try require(controller.status == .requiresApproval && controller.enabled && controller.detail.contains("Itens de Início"), "Aprovação pendente")
            controller.openSystemSettings()
            fake.status = .enabled; controller.refresh()
            controller.setEnabled(false)
            try require(fake.events == ["register", "settings", "unregister"] && controller.status == .notRegistered, "Eventos: \(fake.events)")
            fake.error = AppFailure("negado")
            controller.setEnabled(true)
            try require(controller.message?.contains("negado") == true && controller.detail.contains("negado"), "Erro sem mensagem")
            try require(LoginItemController.production().available == false, "Executor de verificações poderia registrar um item de início")
        }

        test("Homebrew: detecção por diretório injetado e comando exato") {
            let base = root.appendingPathComponent("brew")
            let present = base.appendingPathComponent("arm/Caskroom/tunnelmac").path
            try FileManager.default.createDirectory(atPath: present, withIntermediateDirectories: true)
            let absent = base.appendingPathComponent("intel/Caskroom/tunnelmac").path
            try require(HomebrewInstall.detect(caskrooms: [absent, present]), "Caskroom não detectado")
            try require(!HomebrewInstall.detect(caskrooms: [absent]), "Detectou sem Caskroom")
            try require(HomebrewInstall.caskrooms == ["/opt/homebrew/Caskroom/tunnelmac", "/usr/local/Caskroom/tunnelmac"], "Caminhos padrão")
            try require(HomebrewInstall.upgradeCommand == "brew upgrade --cask luizmz94/tunnelmac/tunnelmac", "Comando exibido")
        }

        test("Renderização fora da tela: Configurações em cada aba e cartão de atualização, claro e escuro") {
            let output = Bundle.main.bundleURL.deletingLastPathComponent().appendingPathComponent("ui-review/settings", isDirectory: true)
            try? FileManager.default.removeItem(at: output)
            try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)
            let store = try JSONStore(directory: root.appendingPathComponent("render"))
            let connection = Connection(name: "Escritório", server: "vpn.exemplo.invalid", port: 443, username: "ana")
            created.append(connection.id)
            try store.save(SavedData(connections: [connection]))
            let model = AppModel(store: store, passwords: passwords, cookies: cookies, service: HelperTests.readyService())
            let clock = Date()
            @MainActor func coordinator(pending: Bool) -> MenuBarCoordinator {
                let preferences = AppPreferences.disposable(currentVersion: "0.3.0-rc.4")
                let transport = FakeUpdateTransport()
                transport.reply = .success((200, json(pending ? fixture : [])))
                let checker = UpdateChecker(preferences: preferences, transport: transport, current: rc4, now: { clock })
                checker.checkNow()
                return MenuBarCoordinator(model: model, updates: checker,
                                          loginItem: LoginItemController(service: nil, unavailableReason: "Desativado na revisão visual."))
            }
            for (appearance, suffix) in [(NSAppearance.Name.aqua, "light"), (.darkAqua, "dark")] {
                for pending in [false, true] {
                    let menuBar = coordinator(pending: pending)
                    for tab in SettingsTab.allCases {
                        menuBar.settingsTab = tab
                        try UIPreviewTests.snapshot(SettingsView(menuBar: menuBar, installedByHomebrew: true), size: NSSize(width: 760, height: 620),
                                                    appearance: appearance,
                                                    to: output.appendingPathComponent("settings-\(tab.rawValue)\(pending ? "-pending" : "")-\(suffix).png"))
                    }
                    if pending {
                        menuBar.settingsTab = .updates
                        try UIPreviewTests.snapshot(SettingsView(menuBar: menuBar, installedByHomebrew: false), size: NSSize(width: 760, height: 620),
                                                    appearance: appearance, to: output.appendingPathComponent("settings-updates-github-\(suffix).png"))
                        let inApp = MenuBarCoordinator(model: model, updates: menuBar.updates, installer: .preview(checker: menuBar.updates),
                                                       loginItem: LoginItemController(service: nil, unavailableReason: "Desativado na revisão visual."))
                        inApp.settingsTab = .updates
                        try UIPreviewTests.snapshot(SettingsView(menuBar: inApp, installedByHomebrew: true), size: NSSize(width: 760, height: 620),
                                                    appearance: appearance, to: output.appendingPathComponent("settings-updates-inapp-\(suffix).png"))
                        try UIPreviewTests.snapshot(MainView(model: model, menuBar: menuBar), size: NSSize(width: 980, height: 640),
                                                    appearance: appearance, to: output.appendingPathComponent("main-update-card-\(suffix).png"))
                        try UIPreviewTests.snapshot(MenuBarView(menuBar: menuBar), size: NSSize(width: 360, height: 300),
                                                    appearance: appearance, to: output.appendingPathComponent("menubar-update-\(suffix).png"))
                        model.service.useForLocalChecks(status: HelperTests.readyStatus()) // The menu refreshes the service on appear.
                    }
                }
            }
            let files = try FileManager.default.contentsOfDirectory(atPath: output.path).filter { $0.hasSuffix(".png") }
            try require(files.count == 28, "Renders esperados: 28, gerados: \(files.count)")
        }
        return failures
    }
}
