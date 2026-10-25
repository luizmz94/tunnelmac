@testable import VPNApp
import Foundation
import SwiftUI
import AppKit
import VPNHelperShared

/// Local checks for the presentation layer: state mapping, digest grouping and offscreen
/// renders (light and dark) written next to the runner for a later visual review.
/// Session states are set directly on test models; nothing connects, nothing is registered.
@MainActor
enum UIPreviewTests {
    static func run() -> Int {
        var failures = 0
        func test(_ name: String, _ block: () throws -> Void) {
            do { try block(); print("PASS: UI: \(name)") }
            catch { failures += 1; print("FAIL: UI: \(name): \(error.localizedDescription)") }
        }
        let require = TestSupport.require
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("VPNGUI-ui-tests-\(UUID())")
        defer { try? FileManager.default.removeItem(at: root) }
        let passwords = PasswordStore(service: "com.luiz.vpngui.tests.ui-password.\(UUID())")
        var created: [UUID] = []
        defer { for id in created { try? passwords.delete(id) } }

        test("Estados: símbolo e cor distinguem conectada, em andamento, falha e desconectada") {
            let all: [ConnectionState] = [.disconnected, .authorizing, .waitingForSAML, .connecting, .authenticating,
                                          .connected, .reconnecting, .disconnecting, .failed]
            try require(Set([ConnectionState.connected, .failed, .disconnected, .connecting].map(\.symbol)).count == 4,
                        "Símbolos repetidos entre estados principais")
            try require(ConnectionState.connected.tone == .success && ConnectionState.failed.tone == .danger
                        && ConnectionState.disconnected.tone == .neutral, "Tons dos estados principais")
            for state in all {
                try require(state.inProgress == (state.active && state != .connected), "Andamento incoerente: \(state)")
                try require(NSImage(systemSymbolName: state.symbol, accessibilityDescription: nil) != nil, "SF Symbol inexistente: \(state.symbol)")
                try require(MenuBarRow.symbol(state) == state.symbol, "Menu e janela divergem: \(state)")
            }
            for summary in [MenuBarSummary.idle, .attention, .transitioning, .connected] {
                try require(NSImage(systemSymbolName: summary.symbol, accessibilityDescription: nil) != nil, "SF Symbol inexistente: \(summary.symbol)")
            }
            for symbol in ["lock.trianglebadge.exclamationmark", "person.crop.circle.badge.exclamationmark", "person.crop.circle.badge.xmark",
                           "network.badge.shield.half.filled", "text.alignleft", "folder.badge.questionmark", "sidebar.left",
                           "bolt.fill", "stop.fill", "macwindow", "gearshape", "power", "terminal", "shippingbox"] {
                try require(NSImage(systemSymbolName: symbol, accessibilityDescription: nil) != nil, "SF Symbol inexistente: \(symbol)")
            }
        }

        test("Certificado: o digest agrupado preserva exatamente os 64 dígitos") {
            let digest = (0..<64).map { String(format: "%x", $0 % 16) }.joined()
            let grouped = CertificateTrustSheet.grouped(digest)
            try require(grouped.filter { !$0.isWhitespace } == digest, "Digest alterado ao agrupar")
            try require(grouped.split(separator: "\n").count == 2, "Agrupamento inesperado: \(grouped)")
        }

        test("Marca: ícone do app e imagens claro/escuro e template estão no bundle") {
            try require(BrandAssets.lightSymbol != nil && BrandAssets.darkSymbol != nil, "Símbolos da marca ausentes")
            try require(BrandAssets.menuIcon?.isTemplate == true && BrandAssets.menuIcon?.size == NSSize(width: 18, height: 18),
                        "Ícone da barra de menus não está preparado como template de 18 pt")
            let icon = Bundle.main.url(forResource: "AppIcon", withExtension: "icns").flatMap { NSImage(contentsOf: $0) }
            try require(icon?.representations.contains(where: { $0.pixelsWide == 1024 && $0.pixelsHigh == 1024 }) == true,
                        "ICNS não contém a representação de 1024 px")
        }

        test("Renderização fora da tela: janela, menu bar, formulários e serviço em claro e escuro") {
            let output = Bundle.main.bundleURL.deletingLastPathComponent().appendingPathComponent("ui-review", isDirectory: true)
            try? FileManager.default.removeItem(at: output)
            try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)

            let store = try JSONStore(directory: root.appendingPathComponent("main"))
            let connections = [
                Connection(name: "Escritório São Paulo", server: "vpn.exemplo.invalid", port: 443, username: "ana"),
                Connection(name: "Cliente com um nome de conexão bem longo para testar o truncamento", server: "gateway.cliente-longo.invalid", port: 10443, username: "ana.souza"),
                Connection(name: "Laboratório", server: "lab-a.invalid", port: 443, username: "", authentication: .saml),
                Connection(name: "Laboratório", server: "lab-b.invalid", port: 8443, username: "", authentication: .saml),
                Connection(name: "Data center", server: "dc.invalid", port: 443, username: "ops",
                           trustedCertificate: String(repeating: "ab", count: 32)),
            ] + ["Filial Curitiba", "Filial Recife", "Fornecedor Alfa", "Fornecedor Beta", "Homologação",
                 "Produção", "Suporte remoto", "Backup noturno", "Parceiro Gama"].enumerated().map { index, name in
                Connection(name: name, server: "vpn\(index).exemplo.invalid", port: 443, username: "ana")
            }
            created += connections.map(\.id)
            try store.save(SavedData(connections: connections))
            let model = AppModel(store: store, passwords: passwords, service: HelperTests.readyService())
            let menuBar = MenuBarCoordinator(model: model)
            let s = connections.map { model.manager.session($0.id) }
            defer { for session in s { session.state = .disconnected; session.connectedAt = nil } }
            s[0].state = .connected; s[0].connectedAt = Date().addingTimeInterval(-3725)
            s[0].logs = ["Conectando a vpn.exemplo.invalid:443", "Senha: ********", "Túnel estabelecido", "Rotas e DNS configurados"]
            s[1].state = .waitingForSAML
            s[2].state = .failed; s[2].suggestedCertificate = String(repeating: "0f", count: 32)
            s[2].logs = ["ERROR: certificado não confiável"]
            s[3].state = .disconnecting; s[3].wantsDisconnect = true
            s[4].authenticationRejected = true; s[4].state = .failed

            let imported = try OpenVPNImporter.importText(OpenVPNTests.singleFile.replacingOccurrences(of: "client\n", with: "client\nauth-user-pass\n"),
                                                          baseDirectory: root, suggestedName: "Summit OpenVPN", source: "~/Downloads/Summit.ovpn")
            var openVPN = Connection(name: "Summit OpenVPN", username: "luiz.carlos", kind: .openvpn, openVPN: imported.summary)
            openVPN.openVPN?.warnings.append("O arquivo original key.key pode ser lido por outros usuários do Mac (recomendado: chmod 600). A cópia do app é privada.")
            created.append(openVPN.id)
            let openVPNSession = model.manager.session(openVPN.id)
            defer { openVPNSession.state = .disconnected }
            openVPNSession.state = .failed
            openVPNSession.digestFix = imported.digestFix
            openVPNSession.logs = ["Message hash algorithm 'RSA-SHA256' not found", "Exiting due to fatal error"]
            var bothStatus = HelperTests.readyStatus()
            bothStatus.openVPNRuntime = RuntimeSummary(id: "ovpn", version: "2.7.8", approvedAt: Date(), capabilities: RuntimeCapabilities(help: ""),
                                                       sourcePath: "/opt/homebrew/Cellar/openvpn/2.7.8_1/sbin/openvpn", sourceSHA256: "0")
            let wireGuardImport = try WireGuardImporter.importText(WireGuardTests.fullTunnel, suggestedName: "Casa WireGuard", source: "~/Downloads/MacOS.conf")
            var wireGuardWarned = wireGuardImport
            wireGuardWarned.warnings = ["PostUp removido: comandos executados como root pelo wg-quick; o TunnelMac não executa scripts do perfil.",
                                        "O arquivo original MacOS.conf contém a chave privada e pode ser lido por outros usuários do Mac (recomendado: apagá-lo ou chmod 600). A cópia do app é privada."]
            let wireGuard = Connection(name: "Casa WireGuard", kind: .wireguard, wireGuard: wireGuardImport.summary)
            created.append(wireGuard.id)
            let wireGuardSession = model.manager.session(wireGuard.id)
            defer { wireGuardSession.state = .disconnected; wireGuardSession.connectedAt = nil }
            wireGuardSession.state = .connected
            wireGuardSession.connectedAt = Date().addingTimeInterval(-421)
            wireGuardSession.logs = ["[+] Interface do WireGuard: utun8", "[#] ifconfig utun8 inet 10.8.0.3/32 10.8.0.3 alias",
                                     "[#] route -q -n add -inet 0.0.0.0/1 -interface utun8", "\(WireGuardMarkers.ready) em utun8.",
                                     "\(WireGuardMarkers.handshake) com 203.0.113.10:51820."]
            let bothService = ServiceController(policy: .unavailable(reason: "verificações locais"), registrar: nil, client: nil)
            bothService.useForLocalChecks(status: bothStatus)
            let bothModel = AppModel(store: try JSONStore(directory: root.appendingPathComponent("both")), passwords: passwords, service: bothService)

            let unavailableModel = AppModel(store: try JSONStore(directory: root.appendingPathComponent("unavailable")),
                                            passwords: passwords,
                                            service: ServiceController(policy: .unavailable(reason: "ad hoc"), registrar: nil, client: nil))
            unavailableModel.service.refresh()
            let emptyMenuBar = MenuBarCoordinator(model: unavailableModel)

            // Exercise a real resizable host, not only fixed-size snapshots. A
            // split view must not grow beyond the window when details are selected.
            let live = NSWindow(contentRect: NSRect(x: -15000, y: -15000, width: 900, height: 600),
                                styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
            live.isReleasedWhenClosed = false
            live.contentView = NSHostingView(rootView: MainView(model: model, menuBar: menuBar)
                .frame(minWidth: 850, minHeight: 550))
            live.orderFrontRegardless()
            defer { live.orderOut(nil) }
            _ = TestSupport.spin(0.2) { false }
            menuBar.pendingSelection = connections[0].id
            _ = TestSupport.spin(0.3) { false }
            @MainActor func splitViews(_ view: NSView) -> [NSSplitView] {
                if let split = view as? NSSplitView { return [split] }
                return view.subviews.flatMap(splitViews)
            }
            if let host = live.contentView {
                let splits = splitViews(host)
                try require(!splits.isEmpty, "Split view não encontrado na janela real")
                try require(splits.allSatisfy { $0.frame.height <= host.bounds.height + 60 },
                            "O conteúdo ultrapassou a altura da janela ao selecionar uma conexão")
                live.setContentSize(NSSize(width: 850, height: 550))
                menuBar.pendingSelection = connections[2].id
                _ = TestSupport.spin(0.3) { false }
                try require(splitViews(host).allSatisfy { $0.frame.height <= host.bounds.height + 60 },
                            "Os avisos de certificado fizeram o conteúdo ultrapassar a janela mínima")
            }

            for (appearance, suffix) in [(NSAppearance.Name.aqua, "light"), (.darkAqua, "dark")] {
                @MainActor func render<V: View>(_ view: V, _ size: NSSize, _ name: String) throws {
                    try snapshot(view, size: size, appearance: appearance, to: output.appendingPathComponent("\(name)-\(suffix).png"))
                }
                try render(MainView(model: model, menuBar: menuBar), NSSize(width: 980, height: 640), "main-empty-selection")
                for (index, name) in ["connected", "saml-queue", "certificate", "disconnecting", "rejected"].enumerated() {
                    try render(ConnectionDetail(connection: connections[index], session: s[index], model: model, edit: {}, delete: {}),
                               NSSize(width: 640, height: 520), "detail-\(name)")
                }
                try render(MainView(model: unavailableModel, menuBar: emptyMenuBar), NSSize(width: 900, height: 560), "main-no-connections")
                try render(MenuBarView(menuBar: menuBar), NSSize(width: 360, height: 520), "menubar-list")
                try render(MenuBarView(menuBar: emptyMenuBar), NSSize(width: 360, height: 300), "menubar-empty-service")
                try render(ConnectionEditor(model: model, connection: Connection(), saved: {}), NSSize(width: 560, height: 600), "editor-new")
                try render(ConnectionEditor(model: model, connection: connections[2], saved: {}), NSSize(width: 560, height: 600), "editor-saml")
                try render(CertificateTrustSheet(connection: connections[4], digest: String(repeating: "0f", count: 32), trust: {}),
                           NSSize(width: 520, height: 400), "certificate-sheet")
                try render(ServicePanel(model: unavailableModel).padding(20), NSSize(width: 620, height: 360), "service-panel")
                try render(ServiceStatusRow(service: model.service) {}, NSSize(width: 300, height: 56), "service-row")
                try render(ConnectionEditor(model: model, connection: openVPN, pendingImport: imported, saved: {}), NSSize(width: 560, height: 640), "editor-openvpn-import")
                try render(ConnectionEditor(model: model, connection: Connection(), saved: {}), NSSize(width: 560, height: 520), "editor-choose-type")
                try render(ConnectionEditor(model: model, connection: wireGuard, pendingWireGuard: wireGuardWarned, saved: {}),
                           NSSize(width: 560, height: 640), "editor-wireguard-import")
                try render(ConnectionDetail(connection: wireGuard, session: wireGuardSession, model: model, edit: {}, delete: {}),
                           NSSize(width: 640, height: 560), "detail-wireguard-connected")
                try render(ConnectionDetail(connection: openVPN, session: openVPNSession, model: model, edit: {}, delete: {}),
                           NSSize(width: 640, height: 560), "detail-openvpn-digest")
                let versions = ClientVersionChecker(transport: DisabledUpdateTransport())
                versions.setForChecks(local: [.openvpn: .init(path: "/opt/homebrew/sbin/openvpn", exists: true, version: "2.7.8", sourceChanged: false),
                                              .openfortivpn: .init(path: "/opt/homebrew/bin/openfortivpn", exists: true, version: "1.24.1", sourceChanged: false),
                                              .wireguard: .init(path: "/opt/homebrew/bin/wireguard-go", exists: true, version: "0.0.20250522", sourceChanged: false)],
                                      latest: [.openvpn: "2.7.10", .openfortivpn: "1.24.1", .wireguard: "0.0.20250522"])
                try render(ServicePanel(model: bothModel, versions: versions).padding(20), NSSize(width: 620, height: 600), "service-panel-both")
                let dnsDefault = AppPreferences.disposable()
                let dnsCustom = AppPreferences.disposable()
                dnsCustom.addCustomDNS(try InternetDNSOption.custom(name: "Servidor de casa com nome longo", servers: "192.0.2.53"))
                for (preferences, name) in [(dnsDefault, "settings-dns-default"), (dnsCustom, "settings-dns-custom")] {
                    try render(VStack(alignment: .leading, spacing: 18) { InternetDNSSection(preferences: preferences) }.padding(24),
                               NSSize(width: 540, height: 170), name)
                }
            }
            let files = try FileManager.default.contentsOfDirectory(atPath: output.path).filter { $0.hasSuffix(".png") }
            try require(files.count == 44, "Renders esperados: 44, gerados: \(files.count)")
        }
        return failures
    }

    /// Draws a view in a borderless offscreen window and writes a PNG.
    static func snapshot<V: View>(_ view: V, size: NSSize, appearance: NSAppearance.Name, to url: URL) throws {
        let window = NSWindow(contentRect: NSRect(x: -20000, y: -20000, width: size.width, height: size.height),
                              styleMask: [.borderless], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        window.appearance = NSAppearance(named: appearance)
        let host = NSHostingView(rootView: view.frame(width: size.width, height: size.height)
            .background(Color(nsColor: .windowBackgroundColor)))
        host.appearance = NSAppearance(named: appearance)
        host.frame = NSRect(origin: .zero, size: size)
        window.contentView = host
        window.orderFrontRegardless()
        _ = TestSupport.spin(0.4) { false }
        host.layoutSubtreeIfNeeded()
        guard let bitmap = host.bitmapImageRepForCachingDisplay(in: host.bounds) else { throw TestSupport.Failure("Sem bitmap") }
        host.cacheDisplay(in: host.bounds, to: bitmap)
        window.orderOut(nil)
        guard let png = bitmap.representation(using: .png, properties: [:]), png.count > 2000 else {
            throw TestSupport.Failure("Render vazio: \(url.lastPathComponent)")
        }
        try png.write(to: url)
    }
}
