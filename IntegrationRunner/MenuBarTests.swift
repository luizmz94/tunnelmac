@testable import VPNApp
import Foundation
import AppKit
import Combine
import SwiftUI

@MainActor
private final class LayoutDelegateProbe: NSObject, NSWindowDelegate {
    func windowWillResize(_ sender: NSWindow, to frameSize: NSSize) -> NSSize {
        NSSize(width: frameSize.width + 1, height: frameSize.height + 2)
    }
}

/// Local checks for the menu bar (SPEC 02).
/// Nothing here starts openfortivpn, asks for privileges or touches the network.
@MainActor
enum MenuBarTests {
    private struct Failure: LocalizedError {
        let errorDescription: String?
        init(_ message: String) { errorDescription = message }
    }
    private static func require(_ condition: Bool, _ message: String) throws {
        if !condition { throw Failure(message) }
    }

    /// Profiles saved without Keychain passwords: a real connect fails locally.
    private static func makeModel(_ root: URL, names: [String]) throws -> (AppModel, [Connection]) {
        let store = try JSONStore(directory: root.appendingPathComponent(UUID().uuidString))
        let connections = names.enumerated().map { index, name in
            Connection(name: name, server: "vpn\(index).invalid", port: 443, username: "test")
        }
        try store.save(SavedData(connections: connections))
        let model = AppModel(store: store, passwords: PasswordStore(service: "com.luiz.vpngui.tests.menubar.\(UUID())"),
                             service: HelperTests.readyService())
        return (model, connections)
    }

    static func run(_ test: (String, () throws -> Void) -> Void) {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("VPNGUI-menubar-tests-\(UUID())")
        defer { try? FileManager.default.removeItem(at: root) }

        test("Menubar: indicador agregado observa cada sessão sem confundir andamento com túnel") {
            let (model, connections) = try makeModel(root, names: ["A", "B"])
            let menuBar = MenuBarCoordinator(model: model)
            var notifications = 0
            let token = menuBar.objectWillChange.sink { notifications += 1 }
            defer { token.cancel() }
            let first = model.manager.session(connections[0].id), second = model.manager.session(connections[1].id)
            try require(menuBar.summary == .idle && menuBar.connectedCount == 0, "Estado inicial incorreto")
            for state in [ConnectionState.authorizing, .connecting, .authenticating, .waitingForSAML, .reconnecting, .disconnecting] {
                first.state = state
                try require(menuBar.summary == .transitioning && menuBar.connectedCount == 0, "\(state.title) apareceu como conectada")
            }
            try require(notifications >= 6, "Mudança dentro da sessão não atualizou o indicador")
            notifications = 0
            second.accept("INFO: Tunnel is up and running.", connection: connections[1]) { _ in }
            try require(notifications > 0 && menuBar.summary == .connected, "Túnel estabelecido não refletido")
            try require(menuBar.summaryText == "1 conectada · 1 em andamento", "Resumo incorreto: \(menuBar.summaryText)")
            first.state = .failed; second.state = .disconnected
            try require(menuBar.summary == .attention, "Falha não sinalizada")
            first.state = .disconnected
            model.error = "erro local"
            try require(menuBar.summary == .attention && menuBar.accessibilityDescription.contains("erro"), "Erro pendente não sinalizado")
        }

        test("Menubar: observação composta não substitui manager.changed usado no Sair") {
            let (model, connections) = try makeModel(root, names: ["A"])
            var changes = 0
            model.manager.changed = { changes += 1 }
            let menuBar = MenuBarCoordinator(model: model)
            let session = model.manager.session(connections[0].id)
            session.state = .connected
            menuBar.perform(connections[0])
            try require(changes == 1 && session.state == .disconnecting, "Callback do manager foi substituído")
            // A session created later is observed too.
            var notifications = 0
            let token = menuBar.objectWillChange.sink { notifications += 1 }
            defer { token.cancel() }
            let late = model.manager.session(UUID())
            notifications = 0
            late.state = .connecting
            try require(notifications > 0, "Sessão nova não observada")
        }

        test("Menubar: encaminha uma única ação ao modelo e bloqueia repetição na desconexão") {
            let (model, connections) = try makeModel(root, names: ["A", "B"])
            let menuBar = MenuBarCoordinator(model: model)
            var connects: [UUID] = [], disconnects: [UUID] = []
            var opened = 0
            menuBar.connectAction = { connects.append($0.id) }
            menuBar.disconnectAction = { disconnects.append($0) }
            menuBar.activateApp = {}
            menuBar.openWindowFallback = { opened += 1 }
            menuBar.perform(connections[0])
            try require(connects == [connections[0].id] && disconnects.isEmpty, "Conectar não encaminhado uma vez")
            let session = model.manager.session(connections[0].id)
            session.state = .connected
            menuBar.perform(connections[0])
            try require(disconnects == [connections[0].id] && connects.count == 1, "Desconectar não encaminhado uma vez")
            session.state = .disconnecting; session.wantsDisconnect = true
            try require(menuBar.action(for: connections[0]) == .disconnecting && !MenuBarRowAction.disconnecting.enabled, "Botão habilitado durante desconexão")
            menuBar.perform(connections[0]); menuBar.perform(connections[0])
            try require(disconnects.count == 1 && connects.count == 1, "Clique repetido gerou outra ação")
            let other = model.manager.session(connections[1].id)
            other.authenticationRejected = true
            menuBar.perform(connections[1])
            try require(connects.count == 1 && opened == 1 && menuBar.pendingSelection == connections[1].id,
                        "Recusa não foi encaminhada à janela para revisão")
            // Real path: the model's manager handles the disconnect, a second click is ignored.
            let real = MenuBarCoordinator(model: model)
            session.state = .connected; session.wantsDisconnect = false
            real.perform(connections[0]); real.perform(connections[0])
            try require(session.state == .disconnecting && session.logs.filter { $0.contains("Solicitando encerramento") }.count == 1,
                        "Desconexão real repetida")
            model.manager.end(session, exit: 0)
            try require(session.state == .disconnected && real.summary == .idle, "Limpeza não refletida no menubar")
        }

        test("Menubar: conectar pelo menu usa a trava de recusa e a falta de senha do modelo") {
            let (model, connections) = try makeModel(root, names: ["A"])
            let menuBar = MenuBarCoordinator(model: model)
            menuBar.perform(connections[0]) // No Keychain password: fails locally, before any process.
            let session = model.manager.session(connections[0].id)
            // Credentials are read off the main thread; the error arrives on a later run-loop turn.
            try require(TestSupport.spin(5) { model.error != nil } && model.error?.contains("Keychain") == true && !session.state.active && session.pid == nil,
                        "Erro local do modelo não ficou visível")
            try require(menuBar.summary == .attention, "Erro não sinalizado no ícone")
        }

        test("Menubar: dados corrompidos e lista vazia não permitem ações de conexão") {
            let store = try JSONStore(directory: root.appendingPathComponent("broken"))
            try Data("invalid-json".utf8).write(to: store.file)
            let broken = AppModel(store: store, passwords: PasswordStore(service: "com.luiz.vpngui.tests.menubar.\(UUID())"))
            let menuBar = MenuBarCoordinator(model: broken)
            var calls = 0
            menuBar.connectAction = { _ in calls += 1 }
            menuBar.disconnectAction = { _ in calls += 1 }
            let ghost = Connection(name: "X", server: "vpn.invalid", username: "test")
            try require(MenuBarRowAction.of(broken.manager.session(ghost.id), ready: broken.ready) == .unavailable, "Ação disponível sem dados")
            menuBar.perform(ghost)
            try require(calls == 0 && menuBar.summary == .attention && menuBar.summaryText == "Dados não carregados", "Modelo não pronto aceitou ação")
            try require(try String(contentsOf: store.file) == "invalid-json", "Arquivo corrompido alterado")
            let (empty, _) = try makeModel(root, names: [])
            try require(MenuBarCoordinator(model: empty).summary == .idle && empty.data.connections.isEmpty, "Lista vazia incorreta")
            let (named, _) = try makeModel(root, names: ["Cliente", "cliente", "Outro"])
            try require(MenuBarCoordinator(model: named).duplicatedNames == ["cliente"], "Nomes repetidos não identificados")
        }

        test("Sair: cancelar mantém sessões; confirmar aguarda limpeza, inclusive reconexão e fila SAML") {
            let (model, connections) = try makeModel(root, names: ["Ativa", "Reconexão", "Fila SAML"])
            let delegate = AppDelegate()
            var replies: [Bool] = [], asked = 0, answer = false
            delegate.confirmTermination = { asked += 1; return answer }
            delegate.replyToTermination = { replies.append($0) }
            try require(delegate.terminationReply() == .terminateNow, "Sem modelo deveria sair")
            delegate.attach(model: model, menuBar: MenuBarCoordinator(model: model))
            try require(delegate.terminationReply() == .terminateNow && asked == 0, "Sem sessões ativas pediu confirmação")
            let active = model.manager.session(connections[0].id)
            let retrying = model.manager.session(connections[1].id)
            let queued = model.manager.session(connections[2].id)
            // Only a scheduled reconnect.
            retrying.begin()
            retrying.accept("INFO: Tunnel is up and running.", connection: connections[1]) { _ in }
            model.manager.end(retrying, exit: 1)
            let task = retrying.reconnectTask
            try require(retrying.state == .reconnecting && task != nil, "Reconexão não agendada")
            try require(delegate.terminationReply() == .terminateCancel && asked == 1, "Cancelar não manteve o app")
            try require(retrying.state == .reconnecting && task?.isCancelled == false && replies.isEmpty, "Cancelar alterou a reconexão")
            answer = true
            try require(delegate.terminationReply() == .terminateLater, "Confirmação não aguardou")
            try require(task?.isCancelled == true && retrying.state == .disconnected && replies == [true], "Reconexão pendente não foi cancelada antes de sair")
            // Only the SAML queue, with a fresh delegate (each run ends in a reply).
            let samlDelegate = AppDelegate()
            samlDelegate.attach(model: model, menuBar: MenuBarCoordinator(model: model))
            var samlReplies: [Bool] = []
            samlDelegate.confirmTermination = { true }
            samlDelegate.replyToTermination = { samlReplies.append($0) }
            queued.state = .waitingForSAML
            try require(samlDelegate.terminationReply() == .terminateLater && queued.state == .disconnected && samlReplies == [true], "Fila SAML não liberada ao sair")
            // A tunnel that needs supervisor cleanup: reply only after it confirms exit.
            let tunnelDelegate = AppDelegate()
            tunnelDelegate.attach(model: model, menuBar: MenuBarCoordinator(model: model))
            var tunnelReplies: [Bool] = [], tunnelAsked = 0
            tunnelDelegate.confirmTermination = { tunnelAsked += 1; return true }
            tunnelDelegate.replyToTermination = { tunnelReplies.append($0) }
            active.state = .connected
            try require(tunnelDelegate.terminationReply() == .terminateLater && active.state == .disconnecting && tunnelReplies.isEmpty, "Saiu antes da limpeza")
            try require(tunnelDelegate.terminationReply() == .terminateLater && tunnelAsked == 1, "Pediu confirmação duas vezes")
            model.manager.end(active, exit: 0)
            try require(tunnelReplies == [true] && !model.manager.anyActive, "Não saiu após a limpeza")
        }

        test("Sair: com o ícone na barra, outro app não encerra o TunnelMac sem janela; Dock, sistema e scripts sim") {
            let utility = QuitRequest(senderBundleID: "com.vorssaint.utils", hasSystemReason: false)
            try require(utility.isAutomaticQuit(menuBarIcon: true, windowVisible: false), "Auto quit de terceiro aceito")
            try require(!utility.isAutomaticQuit(menuBarIcon: false, windowVisible: false), "Sem ícone na barra deveria sair")
            try require(!utility.isAutomaticQuit(menuBarIcon: true, windowVisible: true), "Com janela visível deveria sair")
            for request in [QuitRequest(senderBundleID: "com.apple.dock", hasSystemReason: false),
                            QuitRequest(senderBundleID: nil, hasSystemReason: false),
                            QuitRequest(senderBundleID: "com.vorssaint.utils", hasSystemReason: true)] {
                try require(!request.isAutomaticQuit(menuBarIcon: true, windowVisible: false), "Pedido legítimo recusado: \(request)")
            }
            let (model, _) = try makeModel(root, names: ["A"])
            let delegate = AppDelegate()
            let menuBar = MenuBarCoordinator(model: model)
            menuBar.preferences.showMenuBarIcon = true
            delegate.attach(model: model, menuBar: menuBar)
            try require(delegate.terminationReply(request: utility) == .terminateCancel, "Auto quit encerrou o app")
            try require(delegate.terminationReply(request: nil) == .terminateNow, "Sair/⌘Q não encerrou")
        }

        test("Ordem: conexões em ordem alfabética na janela e no menu, sem mudar o arquivo") {
            let names = ["summit", "Cimed", "Écran", "Kyly", "VPN 10", "VPN 2", "Docol"]
            let (model, _) = try makeModel(root, names: names)
            try require(model.sortedConnections.map(\.name) == ["Cimed", "Docol", "Écran", "Kyly", "summit", "VPN 2", "VPN 10"],
                        "Ordem inesperada: \(model.sortedConnections.map(\.name))")
            try require(model.data.connections.map(\.name) == names, "A ordem salva mudou")
        }

        test("Busca: nome, servidor e protocolo sem acento; o campo só aparece quando a lista rola") {
            let connection = Connection(name: "Escritório São Paulo", server: "vpn.exemplo.invalid", port: 443)
            try require(ConnectionSearch.matches(connection, "escritorio sao"), "Acentos/maiúsculas não ignorados")
            try require(ConnectionSearch.matches(connection, "exemplo") && ConnectionSearch.matches(connection, "  "), "Servidor ou busca vazia")
            try require(!ConnectionSearch.matches(connection, "summit"), "Filtro aceitou outra conexão")
            try require(!ConnectionSearch.overflows(count: 6, rowHeight: 40, available: 500), "Lista curta mostrou a busca")
            try require(ConnectionSearch.overflows(count: 14, rowHeight: 40, available: 500), "Lista longa sem busca")
            try require(!ConnectionSearch.overflows(count: 50, rowHeight: 0, available: 500), "Sem medida mostrou a busca")
        }

        test("Janela: fechar só oculta, não encerra sessões, e reabrir reaproveita a mesma janela") {
            let (model, connections) = try makeModel(root, names: ["A"])
            let menuBar = MenuBarCoordinator(model: model)
            menuBar.activateApp = {}
            var policies: [NSApplication.ActivationPolicy] = []
            menuBar.setActivationPolicy = { policies.append($0) }
            var created = 0
            menuBar.openWindowFallback = { created += 1 }
            let delegate = AppDelegate()
            delegate.attach(model: model, menuBar: menuBar)
            let session = model.manager.session(connections[0].id)
            session.state = .connected
            try require(delegate.applicationShouldHandleReopen(NSApplication.shared, hasVisibleWindows: false), "Sem janela, SwiftUI deveria recriá-la")
            menuBar.showMainWindow()
            try require(created == 1, "Fallback de janela não usado")
            let window = NSWindow(contentRect: NSRect(x: -10000, y: -10000, width: 10, height: 10), styleMask: [.titled, .closable], backing: .buffered, defer: true)
            window.isReleasedWhenClosed = false
            let layoutDelegate = LayoutDelegateProbe()
            window.delegate = layoutDelegate
            // The view starts without a window, as it does during SwiftUI creation.
            let binding = MainWindowBinding(delegate: delegate, menuBar: menuBar)
            binding.bindWindow()
            window.contentView?.addSubview(binding)
            try require(menuBar.mainWindow === window && window.delegate is MainWindowCloseDelegate,
                        "A janela não foi associada quando a view entrou na hierarquia")
            try require(window.delegate?.windowWillResize?(window, to: NSSize(width: 100, height: 100)) == NSSize(width: 101, height: 102),
                        "O delegate de fechamento deixou de encaminhar o layout do SwiftUI")
            window.orderFront(nil)
            // Simulate SwiftUI replacing its delegate; a real click on X must still hide.
            window.delegate = nil
            window.standardWindowButton(.closeButton)?.performClick(nil)
            try require(!window.isVisible, "O botão X não ocultou a janela")
            binding.bindWindow()
            window.orderFront(nil)
            window.performClose(nil) // AppKit's close command (also used by Command-W).
            try require(!window.isVisible && window.delegate is MainWindowCloseDelegate,
                        "O comando Fechar não apenas ocultou a janela")
            try require(policies.last == .accessory, "Fechar não removeu o app do Dock")
            try require(session.state == .connected && model.manager.anyActive, "Fechar a janela alterou a conexão")
            try require(!delegate.applicationShouldTerminateAfterLastWindowClosed(NSApplication.shared) || MenuBarCoordinator.isLocalChecks, "Fechar a última janela encerraria o app")
            try require(!delegate.applicationShouldHandleReopen(NSApplication.shared, hasVisibleWindows: false) && window.isVisible && created == 1,
                        "Reabrir criou outra janela")
            try require(policies.last == .regular, "Reabrir não restaurou o app no Dock")
            window.orderOut(nil)
            session.state = .disconnected
        }

        test("Barra de menus: ícone anima só com conexão pendente, parado com Reduzir movimento, badge e nada ao lado") {
            let idle = MenuBarIconState.of(connectedCount: 0, pendingCount: 0, reduceMotion: false, step: 5)
            try require(!idle.spinning && idle.angle == 0 && !idle.connected && idle.badge == 0, "Ícone parado: \(idle)")
            try require(idle.image?.isTemplate == true && idle.image?.size == NSSize(width: 18, height: 18), "Ícone sem túnel não é o template de 18 pt")
            let pending = MenuBarIconState.of(connectedCount: 0, pendingCount: 1, reduceMotion: false, step: 6)
            try require(pending.spinning && pending.angle == 90, "Ícone em andamento: \(pending)")
            let still = MenuBarIconState.of(connectedCount: 0, pendingCount: 1, reduceMotion: true, step: 6)
            try require(!still.spinning && still.angle == 0, "Ícone girou com Reduzir movimento")
            let connected = MenuBarIconState.of(connectedCount: 2, pendingCount: 1, reduceMotion: false, step: 30)
            try require(connected.connected && connected.badge == 2 && connected.angle == 90, "Ícone conectado: \(connected)")
            // Only the mark: no state symbol beside it.
            try require(connected.image?.isTemplate == false && connected.image?.size == NSSize(width: 18, height: 18), "Algo ao lado do ícone")
        }

        test("Barra de menus: a preferência insere e remove o item (host falso), sem eco, e o app fica no Dock") {
            let (model, connections) = try makeModel(root, names: ["A"])
            let preferences = AppPreferences.disposable()
            let menuBar = MenuBarCoordinator(model: model, preferences: preferences)
            var policies: [NSApplication.ActivationPolicy] = []
            menuBar.setActivationPolicy = { policies.append($0) }
            let host = FakeStatusItemHost(), presenter = FakeMenuPresenter()
            menuBar.installMenuBar(host: host, presenter: presenter)
            try require(host.isInserted && host.inserts == 1 && host.label.hasPrefix("TunnelMac"), "Item não inserido com a preferência ligada")
            for _ in 0..<3 { preferences.showMenuBarIcon = true }
            try require(host.inserts == 1 && host.removes == 0, "Escrever o mesmo valor reinseriu o item")
            preferences.showMenuBarIcon = false
            try require(!host.isInserted && host.removes == 1 && policies.last == .regular, "Desligar não removeu o item ou tirou o app do Dock")
            preferences.showMenuBarIcon = false
            try require(host.removes == 1, "Remover duas vezes")
            host.forgetDrawing()
            preferences.showMenuBarIcon = true
            try require(host.isInserted && host.inserts == 2, "Religar não inseriu o item")
            try require(host.image != nil && host.label.hasPrefix("TunnelMac"), "Item religado ficou sem imagem ou rótulo (ícone invisível)")
            // The label follows the summary even when the image stays the same.
            model.error = "erro local"
            _ = TestSupport.spin(0.2) { host.label.contains("erro") }
            try require(host.label.contains("erro"), "Rótulo de acessibilidade não acompanhou o resumo: \(host.label)")
            model.error = nil
            // The icon follows the sessions.
            model.manager.session(connections[0].id).state = .connected
            _ = TestSupport.spin(0.2) { menuBar.statusItem?.lastState?.connected == true }
            try require(menuBar.statusItem?.lastState?.badge == 1 && host.label.contains("1 conectada"), "Ícone não acompanhou a conexão: \(host.label)")
            model.manager.session(connections[0].id).state = .disconnected
            _ = TestSupport.spin(0.2) { menuBar.statusItem?.lastState?.connected == false }
            try require(menuBar.statusItem?.lastState?.connected == false, "Ícone não voltou ao estado parado")
        }

        test("Barra de menus: clique alterna o menu, destaca o botão, e abrir janelas ou um modal fecha ou impede") {
            let (model, _) = try makeModel(root, names: ["A"])
            let menuBar = MenuBarCoordinator(model: model)
            menuBar.activateApp = {}
            menuBar.setActivationPolicy = { _ in }
            var opened = 0, settings = 0
            menuBar.openWindowFallback = { opened += 1 }
            menuBar.openSettingsFallback = { settings += 1 }
            let host = FakeStatusItemHost(), presenter = FakeMenuPresenter()
            menuBar.installMenuBar(host: host, presenter: presenter)
            host.action?()
            try require(presenter.isOpen && menuBar.menuOpen && host.highlighted && presenter.anchors == [host.anchor], "Clique não abriu o menu sob o ícone")
            host.action?()
            try require(!presenter.isOpen && !menuBar.menuOpen && !host.highlighted, "Segundo clique não fechou o menu")
            menuBar.toggleMenu()
            menuBar.showMainWindow()
            try require(!presenter.isOpen && opened == 1, "Abrir TunnelMac não fechou o menu (ou não abriu a janela nunca aberta)")
            menuBar.toggleMenu()
            menuBar.showSettings()
            try require(!presenter.isOpen && settings == 1, "Configurações… não fechou o menu (ou não abriu a janela)")
            // Closed by the panel itself (click outside, ⌘Tab, Space).
            menuBar.toggleMenu()
            presenter.close()
            try require(!menuBar.menuOpen && !host.highlighted, "Fechar pelo painel não atualizou o estado")
            menuBar.hasModalWindow = { true }
            menuBar.toggleMenu()
            try require(!presenter.isOpen && presenter.anchors.count == 4, "O menu abriu sobre um alerta do app")
            // Openers captured by the app's commands win over a hosted view's.
            let fresh = MenuBarCoordinator(model: model)
            var first = 0, second = 0
            fresh.adoptWindowOpeners(main: { first += 1 }, settings: { first += 1 })
            fresh.adoptWindowOpeners(main: { second += 1 }, settings: { second += 1 })
            fresh.openWindowFallback?(); fresh.openSettingsFallback?()
            try require(first == 2 && second == 0, "O abridor do painel substituiu o dos comandos do app")
        }

        test("Barra de menus: posição do painel cabe no visibleFrame (monitor secundário, notch, ícone oculto)") {
            let size = NSSize(width: 360, height: 520)
            let main = NSRect(x: 0, y: 0, width: 1512, height: 944) // under a 38 pt menu bar
            @MainActor func check(_ anchor: MenuAnchor, size: NSSize = size, _ name: String) throws -> NSRect {
                let frame = MenuPanelPlacement.frame(size: size, anchor: anchor)
                let inside = anchor.visibleFrame.insetBy(dx: MenuPanelPlacement.margin - 0.5, dy: -0.5)
                try require(inside.contains(frame), "\(name): \(frame) fora de \(anchor.visibleFrame)")
                return frame
            }
            let button = NSRect(x: 1200, y: 950, width: 30, height: 28)
            var frame = try check(MenuAnchor(button: button, visibleFrame: main), "Ícone no meio")
            try require(frame.minX == button.minX && frame.maxY == button.minY - 6 && frame.width == 360, "Não abriu para a direita a partir do ícone: \(frame)")
            frame = try check(MenuAnchor(button: NSRect(x: 1490, y: 950, width: 22, height: 28), visibleFrame: main), "Ícone na borda direita")
            try require(frame.maxX == main.maxX - 8, "Não respeitou a margem direita: \(frame)")
            // Secondary screen to the left, below the main one, with negative coordinates.
            let left = NSRect(x: -1920, y: -200, width: 1920, height: 1055)
            frame = try check(MenuAnchor(button: NSRect(x: -1900, y: 856, width: 30, height: 24), visibleFrame: left), "Monitor secundário")
            try require(frame.minX == -1900, "Monitor secundário não abriu a partir do ícone: \(frame)")
            frame = try check(MenuAnchor(button: NSRect(x: -1918, y: 856, width: 30, height: 24), visibleFrame: left), "Ícone na borda esquerda")
            try require(frame.minX == left.minX + 8, "Não respeitou a margem esquerda: \(frame)")
            // Hidden icon (preference, Menu Bar settings or the notch): top right corner.
            frame = try check(MenuAnchor(button: nil, visibleFrame: main), "Sem ícone")
            try require(frame.maxX == main.maxX - 8 && frame.maxY == main.maxY - 6, "Sem ícone fora do canto: \(frame)")
            // Taller than the screen: capped at the visible height minus 40.
            frame = try check(MenuAnchor(button: button, visibleFrame: main), size: NSSize(width: 360, height: 3000), "Conteúdo alto")
            try require(frame.height == main.height - 40, "Altura não limitada: \(frame)")
        }

        test("Barra de menus: painel real fora da tela abre sem virar janela principal e fecha ao perder o foco") {
            let (model, _) = try makeModel(root, names: ["A", "B"])
            let menuBar = MenuBarCoordinator(model: model)
            let controller = MenuBarPanelController(menuBar: menuBar)
            var closes = 0
            controller.onClose = { closes += 1 }
            let visible = NSRect(x: -30000, y: -30000, width: 1440, height: 870)
            controller.open(anchor: MenuAnchor(button: NSRect(x: -28700, y: -29125, width: 30, height: 24), visibleFrame: visible))
            _ = TestSupport.spin(0.3) { false }
            let panel = controller.panel
            try require(panel.isVisible && controller.isOpen && visible.contains(panel.frame) && panel.frame.width == 360,
                        "Painel não abriu dentro da tela fictícia: \(panel.frame)")
            try require(panel.canBecomeKey && !panel.canBecomeMain && panel.level == .popUpMenu
                        && panel.styleMask.contains(.nonactivatingPanel) && !panel.hidesOnDeactivate && panel.backgroundColor == .clear,
                        "Configuração do painel")
            try require(panel.frame.height > 100, "Altura do conteúdo não aplicada: \(panel.frame.height)")
            controller.windowDidResignKey(Notification(name: NSWindow.didResignKeyNotification))
            try require(!panel.isVisible && closes == 1, "Perder o foco não fechou o painel")
            controller.close()
            try require(closes == 1, "Fechar duas vezes notificou duas vezes")
        }

        test("Busca no menu: nome, servidor, tipo e cliente sem acento; destaque inicial, setas e ajuste") {
            let office = Connection(name: "Escritório São Paulo", server: "vpn0.invalid", port: 443, username: "a")
            let lab = Connection(name: "Lab", server: "portal.lab.invalid", port: 443, username: "", kind: .globalProtect)
            let home = Connection(name: "Casa", kind: .wireguard)
            let all = [home, office, lab]
            func names(_ query: String) -> [String] { MenuBarSearch.results(all, query: query).map(\.name) }
            try require(names("sao paulo") == ["Escritório São Paulo"] && names("ESCRITORIO") == ["Escritório São Paulo"], "Acento/maiúscula")
            try require(names("forti") == ["Escritório São Paulo"] && names("fortinet") == ["Escritório São Paulo"], "Tipo Fortinet")
            try require(names("openconnect") == ["Lab"] && names("globalprotect") == ["Lab"] && names("portal.lab") == ["Lab"], "Cliente, tipo ou servidor")
            try require(names("wireguard") == ["Casa"] && names("  ") == ["Casa", "Escritório São Paulo", "Lab"], "Ordem da lista ou busca vazia")
            try require(names("zzz").isEmpty, "Sem resultado")
            // Initial highlight.
            try require(MenuBarSearch.initialHighlight(results: [lab], query: "lab", total: 3) == lab.id, "Com texto, o 1º não ficou destacado")
            try require(MenuBarSearch.initialHighlight(results: [home], query: "", total: 1) == home.id, "Uma conexão só não ficou destacada")
            try require(MenuBarSearch.initialHighlight(results: all, query: "", total: 3) == nil, "Com várias e sem texto, algo ficou destacado")
            try require(MenuBarSearch.initialHighlight(results: [], query: "zzz", total: 3) == nil, "Sem resultado com destaque")
            // Arrows: no wrapping.
            try require(MenuBarSearch.move(nil, down: true, in: all) == home.id && MenuBarSearch.move(nil, down: false, in: all) == home.id, "Primeira seta")
            try require(MenuBarSearch.move(home.id, down: true, in: all) == office.id && MenuBarSearch.move(lab.id, down: true, in: all) == lab.id, "↓ deu a volta")
            try require(MenuBarSearch.move(home.id, down: false, in: all) == home.id && MenuBarSearch.move(lab.id, down: false, in: all) == office.id, "↑ deu a volta")
            try require(MenuBarSearch.move(home.id, down: true, in: []) == nil, "Seta sem resultado")
            // The filter removes the highlighted row.
            try require(MenuBarSearch.adjusted(office.id, in: [home, lab]) == home.id, "Destaque removido não foi para a 1ª")
            try require(MenuBarSearch.adjusted(office.id, in: []) == nil && MenuBarSearch.adjusted(nil, in: all) == nil, "Destaque sem resultado")
            try require(MenuBarSearch.adjusted(lab.id, in: all) == lab.id, "Destaque mantido")
        }

        test("Menu: ativas e fixadas no topo, separadas das demais; o pino persiste e as setas seguem essa ordem") {
            let (model, connections) = try makeModel(root, names: ["Alfa", "Beta", "Gama", "Delta"])
            let menuBar = MenuBarCoordinator(model: model)
            menuBar.announce = { _ in }
            let names = { (list: [Connection]) in list.map(\.name) }
            try require(menuBar.searchSections.top.isEmpty && names(menuBar.searchSections.rest) == ["Alfa", "Beta", "Delta", "Gama"], "Sem ativas nem fixadas")
            model.manager.session(connections[2].id).state = .connecting   // Gama active
            menuBar.togglePin(connections[3].id)                             // Delta pinned
            try require(names(menuBar.searchSections.top) == ["Delta", "Gama"] && names(menuBar.searchSections.rest) == ["Alfa", "Beta"],
                        "Topo: \(names(menuBar.searchSections.top)), demais: \(names(menuBar.searchSections.rest))")
            try require(names(menuBar.searchResults) == ["Delta", "Gama", "Alfa", "Beta"], "As setas não seguem a ordem das seções")
            try require(AppPreferences(defaults: menuBar.preferences.defaults).pinnedConnections == [connections[3].id], "Pino não persistiu")
            menuBar.setSearch("a")
            try require(names(menuBar.searchSections.top) == ["Delta", "Gama"] && menuBar.highlightedID == connections[3].id, "Busca não manteve o topo")
            menuBar.togglePin(connections[3].id)
            model.manager.session(connections[2].id).state = .disconnected
            try require(menuBar.searchSections.top.isEmpty && !menuBar.isPinned(connections[3].id), "Desafixar ou desconectar não devolveu às demais")
        }

        test("Busca no menu: Enter segue a regra da linha, ⌘Enter abre a janela, Esc limpa e depois fecha") {
            let (model, connections) = try makeModel(root, names: ["Alfa", "Beta", "Gama", "Delta"])
            let menuBar = MenuBarCoordinator(model: model)
            var connects: [UUID] = [], disconnects: [UUID] = [], opened = 0, beeps = 0
            var spoken: [String] = []
            menuBar.connectAction = { connects.append($0.id) }
            menuBar.disconnectAction = { disconnects.append($0) }
            menuBar.activateApp = {}
            menuBar.setActivationPolicy = { _ in }
            menuBar.openWindowFallback = { opened += 1 }
            menuBar.beep = { beeps += 1 }
            menuBar.announce = { spoken.append($0) }
            let host = FakeStatusItemHost(), presenter = FakeMenuPresenter()
            menuBar.installMenuBar(host: host, presenter: presenter)
            menuBar.showMenu(focusSearch: true)
            try require(menuBar.highlightedID == nil && menuBar.searchFocusRequest > 0, "Ao abrir com várias, algo ficou destacado ou o campo não pediu o foco")
            menuBar.handleMenuKey(.enter)
            try require(beeps == 1 && connects.isEmpty, "Enter distraído ao abrir conectou")
            menuBar.setSearch("alf")
            try require(menuBar.highlightedID == connections[0].id && spoken.last == "1 conexão", "Busca não destacou o 1º ou não anunciou: \(spoken)")
            menuBar.handleMenuKey(.enter)
            try require(connects == [connections[0].id] && presenter.isOpen, ".connect pelo Enter (o menu continua aberto)")
            let session = model.manager.session(connections[0].id)
            session.state = .connected
            menuBar.handleMenuKey(.enter)
            try require(disconnects == [connections[0].id] && presenter.isOpen, ".disconnect pelo Enter")
            session.state = .disconnecting; session.wantsDisconnect = true
            menuBar.handleMenuKey(.enter)
            try require(beeps == 2 && disconnects.count == 1, ".disconnecting não fez só beep")
            session.state = .disconnected; session.wantsDisconnect = false
            model.manager.session(connections[1].id).authenticationRejected = true
            menuBar.setSearch("beta")
            menuBar.handleMenuKey(.enter)
            try require(opened == 1 && menuBar.pendingSelection == connections[1].id && !presenter.isOpen, ".review abriu a janela e fechou o menu")
            // ⌘Enter opens the window on the highlighted row.
            menuBar.showMenu()
            menuBar.handleMenuKey(.down); menuBar.handleMenuKey(.down); menuBar.handleMenuKey(.down)
            // Alphabetical: Alfa, Beta, Delta, Gama.
            try require(menuBar.highlightedID == connections[3].id, "Setas no menu (ordem alfabética): \(String(describing: menuBar.highlightedID))")
            try require(spoken.last?.hasPrefix("Delta, ") == true, "Mudança de destaque não anunciou nome e estado")
            menuBar.handleMenuKey(.commandEnter)
            try require(opened == 2 && menuBar.pendingSelection == connections[3].id && !presenter.isOpen, "⌘Enter não abriu a janela na conexão")
            // Esc: clears the text first, then closes; closing clears the search.
            menuBar.showMenu()
            menuBar.setSearch("ga")
            menuBar.handleMenuKey(.escape)
            try require(presenter.isOpen && menuBar.searchText.isEmpty, "Esc com texto não só limpou")
            menuBar.handleMenuKey(.escape)
            try require(!presenter.isOpen && !menuBar.menuOpen, "Esc sem texto não fechou")
            menuBar.showMenu()
            menuBar.setSearch("zzz")
            try require(menuBar.searchResults.isEmpty && menuBar.highlightedID == nil && spoken.last == "Nenhuma conexão encontrada", "Sem resultados")
            menuBar.handleMenuKey(.enter)
            try require(beeps == 3, "Enter sem resultado não fez beep")
            menuBar.closeMenu()
            try require(menuBar.searchText.isEmpty && menuBar.highlightedID == nil, "Fechar não zerou a busca")
            // Unavailable service: beep.
            let unavailableStore = try JSONStore(directory: root.appendingPathComponent(UUID().uuidString))
            try unavailableStore.save(SavedData(connections: connections))
            let unavailable = MenuBarCoordinator(model: AppModel(store: unavailableStore, passwords: model.passwords,
                                                                 service: ServiceController(policy: .unavailable(reason: "teste"), registrar: nil, client: nil)))
            var unavailableBeeps = 0
            unavailable.beep = { unavailableBeeps += 1 }
            unavailable.announce = { _ in }
            unavailable.setSearch("alfa")
            unavailable.handleMenuKey(.enter)
            try require(unavailableBeeps == 1 && unavailable.action(for: connections[0]) == .unavailable, ".unavailable não fez só beep")
            // One connection: highlighted at once (shortcut + Enter connects).
            let (single, singleConnections) = try makeModel(root, names: ["Só"])
            let one = MenuBarCoordinator(model: single)
            one.announce = { _ in }
            one.installMenuBar(host: FakeStatusItemHost(), presenter: FakeMenuPresenter())
            one.showMenu()
            try require(one.highlightedID == singleConnections[0].id, "Com uma conexão, ela não ficou destacada")
            // The pointer moves the highlight only when it really moved.
            one.pointerHovered(singleConnections[0].id, at: NSPoint(x: 1, y: 1))
            one.highlightedID = nil
            one.pointerHovered(singleConnections[0].id, at: NSPoint(x: 1, y: 1))
            try require(one.highlightedID == nil, "A lista rolando sob o ponteiro parado mudou o destaque")
            one.pointerHovered(singleConnections[0].id, at: NSPoint(x: 2, y: 1))
            try require(one.highlightedID == singleConnections[0].id, "Mover o mouse não destacou a linha")
        }

        test("Busca no menu: ao abrir, o campo é o first responder (painel real fora da tela, host falso) e as teclas chegam") {
            let (model, connections) = try makeModel(root, names: ["A", "B"])
            let menuBar = MenuBarCoordinator(model: model)
            menuBar.announce = { _ in }
            let controller = MenuBarPanelController(menuBar: menuBar)
            menuBar.installMenuBar(host: FakeStatusItemHost(), presenter: controller)
            menuBar.showMenu(focusSearch: true)
            defer { menuBar.closeMenu() }
            _ = TestSupport.spin(2) { controller.searchFieldFocused }
            try require(controller.panel.isVisible && controller.searchFieldFocused,
                        "Campo de busca sem foco ao abrir: \(String(describing: controller.panel.firstResponder))")
            try require(controller.handle(window: controller.panel.windowNumber, keyCode: 125, flags: [.numericPad, .function], characters: nil)
                        && menuBar.highlightedID == connections[0].id, "↓ não chegou à busca")
            try require(!controller.handle(window: controller.panel.windowNumber, keyCode: 48, flags: [], characters: "\t"), "Tab foi interceptado")
            try require(!controller.handle(window: -1, keyCode: 125, flags: [], characters: nil), "Tecla de outra janela interceptada")
            try require(controller.handle(window: controller.panel.windowNumber, keyCode: 53, flags: [], characters: nil) && !controller.isOpen,
                        "Esc sem texto não fechou o painel real")
        }
    }

}

/// Status item stand-in: the local checks never touch the real menu bar.
@MainActor
final class FakeStatusItemHost: StatusItemHost {
    private(set) var isInserted = false
    private(set) var inserts = 0, removes = 0
    private(set) var label = ""
    private(set) var image: NSImage?
    private(set) var highlighted = false
    private(set) var action: (() -> Void)?
    var anchor = MenuAnchor(button: NSRect(x: -28700, y: -29125, width: 30, height: 24),
                            visibleFrame: NSRect(x: -30000, y: -30000, width: 1440, height: 870))
    func insert(action: @escaping () -> Void) { isInserted = true; inserts += 1; self.action = action }
    func remove() { isInserted = false; removes += 1; action = nil }
    /// A new NSStatusItem starts without image or label.
    func forgetDrawing() { image = nil; label = "" }
    func update(image: NSImage?, label: String) { self.image = image; self.label = label }
    func setHighlighted(_ highlighted: Bool) { self.highlighted = highlighted }
}

/// Menu panel stand-in: records where it was asked to open.
@MainActor
final class FakeMenuPresenter: MenuPanelPresenter {
    private(set) var isOpen = false
    private(set) var anchors: [MenuAnchor] = []
    var onClose: (() -> Void)?
    func open(anchor: MenuAnchor) { isOpen = true; anchors.append(anchor) }
    func close() {
        guard isOpen else { return }
        isOpen = false
        onClose?()
    }
}
