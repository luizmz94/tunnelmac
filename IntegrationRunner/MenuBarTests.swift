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
                try require(menuBar.summary == .transitioning && menuBar.connectedCount == 0, "\(state.rawValue) apareceu como conectada")
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
    }

}
