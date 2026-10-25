import SwiftUI
import AppKit
import Combine

/// Aggregated state shown by the menu bar icon. An intermediate state never
/// counts as an established tunnel.
enum MenuBarSummary: Equatable {
    case idle, attention, transitioning, connected
    var symbol: String {
        switch self {
        case .idle: return "shield"
        case .attention: return "exclamationmark.shield"
        case .transitioning: return "shield.lefthalf.filled"
        case .connected: return "checkmark.shield.fill"
        }
    }
}

/// What the row button does for a session, using the same criteria as the window.
enum MenuBarRowAction: Equatable {
    case connect, disconnect, disconnecting, review, unavailable
    var title: String {
        switch self {
        case .connect, .unavailable: return "Conectar"
        case .disconnect: return "Desconectar"
        case .disconnecting: return "Desconectando…"
        case .review: return "Revisar acesso…"
        }
    }
    var enabled: Bool { ![.disconnecting, .unavailable].contains(self) }
    @MainActor static func of(_ session: Session, ready: Bool, serviceReady: Bool = true) -> MenuBarRowAction {
        guard ready else { return .unavailable }
        if session.state.active {
            return session.state == .disconnecting && session.wantsDisconnect ? .disconnecting : .disconnect
        }
        if session.authenticationRejected { return .review }
        return serviceReady ? .connect : .unavailable
    }
}

/// Observes the shared AppModel for the menu bar and routes actions to the model
/// or to the main window. It keeps no connection state of its own.
/// Tabs of the Configurações window.
enum SettingsTab: String, CaseIterable, Identifiable, Hashable {
    case general, updates, service, backup, about
    var id: String { rawValue }
    var title: String {
        switch self {
        case .general: return "Geral"
        case .updates: return "Atualizações"
        case .service: return "Serviço privilegiado"
        case .backup: return "Backup"
        case .about: return "Sobre"
        }
    }
    var subtitle: String {
        switch self {
        case .general: return "Barra de menus, Dock e abertura ao iniciar sessão"
        case .updates: return "Verificação de novas versões no GitHub; a instalação é pelo Homebrew"
        case .service: return "O componente do sistema que inicia o openfortivpn, o OpenVPN e o WireGuard por você"
        case .backup: return "Exporte as conexões para outro Mac ou guarde uma cópia, protegida por senha"
        case .about: return "Versão, licença e links do projeto"
        }
    }
    var symbol: String {
        switch self {
        case .general: return "gearshape"
        case .updates: return "arrow.triangle.2.circlepath"
        case .service: return "lock.shield"
        case .backup: return "archivebox"
        case .about: return "info.circle"
        }
    }
}

@MainActor
final class MenuBarCoordinator: ObservableObject {
    static let sceneID = "main"
    static let settingsSceneID = "settings"
    static let windowIdentifier = NSUserInterfaceItemIdentifier("com.luiz.vpngui.main-window")
    static let settingsWindowIdentifier = NSUserInterfaceItemIdentifier("com.luiz.vpngui.settings-window")
    static var isLocalChecks: Bool { Bundle.main.bundleIdentifier?.hasPrefix("com.luiz.vpngui.local-checks") == true }

    let model: AppModel
    let preferences: AppPreferences
    let updates: UpdateChecker
    let loginItem: LoginItemController
    @Published var pendingSelection: UUID?
    /// Tab shown by the Configurações window (also when it is reopened).
    @Published var settingsTab: SettingsTab = .general
    weak var mainWindow: NSWindow?
    weak var settingsWindow: NSWindow? { didSet { observeSettingsClose() } }
    var connectAction: (Connection) -> Void
    var disconnectAction: (UUID) -> Void
    var openWindowFallback: (() -> Void)?
    /// SwiftUI's openWindow(id: "settings"), captured by any view that has it.
    var openSettingsFallback: (() -> Void)?
    var activateApp: () -> Void = { NSApplication.shared.activate(ignoringOtherApps: true) }
    var setActivationPolicy: (NSApplication.ActivationPolicy) -> Void = { _ = NSApp?.setActivationPolicy($0) }
    private var observers = Set<AnyCancellable>()
    private var sessionObservers: [AnyCancellable] = []
    private var settingsCloseObserver: NSObjectProtocol?

    init(model: AppModel, preferences: AppPreferences? = nil, updates: UpdateChecker? = nil,
         loginItem: LoginItemController? = nil) {
        let preferences = preferences ?? updates?.preferences ?? .disposable()
        self.model = model
        self.preferences = preferences
        self.updates = updates ?? UpdateChecker(preferences: preferences, transport: DisabledUpdateTransport())
        self.loginItem = loginItem ?? LoginItemController(service: nil, unavailableReason: "Indisponível neste contexto.")
        connectAction = { [unowned model] in model.connect($0) }
        disconnectAction = { [unowned model] in model.manager.disconnect($0) }
        model.objectWillChange.sink { [weak self] in self?.objectWillChange.send() }.store(in: &observers)
        model.service.objectWillChange.sink { [weak self] in self?.objectWillChange.send() }.store(in: &observers)
        preferences.objectWillChange.sink { [weak self] in self?.objectWillChange.send() }.store(in: &observers)
        self.updates.objectWillChange.sink { [weak self] in self?.objectWillChange.send() }.store(in: &observers)
        self.loginItem.objectWillChange.sink { [weak self] in self?.objectWillChange.send() }.store(in: &observers)
        // Turning the menu bar icon off must never leave the app without a Dock icon.
        preferences.$showMenuBarIcon.dropFirst().sink { [weak self] shown in
            if !shown { self?.setActivationPolicy(.regular) }
        }.store(in: &observers)
        // A @Published change inside a Session does not publish the manager's dictionary,
        // so each session is observed individually. manager.changed stays untouched.
        model.manager.$sessions.sink { [weak self] sessions in
            self?.objectWillChange.send()
            self?.observe(Array(sessions.values))
        }.store(in: &observers)
    }

    private func observe(_ sessions: [Session]) {
        sessionObservers = sessions.map { session in
            Publishers.Merge4(session.$state.dropFirst().map { _ in () },
                              session.$connectedAt.dropFirst().map { _ in () },
                              session.$authenticationRejected.dropFirst().map { _ in () },
                              session.$suggestedCertificate.dropFirst().map { _ in () })
                .sink { [weak self] in self?.objectWillChange.send() }
        }
    }

    private var states: [ConnectionState] { model.manager.sessions.values.map(\.state) }
    var connectedCount: Int { states.filter { $0 == .connected }.count }
    var pendingCount: Int { states.filter { $0.active && $0 != .connected }.count }
    var summary: MenuBarSummary {
        if connectedCount > 0 { return .connected }
        if pendingCount > 0 { return .transitioning }
        if !model.ready || model.error != nil || states.contains(.failed) { return .attention }
        return .idle
    }
    var summaryText: String {
        guard model.ready else { return "Dados não carregados" }
        var parts: [String] = []
        let connected = connectedCount, pending = pendingCount
        if connected > 0 { parts.append(connected == 1 ? "1 conectada" : "\(connected) conectadas") }
        if pending > 0 { parts.append("\(pending) em andamento") }
        if parts.isEmpty { return states.contains(.failed) ? "Nenhuma conexão ativa · falha recente" : "Nenhuma conexão ativa" }
        return parts.joined(separator: " · ")
    }
    var accessibilityDescription: String {
        "TunnelMac: \(summaryText)\(model.error != nil ? ", com erro pendente" : "")"
    }

    /// Names repeated in the list; only these rows show the server to tell them apart.
    var duplicatedNames: Set<String> {
        var seen = Set<String>(), repeated = Set<String>()
        for name in model.data.connections.map({ $0.name.lowercased() }) where !seen.insert(name).inserted { repeated.insert(name) }
        return repeated
    }

    func action(for connection: Connection) -> MenuBarRowAction {
        MenuBarRowAction.of(model.manager.session(connection.id), ready: model.ready, serviceReady: model.service.canConnect)
    }
    func showServiceManagement() { showSettings(.service) }

    /// The single Configurações window, brought to the front on the requested tab.
    func showSettings(_ tab: SettingsTab? = nil) {
        if let tab { settingsTab = tab }
        setActivationPolicy(.regular)
        activateApp()
        if let window = settingsWindow, window.isVisible || window.isMiniaturized {
            if window.isMiniaturized { window.deminiaturize(nil) }
            window.makeKeyAndOrderFront(nil)
        } else if let openSettingsFallback {
            openSettingsFallback() // A closed Window scene is recreated by SwiftUI, once.
        } else {
            settingsWindow?.makeKeyAndOrderFront(nil)
        }
    }

    /// "Verificar atualizações…": ignores the interval and shows the result.
    func checkForUpdates() {
        updates.checkNow()
        showSettings(.updates)
    }

    /// Launch: a hidden menu bar icon with saved preferences keeps the Dock icon.
    func enforceVisibility() {
        if !preferences.showMenuBarIcon { setActivationPolicy(.regular) }
    }

    /// Forwards exactly one action to the model. Review goes to the window.
    func perform(_ connection: Connection) {
        guard model.ready, let current = model.data.connections.first(where: { $0.id == connection.id }) else { return }
        switch action(for: current) {
        case .connect: connectAction(current)
        case .disconnect: disconnectAction(current.id)
        case .review: showMainWindow(selecting: current.id)
        case .disconnecting, .unavailable: break
        }
    }

    /// Shows the single main window, recreating it only if SwiftUI released it.
    func showMainWindow(selecting id: UUID? = nil) {
        if let id { pendingSelection = id }
        setActivationPolicy(.regular)
        activateApp()
        if let window = mainWindow {
            if window.isMiniaturized { window.deminiaturize(nil) }
            window.makeKeyAndOrderFront(nil)
        } else {
            openWindowFallback?()
        }
    }
    func hideMainWindow(_ window: NSWindow) {
        window.orderOut(nil)
        setActivationPolicy(policyAfterHiding(otherWindowVisible: settingsWindow?.isVisible == true))
    }

    /// Same Dock rule for both windows: stay in the Dock while another window is shown
    /// or when the user (or the hidden menu bar icon) keeps it there.
    func policyAfterHiding(otherWindowVisible: Bool) -> NSApplication.ActivationPolicy {
        otherWindowVisible || !preferences.hidesDockOnClose ? .regular : .accessory
    }

    func settingsWindowClosed() {
        settingsWindow = nil
        setActivationPolicy(policyAfterHiding(otherWindowVisible: mainWindow?.isVisible == true))
    }

    private func observeSettingsClose() {
        if let settingsCloseObserver { NotificationCenter.default.removeObserver(settingsCloseObserver) }
        settingsCloseObserver = nil
        guard let settingsWindow else { return }
        settingsCloseObserver = NotificationCenter.default.addObserver(forName: NSWindow.willCloseNotification,
                                                                       object: settingsWindow, queue: nil) { [weak self] _ in
            MainActor.assumeIsolated { self?.settingsWindowClosed() }
        }
    }
}
