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
        case .connect, .unavailable: return String(localized: "Conectar")
        case .disconnect: return String(localized: "Desconectar")
        case .disconnecting: return String(localized: "Desconectando…")
        case .review: return String(localized: "Revisar acesso…")
        }
    }
    /// Linked chain to connect, broken chain to disconnect.
    var symbol: String {
        switch self {
        case .connect, .unavailable: return "personalhotspot"
        case .disconnect: return "personalhotspot.slash"
        case .disconnecting: return "hourglass"
        case .review: return "person.crop.circle.badge.exclamationmark"
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
        case .general: return String(localized: "Geral")
        case .updates: return String(localized: "Atualizações")
        case .service: return String(localized: "Serviço privilegiado")
        case .backup: return String(localized: "Backup")
        case .about: return String(localized: "Sobre")
        }
    }
    /// Glyph and color of the tab's tile in the sidebar, as in System Settings.
    var symbol: String {
        switch self {
        case .general: return "gearshape.fill"
        case .updates: return "arrow.triangle.2.circlepath"
        case .service: return "lock.shield.fill"
        case .backup: return "archivebox.fill"
        case .about: return "info"
        }
    }
    var tileColor: Color {
        switch self {
        case .general, .about: return .gray
        case .updates: return .blue
        case .service: return .green
        case .backup: return .orange
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
    let installer: AppUpdater
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
    /// The app's own modal alert (Sair, errors): the menu does not open over it.
    var hasModalWindow: () -> Bool = { NSApp?.modalWindow != nil }
    /// The menu bar icon and its menu panel; nil in the local checks unless a fake is installed.
    private(set) var statusItem: MenuBarStatusItem?
    private(set) var menuPresenter: MenuPanelPresenter?
    @Published private(set) var menuOpen = false
    /// Menu search: cleared every time the menu closes. Never logged.
    @Published private(set) var searchText = ""
    @Published var highlightedID: UUID?
    /// Bumped to put the keyboard focus in the search field (opening, ⌘F).
    @Published private(set) var searchFocusRequest = 0
    var beep: () -> Void = { NSSound.beep() }
    /// VoiceOver announcement (the search field keeps the focus while the results change).
    var announce: (String) -> Void = { text in
        NSAccessibility.post(element: NSApp as Any, notification: .announcementRequested,
                             userInfo: [.announcement: text, .priority: NSAccessibilityPriorityLevel.high.rawValue])
    }
    private var lastPointer: NSPoint?
    /// Cards of the progress panel and the panel itself (a fake in the local checks).
    let progress = ConnectionProgressCenter()
    private(set) var progressPresenter: ProgressPanelPresenter?
    /// Global shortcut and its recorder; nil in the local checks unless fakes are installed.
    private(set) var hotKeys: GlobalHotKeyCenter?
    private(set) var shortcutRecorder: ShortcutRecorderModel?
    var setActivationPolicy: (NSApplication.ActivationPolicy) -> Void = { _ = NSApp?.setActivationPolicy($0) }
    private var observers = Set<AnyCancellable>()
    private var sessionObservers: [AnyCancellable] = []
    private var settingsCloseObserver: NSObjectProtocol?

    init(model: AppModel, preferences: AppPreferences? = nil, updates: UpdateChecker? = nil,
         installer: AppUpdater? = nil, loginItem: LoginItemController? = nil) {
        let preferences = preferences ?? updates?.preferences ?? .disposable()
        self.model = model
        self.preferences = preferences
        let updates = updates ?? UpdateChecker(preferences: preferences, transport: DisabledUpdateTransport())
        self.updates = updates
        self.installer = installer ?? AppUpdater(checker: updates, enabled: false)
        self.loginItem = loginItem ?? LoginItemController(service: nil, unavailableReason: String(localized: "Indisponível neste contexto."))
        connectAction = { [unowned model] in model.connect($0) }
        disconnectAction = { [unowned model] in model.manager.disconnect($0) }
        model.objectWillChange.sink { [weak self] in self?.objectWillChange.send() }.store(in: &observers)
        model.service.objectWillChange.sink { [weak self] in self?.objectWillChange.send() }.store(in: &observers)
        preferences.objectWillChange.sink { [weak self] in self?.objectWillChange.send() }.store(in: &observers)
        self.updates.objectWillChange.sink { [weak self] in self?.objectWillChange.send() }.store(in: &observers)
        self.installer.objectWillChange.sink { [weak self] in self?.objectWillChange.send() }.store(in: &observers)
        self.loginItem.objectWillChange.sink { [weak self] in self?.objectWillChange.send() }.store(in: &observers)
        // Windows, sheets and the menu bar window all take the chosen appearance.
        preferences.$appearance.sink { NSApp?.appearance = $0.nsAppearance }.store(in: &observers)
        // Turning the menu bar icon off must never leave the app without a Dock icon.
        preferences.$showMenuBarIcon.dropFirst().sink { [weak self] shown in
            if !shown { self?.setActivationPolicy(.regular) }
        }.store(in: &observers)
        // A @Published change inside a Session does not publish the manager's dictionary,
        // so each session is observed individually. manager.changed stays untouched.
        progress.announce = { [weak self] in self?.announce($0) }
        progress.objectWillChange.sink { [weak self] in
            DispatchQueue.main.async { self?.updateProgressPanel() }
        }.store(in: &observers)
        preferences.$showConnectionProgress.dropFirst().removeDuplicates().sink { [weak self] shown in
            if !shown { self?.progress.disable() }
        }.store(in: &observers)
        model.$data.dropFirst().sink { [weak self] _ in
            DispatchQueue.main.async { self?.searchResultsChanged() }
        }.store(in: &observers)
        model.manager.$sessions.sink { [weak self] sessions in
            self?.objectWillChange.send()
            self?.observe(Array(sessions.values))
        }.store(in: &observers)
    }

    private func observe(_ sessions: [Session]) {
        // Every state change of every session, whatever started it (menu, window, search,
        // shortcut or an automatic reconnect), reaches the progress panel.
        let progressObservers = sessions.map { session in
            session.$state.sink { [weak self, weak session] state in
                guard let self, let session else { return }
                self.progress.sessionChanged(session, to: state, connection: self.model.data.connections.first { $0.id == session.id },
                                             enabled: self.preferences.showConnectionProgress)
            }
        }
        sessionObservers = progressObservers + sessions.map { session in
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
        guard model.ready else { return String(localized: "Dados não carregados") }
        var parts: [String] = []
        let connected = connectedCount, pending = pendingCount
        if connected > 0 { parts.append(String(localized: "\(connected) conectadas")) }
        if pending > 0 { parts.append(String(localized: "\(pending) em andamento")) }
        if parts.isEmpty { return states.contains(.failed) ? String(localized: "Nenhuma conexão ativa · falha recente") : String(localized: "Nenhuma conexão ativa") }
        return parts.joined(separator: " · ")
    }
    var accessibilityDescription: String {
        model.error != nil ? String(localized: "TunnelMac: \(summaryText), com erro pendente") : "TunnelMac: \(summaryText)"
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

    // MARK: Menu

    /// Installs the icon and its menu. The app passes the real ones (never in the local
    /// checks); the checks pass fakes.
    func installMenuBar(host: StatusItemHost, presenter: MenuPanelPresenter) {
        presenter.onClose = { [weak self] in self?.menuDidClose() }
        menuPresenter = presenter
        statusItem = MenuBarStatusItem(menuBar: self, host: host)
    }

    /// Click on the icon (and, later, the global shortcut): opens or closes the menu.
    func toggleMenu(focusSearch: Bool = false) {
        if menuPresenter?.isOpen == true { closeMenu() } else { showMenu(focusSearch: focusSearch) }
    }

    func showMenu(focusSearch: Bool = false) {
        guard let menuPresenter, let statusItem, !menuPresenter.isOpen, !hasModalWindow() else { return }
        activeWhenOpened = Set(model.manager.sessions.values.filter { $0.state.active }.map(\.id))
        resetSearch()
        lastPointer = NSEvent.mouseLocation
        menuPresenter.open(anchor: statusItem.host.anchor)
        menuOpen = true
        updateProgressPanel()
        // The search field takes the keyboard whenever the menu opens, by click or shortcut.
        searchFocusRequest += 1
        statusItem.host.setHighlighted(true)
    }

    func closeMenu() { menuPresenter?.close() }

    private func menuDidClose() {
        activeWhenOpened = nil
        menuOpen = false
        updateProgressPanel()
        searchText = ""
        highlightedID = nil
        statusItem?.host.setHighlighted(false)
    }

    func installHotKeys(_ center: GlobalHotKeyCenter) {
        hotKeys = center
        shortcutRecorder = ShortcutRecorderModel(center: center)
    }

    // MARK: Progress panel

    func installProgressPanel(_ presenter: ProgressPanelPresenter) {
        progressPresenter = presenter
        updateProgressPanel()
    }

    /// Hidden while the menu is open (it shows the same states); back when it closes if
    /// something is still in progress.
    func updateProgressPanel() {
        guard let progressPresenter else { return }
        if ConnectionProgressModel.shown(cards: progress.model.cards.count, enabled: preferences.showConnectionProgress, menuOpen: menuOpen) {
            progressPresenter.show(anchor: progressAnchor)
        } else {
            progressPresenter.hide()
        }
    }

    /// Cancelar on a progress card: the same as turning the connection off in the menu (also
    /// cancels a reconnect and the SAML queue).
    func cancelProgress(_ id: UUID) { disconnectAction(id) }

    /// The top right corner of the screen with the menu bar, where other apps' notifications appear.
    private var progressAnchor: MenuAnchor {
        let frame = NSScreen.screens.first?.visibleFrame ?? statusItem?.host.anchor.visibleFrame ?? NSRect(x: 0, y: 0, width: 1440, height: 900)
        return MenuAnchor(button: nil, visibleFrame: frame)
    }

    // MARK: Search

    /// Pinned and active connections on top, the rest below; the keyboard follows this order.
    var searchSections: (top: [Connection], rest: [Connection]) {
        guard model.ready else { return ([], []) }
        return MenuBarSearch.sections(MenuBarSearch.results(model.sortedConnections, query: searchText), onTop: isOnTop)
    }
    var searchResults: [Connection] { let sections = searchSections; return sections.top + sections.rest }

    func isPinned(_ id: UUID) -> Bool { preferences.pinnedConnections.contains(id) }
    /// Active connections when the menu opened: while it is open, a connection that connects or
    /// disconnects keeps its place, so no row moves under the pointer (a click could hit
    /// another connection's switch). Pins apply at once: the user just asked for them.
    private var activeWhenOpened: Set<UUID>?
    private func isOnTop(_ connection: Connection) -> Bool {
        if isPinned(connection.id) { return true }
        if let activeWhenOpened { return activeWhenOpened.contains(connection.id) }
        return model.manager.session(connection.id).state.active
    }

    /// Pins a connection to the top of the menu, or unpins it.
    func togglePin(_ id: UUID) {
        if isPinned(id) { preferences.pinnedConnections.removeAll { $0 == id } } else { preferences.pinnedConnections.append(id) }
    }
    var searchAvailable: Bool { model.ready && !model.data.connections.isEmpty }

    func setSearch(_ text: String) {
        guard text != searchText else { return }
        searchText = text
        let results = searchResults
        highlightedID = MenuBarSearch.initialHighlight(results: results, query: text, total: model.data.connections.count)
        announce(results.isEmpty ? String(localized: "Nenhuma conexão encontrada") : String(localized: "\(results.count) conexões"))
    }

    private func resetSearch() {
        searchText = ""
        highlightedID = MenuBarSearch.initialHighlight(results: searchResults, query: "", total: model.data.connections.count)
    }

    /// The list changed under the search (a connection added or removed).
    func searchResultsChanged() {
        highlightedID = MenuBarSearch.adjusted(highlightedID, in: searchResults)
    }

    /// Highlight under the pointer, only when the mouse really moved (not when the list
    /// scrolls under a still pointer).
    func pointerHovered(_ id: UUID, at location: NSPoint = NSEvent.mouseLocation) {
        guard location != lastPointer else { return }
        lastPointer = location
        highlight(id)
    }

    private func highlight(_ id: UUID?) {
        guard id != highlightedID else { return }
        highlightedID = id
        guard let id, let connection = model.data.connections.first(where: { $0.id == id }) else { return }
        announce(String(localized: "\(connection.name), \(model.manager.session(id).state.title)"))
    }

    /// Keys of the search field. Returns false for keys left to the field.
    @discardableResult
    func handleMenuKey(_ key: MenuKey) -> Bool {
        let results = searchResults
        let highlighted = results.first { $0.id == highlightedID }
        switch key {
        case .up, .down:
            highlight(MenuBarSearch.move(highlightedID, down: key == .down, in: results))
        case .enter:
            guard let highlighted else { beep(); return true }
            switch action(for: highlighted) {
            // The menu stays open to watch the state change; Esc closes it.
            case .connect, .disconnect, .review: perform(highlighted)
            case .disconnecting, .unavailable: beep()
            }
        case .commandEnter:
            guard let highlighted else { beep(); return true }
            showMainWindow(selecting: highlighted.id)
        case .escape:
            if searchText.isEmpty { closeMenu() } else { setSearch("") }
        case .find:
            searchFocusRequest += 1
        }
        return true
    }

    /// SwiftUI's window openers, captured where they are reliable (the app's commands); a
    /// hosted view outside a scene may not have a working openWindow.
    func adoptWindowOpeners(main: @escaping () -> Void, settings: @escaping () -> Void) {
        if openWindowFallback == nil { openWindowFallback = main }
        if openSettingsFallback == nil { openSettingsFallback = settings }
    }

    /// The single Configurações window, brought to the front on the requested tab.
    func showSettings(_ tab: SettingsTab? = nil) {
        closeMenu()
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

    /// "Atualizar": installs in the app when Sparkle is available, else shows how to update.
    func installUpdate() {
        guard let offer = updates.offer, installer.available else { return showSettings(.updates) }
        installer.install(offer)
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
        closeMenu()
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
