import SwiftUI
import AppKit
import Security
import VPNHelperShared

/// Who asked AppKit to quit, read from the quit Apple event being handled. Sair and ⌘Q
/// call terminate directly and carry no event.
struct QuitRequest: Equatable {
    /// Bundle id of the sending app; nil for command-line tools (osascript, brew).
    var senderBundleID: String?
    /// True only for a Sparkle updater process signed by our Apple team.
    var isTrustedUpdater = false
    /// Logout, restart or shutdown.
    var hasSystemReason: Bool

    /// Apps whose quit is always a user's or the system's request.
    static let trustedSenders: Set<String> = ["com.apple.dock", "com.apple.loginwindow", "com.apple.ActivityMonitor",
                                              "com.apple.systemevents", "com.apple.ScriptEditor2", "com.apple.Terminal"]

    /// A quit sent by another app while only the menu bar icon is left: that is a
    /// window-based auto quit, not the user leaving TunnelMac.
    func isAutomaticQuit(menuBarIcon: Bool, windowVisible: Bool, updaterBusy: Bool = false) -> Bool {
        if isTrustedUpdater && updaterBusy { return false }
        guard menuBarIcon, !windowVisible, !hasSystemReason, let senderBundleID else { return false }
        return !Self.trustedSenders.contains(senderBundleID)
    }

    @MainActor static func current() -> QuitRequest? {
        guard let event = NSAppleEventManager.shared().currentAppleEvent,
              event.eventClass == AEEventClass(kCoreEventClass), event.eventID == AEEventID(kAEQuitApplication),
              let pid = event.attributeDescriptor(forKeyword: AEKeyword(keySenderPIDAttr))?.int32Value,
              pid != ProcessInfo.processInfo.processIdentifier else { return nil }
        let sender = NSRunningApplication(processIdentifier: pid)
        return QuitRequest(senderBundleID: sender?.bundleIdentifier,
                           isTrustedUpdater: sender?.bundleIdentifier == "org.sparkle-project.Sparkle.Updater"
                               && trustedUpdater(pid: pid),
                           hasSystemReason: event.paramDescriptor(forKeyword: AEKeyword(kAEQuitReason)) != nil)
    }
    /// Sparkle copies Updater.app to its cache before launching it. Authenticate the
    /// running sender, not its path or self-reported bundle ID. Ad hoc builds fail closed.
    private static func trustedUpdater(pid: pid_t) -> Bool {
        guard case .trusted(let team) = CodeTrust.localPolicy() else { return false }
        var code: SecCode?
        let attributes = [kSecGuestAttributePid as String: NSNumber(value: pid)] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess,
              let code else { return false }
        var requirement: SecRequirement?
        let text = CodeTrust.requirement(identifier: "org.sparkle-project.Sparkle.Updater", team: team)
        guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess,
              let requirement else { return false }
        return SecCodeCheckValidity(code, [], requirement) == errSecSuccess
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate, NSWindowDelegate {
    var model: AppModel?
    var menuBar: MenuBarCoordinator?
    // Injectable for local checks; production asks with an alert and replies to AppKit.
    var confirmTermination: () -> Bool = AppDelegate.askToDisconnect
    var replyToTermination: (Bool) -> Void = { ok in
        DispatchQueue.main.async { NSApp.reply(toApplicationShouldTerminate: ok) }
    }
    private var awaitingTermination = false
    static weak var current: AppDelegate? // NSApp.delegate is SwiftUI's own adaptor.
    func attach(model: AppModel, menuBar: MenuBarCoordinator) {
        AppDelegate.current = self
        self.model = model
        self.menuBar = menuBar
    }
    // The red button only hides the main window: the app, the menu bar and the tunnels
    // stay as they are. Quitting is done by Sair, ⌘Q or the system.
    func windowShouldClose(_ sender: NSWindow) -> Bool {
        if let menuBar { menuBar.hideMainWindow(sender) }
        else { sender.orderOut(nil) }
        return false
    }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        terminationReply(request: QuitRequest.current())
    }
    func terminationReply(request: QuitRequest? = nil) -> NSApplication.TerminateReply {
        // Utilities that quit apps without windows (e.g. Vorssaint's auto quit) would take
        // the menu bar icon with them; the user quits with Sair, ⌘Q, the Dock or a script.
        if let request, let menuBar, request.isAutomaticQuit(menuBarIcon: menuBar.preferences.showMenuBarIcon,
                                                              windowVisible: menuBar.mainWindow?.isVisible == true,
                                                              updaterBusy: menuBar.installer.busy) {
            return .terminateCancel
        }
        guard let model, model.manager.anyActive else { return .terminateNow }
        if awaitingTermination { return .terminateLater }
        guard confirmTermination() else {
            menuBar?.installer.quitCancelled()
            return .terminateCancel
        }
        awaitingTermination = true
        model.manager.changed = { [weak self] in
            guard let self, self.awaitingTermination, !model.manager.anyActive else { return }
            self.awaitingTermination = false
            self.replyToTermination(true)
        }
        model.manager.disconnectAll()
        DispatchQueue.main.asyncAfter(deadline: .now() + 30) { [weak self] in
            guard let self, self.awaitingTermination else { return }
            self.awaitingTermination = false
            model.error = "Encerramento e limpeza não confirmados em 30 s. O app permanece aberto; verifique o serviço antes de sair novamente."
            self.menuBar?.installer.quitCancelled()
            self.replyToTermination(false)
        }
        return .terminateLater
    }
    private static func askToDisconnect() -> Bool {
        NSApp.activate(ignoringOtherApps: true) // The window may be hidden; keep the alert visible.
        let alert = NSAlert()
        alert.messageText = "Desconectar e sair?"
        alert.informativeText = "Há conexões ativas, em andamento ou com reconexão agendada. O app aguardará o encerramento e a limpeza das VPNs antes de sair."
        alert.addButton(withTitle: "Desconectar e sair")
        alert.addButton(withTitle: "Cancelar")
        return alert.runModal() == .alertFirstButtonReturn
    }
    // Only the local checks runner quits with its window; the app stays in the menu bar.
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { MenuBarCoordinator.isLocalChecks }
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        guard let menuBar, menuBar.mainWindow != nil else { return true } // SwiftUI recreates the window.
        menuBar.showMainWindow()
        return false
    }
}

public struct VPNGUIApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var delegate
    @StateObject private var model: AppModel
    @StateObject private var menuBar: MenuBarCoordinator
    @StateObject private var preferences: AppPreferences
    public init() {
        if CommandLine.arguments.contains(where: [Maintenance.argument, Maintenance.legacyMigrationArgument].contains) {
            exit(Maintenance.run())
        }
        signal(SIGPIPE, SIG_IGN) // A closed control socket returns EPIPE instead of terminating the app.
        // One AppModel (and VPNManager) shared by the window and the menu bar.
        let model = AppModel()
        model.service.refresh() // Read-only: registration status and authenticated handshake.
        let preferences = AppPreferences.forCurrentProcess()
        model.manager.internetDNS = { [weak preferences] in preferences?.internetDNSServers }
        let updates = UpdateChecker.production(preferences: preferences)
        let installer = AppUpdater.production(checker: updates) { NSApplication.shared.activate(ignoringOtherApps: true) }
        updates.onLaunchOffer = { [weak installer] in installer?.present($0) }
        let menuBar = MenuBarCoordinator(model: model, preferences: preferences, updates: updates,
                                         installer: installer, loginItem: .production())
        // NSApp does not exist yet inside App.init; with the menu bar icon off, applying the
        // Dock policy here crashed at launch (0.3.0-rc.4 to 0.5.0). Apply it once AppKit runs.
        DispatchQueue.main.async { menuBar.enforceVisibility() }
        if !MenuBarCoordinator.isLocalChecks {
            model.onUserConnect = { [weak updates] in updates?.checkIfDue() }
            // After the interface is ready; the request runs in the background.
            DispatchQueue.main.asyncAfter(deadline: .now() + 5) { [weak updates] in
                updates?.checkOnLaunch()
                updates?.startTimer()
            }
        }
        _model = StateObject(wrappedValue: model)
        _menuBar = StateObject(wrappedValue: menuBar)
        _preferences = StateObject(wrappedValue: preferences)
    }
    public var body: some Scene {
        WindowGroup("TunnelMac · \(HelperConstants.version)", id: MenuBarCoordinator.sceneID) {
                MainView(model: model, menuBar: menuBar)
                    .frame(minWidth: 850, minHeight: 550)
                    .onAppear { delegate.attach(model: model, menuBar: menuBar) }
                    .background(WindowCloseGuard(delegate: delegate, menuBar: menuBar))
        }
        .commands {
            CommandGroup(replacing: .newItem) {}
            AppCommands(menuBar: menuBar)
        }
        Window("Configurações", id: MenuBarCoordinator.settingsSceneID) {
            SettingsView(menuBar: menuBar)
                .background(SettingsWindowBinding(menuBar: menuBar))
        }
        .defaultSize(width: 760, height: 540)
        // Not inserted in the local checks runner, so it still quits on its own.
        MenuBarExtra(isInserted: preferences.menuBarIconBinding(enabled: !MenuBarCoordinator.isLocalChecks)) {
            MenuBarView(menuBar: menuBar)
        } label: {
            MenuBarLabel(menuBar: menuBar)
                .onAppear { delegate.attach(model: model, menuBar: menuBar) }
        }
        .menuBarExtraStyle(.window)
    }
}

/// App menu: Sobre, Verificar atualizações…, separator, Configurações… ⌘,
struct AppCommands: Commands {
    let menuBar: MenuBarCoordinator
    @Environment(\.openWindow) private var openWindow
    var body: some Commands {
        CommandGroup(after: .appInfo) {
            Button("Verificar atualizações…") {
                register()
                menuBar.checkForUpdates()
            }
        }
        CommandGroup(replacing: .appSettings) {
            Button("Configurações…") {
                register()
                menuBar.showSettings()
            }
            .keyboardShortcut(",", modifiers: .command)
        }
    }
    private func register() {
        let open = openWindow
        if menuBar.openSettingsFallback == nil {
            menuBar.openSettingsFallback = { open(id: MenuBarCoordinator.settingsSceneID) }
        }
    }
}

/// Registers the Configurações window (single instance) so reopening brings it forward
/// and closing applies the Dock rule.
struct SettingsWindowBinding: NSViewRepresentable {
    let menuBar: MenuBarCoordinator
    func makeNSView(context: Context) -> SettingsWindowView { SettingsWindowView(menuBar: menuBar) }
    func updateNSView(_ view: SettingsWindowView, context: Context) { view.bind() }
}

final class SettingsWindowView: NSView {
    private let menuBar: MenuBarCoordinator
    init(menuBar: MenuBarCoordinator) {
        self.menuBar = menuBar
        super.init(frame: .zero)
    }
    required init?(coder: NSCoder) { nil }
    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        bind()
    }
    func bind() {
        guard let window, menuBar.settingsWindow !== window else { return }
        window.identifier = MenuBarCoordinator.settingsWindowIdentifier
        window.tabbingMode = .disallowed
        window.minSize = NSSize(width: 640, height: 440)
        menuBar.settingsWindow = window
    }
}

// Closing hides the main window; registers it (by reference, not title) for reopening.
struct WindowCloseGuard: NSViewRepresentable {
    let delegate: AppDelegate
    let menuBar: MenuBarCoordinator
    func makeNSView(context: Context) -> MainWindowBinding {
        MainWindowBinding(delegate: delegate, menuBar: menuBar)
    }
    func updateNSView(_ view: MainWindowBinding, context: Context) {
        view.bindWindow()
    }
}

/// SwiftUI can attach a representable to its window after updateNSView has run,
/// and may replace the window delegate. Bind at attachment and give the red
/// button its own hide action so it never depends on SwiftUI's close handling.
final class MainWindowBinding: NSView {
    private let appDelegate: AppDelegate
    private let menuBar: MenuBarCoordinator
    private var closeDelegate: MainWindowCloseDelegate?

    init(delegate: AppDelegate, menuBar: MenuBarCoordinator) {
        self.appDelegate = delegate
        self.menuBar = menuBar
        super.init(frame: .zero)
    }
    required init?(coder: NSCoder) { nil }


    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        bindWindow()
    }

    func bindWindow() {
        guard let window else { return }
        appDelegate.attach(model: menuBar.model, menuBar: menuBar)
        // Keep SwiftUI's own delegate for layout, toolbar and resizing callbacks.
        if window.delegate !== closeDelegate || closeDelegate == nil {
            let proxy = MainWindowCloseDelegate(appDelegate: appDelegate, original: window.delegate)
            closeDelegate = proxy
            window.delegate = proxy
        }
        window.identifier = MenuBarCoordinator.windowIdentifier
        menuBar.mainWindow = window
        Self.enforceSidebarMinimum(in: window)
        DispatchQueue.main.async { [weak window] in if let window { Self.enforceSidebarMinimum(in: window) } }
        if let closeButton = window.standardWindowButton(.closeButton) {
            closeButton.target = self
            closeButton.action = #selector(hideWindow(_:))
        }
    }

    /// macOS 13–15 restore the split view's saved sidebar width even when it is below
    /// navigationSplitViewColumnWidth(min:), hiding the sidebar's toolbar buttons.
    static func enforceSidebarMinimum(in window: NSWindow, width: CGFloat = MainView.sidebarMinimum) {
        guard let split = window.contentView.flatMap(splitView(in:)), let sidebar = split.arrangedSubviews.first else { return }
        if let controller = split.delegate as? NSSplitViewController, let item = controller.splitViewItems.first {
            item.minimumThickness = max(item.minimumThickness, width)
        }
        if !split.isSubviewCollapsed(sidebar), sidebar.frame.width < width { split.setPosition(width, ofDividerAt: 0) }
    }

    private static func splitView(in view: NSView) -> NSSplitView? {
        if let split = view as? NSSplitView, split.isVertical { return split }
        for subview in view.subviews { if let found = splitView(in: subview) { return found } }
        return nil
    }

    @objc private func hideWindow(_ sender: Any?) {
        guard let window else { return }
        menuBar.hideMainWindow(window)
    }
}

/// Intercept only close, forwarding all other optional NSWindowDelegate methods
/// to the delegate installed by SwiftUI.
final class MainWindowCloseDelegate: NSObject, NSWindowDelegate {
    private weak var appDelegate: AppDelegate?
    private weak var original: NSWindowDelegate?
    init(appDelegate: AppDelegate, original: NSWindowDelegate?) {
        self.appDelegate = appDelegate
        self.original = original
    }
    func windowShouldClose(_ sender: NSWindow) -> Bool {
        appDelegate?.windowShouldClose(sender) ?? false
    }
    override func responds(to selector: Selector!) -> Bool {
        super.responds(to: selector) || original?.responds(to: selector) == true
    }
    override func forwardingTarget(for selector: Selector!) -> Any? {
        if original?.responds(to: selector) == true { return original }
        return super.forwardingTarget(for: selector)
    }
}
