import SwiftUI
import AppKit
import Combine

// The menu bar icon is our own NSStatusItem and the menu our own NSPanel: a MenuBarExtra
// cannot be opened, focused or closed from code (macOS 13–27), and the search and the global
// shortcut need all three. The local checks drive both through the protocols below with
// fakes; they never create a status item.

/// Where the menu opens: under the icon's button, or (no visible button) in the top right
/// corner of the screen with the pointer.
struct MenuAnchor: Equatable {
    /// The button in screen coordinates; nil when hidden by the preference, by System
    /// Settings › Menu Bar or behind the notch.
    var button: NSRect?
    /// Visible frame of the button's screen (or of the pointer's screen without a button).
    var visibleFrame: NSRect
}

/// Creates and removes the status item and draws its button.
@MainActor protocol StatusItemHost: AnyObject {
    var isInserted: Bool { get }
    func insert(action: @escaping () -> Void)
    func remove()
    func update(image: NSImage?, label: String)
    func setHighlighted(_ highlighted: Bool)
    var anchor: MenuAnchor { get }
}

/// Shows and hides the menu panel.
@MainActor protocol MenuPanelPresenter: AnyObject {
    var isOpen: Bool { get }
    /// Called whenever the panel closes, whoever closed it.
    var onClose: (() -> Void)? { get set }
    func open(anchor: MenuAnchor)
    func close()
}

/// Position of the menu panel: top edge 6 pt under the button, opening to the right from the
/// button's left edge like other menu bar apps, kept 8 pt inside the visible frame; without a
/// button, the top right corner of that frame.
enum MenuPanelPlacement {
    static let gap: CGFloat = 6, margin: CGFloat = 8

    static func frame(size: NSSize, anchor: MenuAnchor) -> NSRect {
        let visible = anchor.visibleFrame
        let height = min(size.height, max(visible.height - 40, 1))
        let top = min(anchor.button.map { $0.minY - gap } ?? visible.maxY - gap, visible.maxY)
        let left = anchor.button?.minX ?? visible.maxX - margin - size.width
        let x = min(max(left, visible.minX + margin), visible.maxX - margin - size.width)
        let y = max(top - height, visible.minY)
        return NSRect(x: x, y: y, width: size.width, height: height)
    }
}

/// What the icon shows: the brand mark (in color with a tunnel up), turned during transitions
/// (never with Reduce Motion) and the connected count in a badge. Nothing else beside it.
struct MenuBarIconState: Equatable {
    static let steps = 24
    static let interval: TimeInterval = 0.125
    var connected: Bool
    var angle: CGFloat
    var badge: Int
    var spinning: Bool

    static func of(connectedCount: Int, pendingCount: Int, reduceMotion: Bool, step: Int) -> MenuBarIconState {
        let spinning = pendingCount > 0 && !reduceMotion
        return MenuBarIconState(connected: connectedCount > 0,
                                angle: spinning ? CGFloat(step % steps) * 360 / CGFloat(steps) : 0,
                                badge: connectedCount,
                                spinning: spinning)
    }

    /// The mark (a template while no tunnel is up).
    @MainActor var image: NSImage? { BrandAssets.menuIcon(connected: connected, angle: angle, badge: badge) }
}

/// The app's menu bar icon: inserted and removed with "Ícone na barra de menus", redrawn as
/// the connections change and turned by hand only while one is starting or stopping.
@MainActor
final class MenuBarStatusItem {
    private unowned let menuBar: MenuBarCoordinator
    let host: StatusItemHost
    private var observers = Set<AnyCancellable>()
    private var step = 0
    private var timer: Timer?
    private var refreshQueued = false
    private(set) var lastState: MenuBarIconState?
    private var lastLabel: String?
    /// Injectable for the checks.
    var reduceMotion: () -> Bool = { NSWorkspace.shared.accessibilityDisplayShouldReduceMotion }

    init(menuBar: MenuBarCoordinator, host: StatusItemHost) {
        self.menuBar = menuBar
        self.host = host
        // Only real changes reach the host: no insert or remove echo.
        menuBar.preferences.$showMenuBarIcon.removeDuplicates().sink { [weak self] shown in
            self?.apply(shown: shown)
        }.store(in: &observers)
        menuBar.objectWillChange.sink { [weak self] in self?.queueRefresh() }.store(in: &observers)
        NSWorkspace.shared.notificationCenter.publisher(for: NSWorkspace.accessibilityDisplayOptionsDidChangeNotification)
            .sink { [weak self] _ in self?.queueRefresh() }.store(in: &observers)
    }

    private func apply(shown: Bool) {
        if shown, !host.isInserted {
            host.insert { [weak self] in self?.menuBar.toggleMenu() }
            // A new item has no image yet: draw it whatever was drawn on the previous one.
            lastState = nil
            lastLabel = nil
            refresh()
        } else if !shown, host.isInserted {
            stopSpinning()
            host.remove()
        }
    }

    /// objectWillChange fires before the change; read the new state on the next turn.
    private func queueRefresh() {
        guard !refreshQueued else { return }
        refreshQueued = true
        DispatchQueue.main.async { [weak self] in
            self?.refreshQueued = false
            self?.refresh()
        }
    }

    func refresh() {
        guard host.isInserted else { return }
        let state = MenuBarIconState.of(connectedCount: menuBar.connectedCount, pendingCount: menuBar.pendingCount,
                                        reduceMotion: reduceMotion(), step: step)
        if state.spinning { startSpinning() } else { stopSpinning() }
        // The label changes without the image (data loaded, an error): both are compared.
        let label = menuBar.accessibilityDescription
        guard state != lastState || label != lastLabel else { return }
        lastState = state
        lastLabel = label
        host.update(image: state.image, label: label)
    }

    private func startSpinning() {
        guard timer == nil else { return }
        timer = Timer.scheduledTimer(withTimeInterval: MenuBarIconState.interval, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self else { return }
                self.step = (self.step + 1) % MenuBarIconState.steps
                self.refresh()
            }
        }
    }

    private func stopSpinning() {
        timer?.invalidate()
        timer = nil
        step = 0
    }
}

/// The real status item (never created by the local checks).
@MainActor
final class SystemStatusItemHost: NSObject, StatusItemHost {
    static let autosaveName = "com.luiz.vpngui.status-item"
    private var item: NSStatusItem?
    private var action: (() -> Void)?

    var isInserted: Bool { item != nil }

    func insert(action: @escaping () -> Void) {
        guard item == nil else { return }
        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        item.autosaveName = Self.autosaveName
        item.button?.target = self
        item.button?.action = #selector(clicked(_:))
        self.action = action
        self.item = item
    }

    func remove() {
        guard let item else { return }
        NSStatusBar.system.removeStatusItem(item)
        self.item = nil
    }

    func update(image: NSImage?, label: String) {
        guard let button = item?.button else { return }
        button.image = image ?? NSImage(systemSymbolName: "shield", accessibilityDescription: nil)
        button.setAccessibilityLabel(label)
        button.toolTip = label
    }

    func setHighlighted(_ highlighted: Bool) {
        // After the click's own mouse-up, which clears the highlight.
        DispatchQueue.main.async { [weak self] in self?.item?.button?.highlight(highlighted) }
    }

    var anchor: MenuAnchor {
        if let button = item?.button, let window = button.window, window.isVisible,
           window.occlusionState.contains(.visible), let screen = window.screen {
            return MenuAnchor(button: window.convertToScreen(button.convert(button.bounds, to: nil)), visibleFrame: screen.visibleFrame)
        }
        let pointer = NSEvent.mouseLocation
        let screen = NSScreen.screens.first { NSMouseInRect(pointer, $0.frame, false) } ?? NSScreen.main
        return MenuAnchor(button: nil, visibleFrame: screen?.visibleFrame ?? NSRect(x: 0, y: 0, width: 1440, height: 900))
    }

    @objc private func clicked(_ sender: Any?) { action?() }
}

/// The menu's window: takes the keyboard without activating the app, so the app in front
/// stays in front (validated on macOS 27, arm64 and x86_64).
final class MenuBarPanel: NSPanel {
    var onCancel: (() -> Void)?
    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { false }
    override func cancelOperation(_ sender: Any?) { onCancel?() }
}

/// The menu panel: MenuBarView on the system's Liquid Glass (NSGlassEffectView) on macOS 26+,
/// on the menu material with rounded corners before, sized to the content and placed by
/// MenuPanelPlacement.
@MainActor
final class MenuBarPanelController: NSObject, MenuPanelPresenter, NSWindowDelegate {
    static let width: CGFloat = 360
    let panel: MenuBarPanel
    private let hosting: NSHostingView<MenuBarView>
    private weak var menuBar: MenuBarCoordinator?
    private var anchor: MenuAnchor?
    private var observers = Set<AnyCancellable>()
    private var spaceObserver: NSObjectProtocol?
    private var fitQueued = false
    private var keyMonitor: Any?
    var onClose: (() -> Void)?
    var isOpen: Bool { panel.isVisible }

    init(menuBar: MenuBarCoordinator) {
        self.menuBar = menuBar
        hosting = NSHostingView(rootView: MenuBarView(menuBar: menuBar, ownGlass: false))
        let size = NSSize(width: Self.width, height: 400)
        panel = MenuBarPanel(contentRect: NSRect(origin: .zero, size: size),
                             styleMask: [.nonactivatingPanel, .borderless, .fullSizeContentView], backing: .buffered, defer: true)
        super.init()
        panel.isReleasedWhenClosed = false
        panel.level = .popUpMenu
        panel.collectionBehavior = [.transient, .moveToActiveSpace, .fullScreenAuxiliary]
        panel.hidesOnDeactivate = false
        panel.isOpaque = false
        panel.backgroundColor = .clear
        panel.hasShadow = true
        panel.animationBehavior = .utilityWindow
        panel.delegate = self
        panel.onCancel = { [weak self] in self?.close() }
        hosting.frame = NSRect(origin: .zero, size: size)
        hosting.autoresizingMask = [.width, .height]
        if #available(macOS 26, *) {
            // The system's Liquid Glass, as menu bar extras like Weather have: a light, blurred
            // view of what is behind. The view itself adds no glass of its own here.
            let glass = NSGlassEffectView(frame: NSRect(origin: .zero, size: size))
            glass.style = .regular
            glass.cornerRadius = 16
            glass.contentView = hosting
            // In a plain container: as the window's own content view, the glass fills the whole
            // frame and ignores cornerRadius, leaving dark square corners (and their shadow).
            let container = NSView(frame: NSRect(origin: .zero, size: size))
            glass.autoresizingMask = [.width, .height]
            container.addSubview(glass)
            panel.contentView = container
        } else {
            // The menu material, as the system popover had.
            let material = NSVisualEffectView(frame: NSRect(origin: .zero, size: size))
            material.material = .menu
            material.state = .active
            material.blendingMode = .behindWindow
            material.maskImage = Self.roundedMask(radius: 12)
            material.addSubview(hosting)
            panel.contentView = material
        }
        menuBar.objectWillChange.sink { [weak self] in self?.queueFit() }.store(in: &observers)
        spaceObserver = NSWorkspace.shared.notificationCenter.addObserver(forName: NSWorkspace.activeSpaceDidChangeNotification,
                                                                          object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.close() }
        }
    }

    private static func roundedMask(radius: CGFloat) -> NSImage {
        let side = radius * 2 + 1
        let image = NSImage(size: NSSize(width: side, height: side), flipped: false) { rect in
            NSBezierPath(roundedRect: rect, xRadius: radius, yRadius: radius).fill()
            return true
        }
        image.capInsets = NSEdgeInsets(top: radius, left: radius, bottom: radius, right: radius)
        return image
    }

    func open(anchor: MenuAnchor) {
        self.anchor = anchor
        fit()
        // makeKey without NSApp.activate: the app in front keeps the front.
        panel.makeKeyAndOrderFront(nil)
        if keyMonitor == nil {
            // Only this panel's keys (macOS 13 has no onKeyPress; one path for every version).
            keyMonitor = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { [weak self] event in
                let window = event.windowNumber, code = event.keyCode, characters = event.charactersIgnoringModifiers
                let flags = event.modifierFlags
                let handled = MainActor.assumeIsolated {
                    self?.handle(window: window, keyCode: code, flags: flags, characters: characters) ?? false
                }
                return handled ? nil : event
            }
        }
    }

    func close() {
        if let keyMonitor { NSEvent.removeMonitor(keyMonitor) }
        keyMonitor = nil
        guard panel.isVisible else { return }
        panel.orderOut(nil)
        onClose?()
    }

    /// The search field is the first responder (its field editor).
    var searchFieldFocused: Bool { (panel.firstResponder as? NSTextView)?.isFieldEditor == true }

    /// ↑ ↓ ↩ ⌘↩ and Esc in the search field, ⌘F anywhere in the panel; the rest (Tab included)
    /// goes on as usual.
    func handle(window: Int, keyCode: UInt16, flags: NSEvent.ModifierFlags, characters: String?) -> Bool {
        guard window == panel.windowNumber, let menuBar else { return false }
        let flags = flags.intersection(.deviceIndependentFlagsMask).subtracting([.capsLock, .numericPad, .function])
        let key: MenuKey?
        if flags == .command, characters?.lowercased() == "f" {
            key = .find
        } else if !searchFieldFocused {
            key = nil
        } else {
            switch (keyCode, flags) {
            case (126, []): key = .up
            case (125, []): key = .down
            case (36, []), (76, []): key = .enter
            case (36, .command), (76, .command): key = .commandEnter
            case (53, []): key = .escape
            default: key = nil
            }
        }
        guard let key else { return false }
        menuBar.handleMenuKey(key)
        return true
    }

    /// Height of the content (no animation), kept under the visible frame; top edge fixed.
    func fit() {
        guard let anchor else { return }
        hosting.layoutSubtreeIfNeeded()
        let height = hosting.fittingSize.height
        let frame = MenuPanelPlacement.frame(size: NSSize(width: Self.width, height: height), anchor: anchor)
        guard frame != panel.frame else { return }
        panel.setFrame(frame, display: panel.isVisible)
        panel.invalidateShadow()
    }

    private func queueFit() {
        guard panel.isVisible, !fitQueued else { return }
        fitQueued = true
        DispatchQueue.main.async { [weak self] in
            self?.fitQueued = false
            self?.fit()
        }
    }

    // Clicking outside, another app or ⌘Tab.
    func windowDidResignKey(_ notification: Notification) { close() }
}
