import SwiftUI
import AppKit
import Carbon.HIToolbox
import Combine

// Global shortcut that opens the menu with the search ready, from any app. A key combination
// or a single F key goes through Carbon's RegisterEventHotKey (no permission); a double tap of
// a modifier through a listen-only tap of modifier changes (Input Monitoring, opt-in; see
// DoubleTap.swift). The local checks never register either: both sit behind protocols.

enum ModifierKey: String, Codable, CaseIterable, Equatable {
    case command, option, control, shift

    /// Left and right key codes.
    var keyCodes: (left: UInt16, right: UInt16) {
        switch self {
        case .command: return (55, 54)
        case .option: return (58, 61)
        case .control: return (59, 62)
        case .shift: return (56, 60)
        }
    }
    var symbol: String {
        switch self {
        case .command: return "⌘"
        case .option: return "⌥"
        case .control: return "⌃"
        case .shift: return "⇧"
        }
    }
    var spoken: String {
        switch self {
        case .command: return String(localized: "Command")
        case .option: return String(localized: "Option")
        case .control: return String(localized: "Control")
        case .shift: return String(localized: "Shift")
        }
    }
    var carbon: UInt32 {
        switch self {
        case .command: return UInt32(cmdKey)
        case .option: return UInt32(optionKey)
        case .control: return UInt32(controlKey)
        case .shift: return UInt32(shiftKey)
        }
    }
    var cgFlag: CGEventFlags {
        switch self {
        case .command: return .maskCommand
        case .option: return .maskAlternate
        case .control: return .maskControl
        case .shift: return .maskShift
        }
    }
    /// The modifier a key code belongs to, and which side it is.
    static func of(keyCode: UInt16) -> (ModifierKey, ModifierSide)? {
        for key in allCases {
            if key.keyCodes.left == keyCode { return (key, .left) }
            if key.keyCodes.right == keyCode { return (key, .right) }
        }
        return nil
    }
    /// Display order of macOS menus: ⌃⌥⇧⌘.
    static let menuOrder: [ModifierKey] = [.control, .option, .shift, .command]
}

enum ModifierSide: String, Codable, CaseIterable, Equatable {
    case any, left, right
}

/// The shortcut that opens the menu. Saved as JSON; none by default.
enum GlobalShortcut: Codable, Equatable {
    /// A combination or a single F key; modifiers in Carbon's format (cmdKey, optionKey…).
    case keys(keyCode: UInt32, modifiers: UInt32)
    case doubleTap(modifier: ModifierKey, side: ModifierSide)

    var isDoubleTap: Bool { if case .doubleTap = self { return true } else { return false } }
}

// MARK: - Key names

/// The character a key code types in the current layout (injectable for the checks).
protocol KeyTranslator {
    func character(for keyCode: UInt16) -> String?
}

/// UCKeyTranslate with the current keyboard layout.
struct SystemKeyTranslator: KeyTranslator {
    func character(for keyCode: UInt16) -> String? {
        guard let source = TISCopyCurrentKeyboardLayoutInputSource()?.takeRetainedValue(),
              let pointer = TISGetInputSourceProperty(source, kTISPropertyUnicodeKeyLayoutData) else { return nil }
        let data = Unmanaged<CFData>.fromOpaque(pointer).takeUnretainedValue() as Data
        var deadKeys: UInt32 = 0
        var length = 0
        var characters = [UniChar](repeating: 0, count: 4)
        let status = data.withUnsafeBytes { raw -> OSStatus in
            guard let layout = raw.bindMemory(to: UCKeyboardLayout.self).baseAddress else { return OSStatus(paramErr) }
            return UCKeyTranslate(layout, keyCode, UInt16(kUCKeyActionDisplay), 0, UInt32(LMGetKbdType()),
                                  OptionBits(kUCKeyTranslateNoDeadKeysBit), &deadKeys, characters.count, &length, &characters)
        }
        guard status == noErr, length > 0 else { return nil }
        let text = String(utf16CodeUnits: characters, count: length).trimmingCharacters(in: .whitespacesAndNewlines)
        return text.isEmpty ? nil : text.uppercased()
    }
}

enum KeyNames {
    /// F1–F20 by key code.
    static let functionKeys: [UInt16: Int] = [122: 1, 120: 2, 99: 3, 118: 4, 96: 5, 97: 6, 98: 7, 100: 8, 101: 9, 109: 10,
                                              103: 11, 111: 12, 105: 13, 107: 14, 113: 15, 106: 16, 64: 17, 79: 18, 80: 19, 90: 20]
    /// Symbols of the special keys, and their spoken names.
    private static let special: [UInt16: (symbol: String, spoken: String)] = [
        36: ("↩", String(localized: "Return")), 76: ("⌤", String(localized: "Enter")), 48: ("⇥", String(localized: "Tab")),
        49: ("␣", String(localized: "Espaço")), 51: ("⌫", String(localized: "Delete")), 117: ("⌦", String(localized: "Delete para a frente")),
        53: ("⎋", String(localized: "Esc")), 123: ("←", String(localized: "Seta para a esquerda")), 124: ("→", String(localized: "Seta para a direita")),
        125: ("↓", String(localized: "Seta para baixo")), 126: ("↑", String(localized: "Seta para cima")),
        115: ("↖", String(localized: "Home")), 119: ("↘", String(localized: "End")), 116: ("⇞", String(localized: "Page Up")),
        121: ("⇟", String(localized: "Page Down")),
    ]
    /// US positions, when the layout gives nothing.
    private static let ansi: [UInt16: String] = [0: "A", 11: "B", 8: "C", 2: "D", 14: "E", 3: "F", 5: "G", 4: "H", 34: "I", 38: "J",
                                                 40: "K", 37: "L", 46: "M", 45: "N", 31: "O", 35: "P", 12: "Q", 15: "R", 1: "S", 17: "T",
                                                 32: "U", 9: "V", 13: "W", 7: "X", 16: "Y", 6: "Z", 18: "1", 19: "2", 20: "3", 21: "4",
                                                 23: "5", 22: "6", 26: "7", 28: "8", 25: "9", 29: "0", 43: ",", 47: ".", 50: "`"]

    static func key(_ keyCode: UInt16, translator: KeyTranslator) -> (symbol: String, spoken: String) {
        if let number = functionKeys[keyCode] { return ("F\(number)", "F\(number)") }
        if let special = special[keyCode] { return special }
        let character = translator.character(for: keyCode) ?? ansi[keyCode] ?? "#\(keyCode)"
        return (character, character)
    }

    static func modifierKeys(_ carbon: UInt32) -> [ModifierKey] { ModifierKey.menuOrder.filter { carbon & $0.carbon != 0 } }

    /// "⌃⌥⌘K", "F13", "⌥ ⌥" or "⌥ ⌥ direito".
    static func symbols(_ shortcut: GlobalShortcut, translator: KeyTranslator = SystemKeyTranslator()) -> String {
        switch shortcut {
        case .keys(let keyCode, let modifiers):
            return modifierKeys(modifiers).map(\.symbol).joined() + key(UInt16(keyCode), translator: translator).symbol
        case .doubleTap(let modifier, let side):
            let pair = "\(modifier.symbol) \(modifier.symbol)"
            switch side {
            case .any: return pair
            case .left: return String(localized: "\(pair) esquerdo")
            case .right: return String(localized: "\(pair) direito")
            }
        }
    }

    /// For VoiceOver: "Control Option Command K", "Option duas vezes".
    static func spoken(_ shortcut: GlobalShortcut, translator: KeyTranslator = SystemKeyTranslator()) -> String {
        switch shortcut {
        case .keys(let keyCode, let modifiers):
            return (modifierKeys(modifiers).map(\.spoken) + [key(UInt16(keyCode), translator: translator).spoken]).joined(separator: " ")
        case .doubleTap(let modifier, let side):
            switch side {
            case .any: return String(localized: "\(modifier.spoken) duas vezes")
            case .left: return String(localized: "\(modifier.spoken) esquerdo duas vezes")
            case .right: return String(localized: "\(modifier.spoken) direito duas vezes")
            }
        }
    }
}

// MARK: - Validation

/// Shortcuts macOS itself uses (System Settings › Keyboard › Keyboard Shortcuts), enabled ones only.
protocol SystemShortcutProvider {
    func enabledShortcuts() -> [(keyCode: UInt32, modifiers: UInt32)]
}

struct SymbolicHotKeys: SystemShortcutProvider {
    func enabledShortcuts() -> [(keyCode: UInt32, modifiers: UInt32)] {
        var array: Unmanaged<CFArray>?
        guard CopySymbolicHotKeys(&array) == noErr, let list = array?.takeRetainedValue() as? [[String: Any]] else { return [] }
        return list.compactMap { entry in
            guard (entry[kHISymbolicHotKeyEnabled as String] as? Bool) == true,
                  let code = (entry[kHISymbolicHotKeyCode as String] as? NSNumber)?.uint32Value,
                  let modifiers = (entry[kHISymbolicHotKeyModifiers as String] as? NSNumber)?.uint32Value else { return nil }
            return (code, modifiers)
        }
    }
}

enum ShortcutVerdict: Equatable {
    /// Accepted, possibly with a notice (F1–F12 need fn on Apple keyboards).
    case accepted(notice: String?)
    case rejected(String)
}

enum ShortcutValidator {
    static let relevantModifiers = UInt32(cmdKey | optionKey | controlKey | shiftKey)

    static var needsCommandOrControl: String {
        String(localized: "Use ⌘ ou ⌃ no atalho, uma tecla F1–F20 sozinha ou toque duas vezes num modificador.")
    }
    static var functionKeyNotice: String {
        String(localized: "Em teclados Apple, F1–F12 controlam brilho e som; aperte com fn ou ative \"Usar F1, F2 etc. como teclas de função padrão\".")
    }
    static var doubleTapModifiers: String { String(localized: "Use ⌘, ⌥, ⌃ ou ⇧ para o toque duplo.") }
    static var systemShortcut: String { String(localized: "Este atalho já é usado pelo macOS (Ajustes › Teclado › Atalhos de Teclado).") }
    static var commonShortcut: String { String(localized: "Este atalho é usado por apps comuns; escolha outro.") }
    /// The code as typed by macOS ("-9878"), not as a localized number ("-9.878").
    static func registrationFailed(_ status: OSStatus) -> String { String(localized: "O macOS recusou este atalho (código \(String(status))). Escolha outro.") }

    /// App and editing shortcuts a global one would take from every app: character (in the
    /// current layout) or key code, with ⌘ alone (⇧⌘ for Z).
    private static let reservedCharacters: Set<String> = ["Q", "W", "H", "M", "O", "N", ",", "C", "V", "X", "Z", "A", "F", "`"]
    private static let reservedKeyCodes: Set<UInt16> = [48, 49] // Tab, Space

    static func validate(_ shortcut: GlobalShortcut, system: SystemShortcutProvider,
                         translator: KeyTranslator = SystemKeyTranslator()) -> ShortcutVerdict {
        guard case .keys(let keyCode, let raw) = shortcut else { return .accepted(notice: nil) }
        let modifiers = raw & relevantModifiers
        let code = UInt16(keyCode)
        let function = KeyNames.functionKeys[code]
        if modifiers & UInt32(cmdKey | controlKey) == 0 {
            guard let function else { return .rejected(needsCommandOrControl) }
            if system.enabledShortcuts().contains(where: { $0.keyCode == keyCode && $0.modifiers & relevantModifiers == modifiers }) {
                return .rejected(systemShortcut)
            }
            return .accepted(notice: function <= 12 && modifiers == 0 ? functionKeyNotice : nil)
        }
        if system.enabledShortcuts().contains(where: { $0.keyCode == keyCode && $0.modifiers & relevantModifiers == modifiers }) {
            return .rejected(systemShortcut)
        }
        let character = KeyNames.key(code, translator: translator).symbol
        let command = UInt32(cmdKey), shiftCommand = UInt32(cmdKey | shiftKey)
        if modifiers == command, reservedCharacters.contains(character) || reservedKeyCodes.contains(code) { return .rejected(commonShortcut) }
        if modifiers == shiftCommand, character == "Z" { return .rejected(commonShortcut) }
        return .accepted(notice: nil)
    }

    /// Double tap of a key that is not one of the four modifiers (Caps Lock, fn/🌐).
    static func validateDoubleTap(keyCode: UInt16) -> ShortcutVerdict {
        ModifierKey.of(keyCode: keyCode) != nil ? .accepted(notice: nil) : .rejected(doubleTapModifiers)
    }
}

// MARK: - Registration

/// Registers the single key shortcut (a fake in the local checks).
@MainActor protocol HotKeyRegistrar: AnyObject {
    var onPressed: (() -> Void)? { get set }
    /// noErr, or the OSStatus macOS returned.
    func register(keyCode: UInt32, modifiers: UInt32) -> OSStatus
    func unregister()
}

/// Carbon RegisterEventHotKey: one event handler on the application target, one hot key
/// ('TNMC', id 1). Needs no permission (validated on macOS 27, arm64 and x86_64).
@MainActor
final class CarbonHotKeyRegistrar: HotKeyRegistrar {
    static let signature: OSType = 0x544E_4D43 // 'TNMC'
    var onPressed: (() -> Void)?
    private var handler: EventHandlerRef?
    private var hotKey: EventHotKeyRef?

    func register(keyCode: UInt32, modifiers: UInt32) -> OSStatus {
        unregister()
        if handler == nil {
            var type = EventTypeSpec(eventClass: OSType(kEventClassKeyboard), eventKind: UInt32(kEventHotKeyPressed))
            let status = InstallEventHandler(GetApplicationEventTarget(), { _, event, userData in
                guard let event, let userData else { return OSStatus(eventNotHandledErr) }
                var id = EventHotKeyID()
                let read = GetEventParameter(event, EventParamName(kEventParamDirectObject), EventParamType(typeEventHotKeyID), nil,
                                             MemoryLayout<EventHotKeyID>.size, nil, &id)
                guard read == noErr, id.signature == CarbonHotKeyRegistrar.signature, id.id == 1 else { return OSStatus(eventNotHandledErr) }
                let registrar = Unmanaged<CarbonHotKeyRegistrar>.fromOpaque(userData).takeUnretainedValue()
                DispatchQueue.main.async { MainActor.assumeIsolated { registrar.onPressed?() } }
                return noErr
            }, 1, &type, Unmanaged.passUnretained(self).toOpaque(), &handler)
            if status != noErr { return status }
        }
        var reference: EventHotKeyRef?
        let status = RegisterEventHotKey(keyCode, modifiers, EventHotKeyID(signature: Self.signature, id: 1),
                                         GetApplicationEventTarget(), 0, &reference)
        if status == noErr { hotKey = reference }
        return status
    }

    func unregister() {
        if let hotKey { UnregisterEventHotKey(hotKey) }
        hotKey = nil
    }
}

// MARK: - Center

/// Keeps the saved shortcut registered (or the double-tap tap running), suspends it while a new
/// one is recorded and reports why it is not active.
@MainActor
final class GlobalHotKeyCenter: ObservableObject {
    enum Status: Equatable {
        case none, active, suspended
        /// Double tap saved, Input Monitoring not allowed yet.
        case waitingForPermission
        /// The saved shortcut could not be activated (kept saved).
        case failed(OSStatus)
        /// Allowed, but the tap did not start: macOS may need the app reopened.
        case tapUnavailable
    }

    @Published private(set) var status: Status = .none
    let preferences: AppPreferences
    let registrar: HotKeyRegistrar
    let taps: ModifierTapSource
    let system: SystemShortcutProvider
    private var detector: DoubleTapDetector?
    private var suspended = false
    private var observers = Set<AnyCancellable>()
    private let trigger: () -> Void

    init(preferences: AppPreferences, registrar: HotKeyRegistrar, taps: ModifierTapSource,
         system: SystemShortcutProvider, trigger: @escaping () -> Void) {
        self.preferences = preferences
        self.registrar = registrar
        self.taps = taps
        self.system = system
        self.trigger = trigger
        registrar.onPressed = { [weak self] in self?.fire() }
        preferences.$menuShortcut.removeDuplicates().sink { [weak self] shortcut in
            self?.apply(shortcut)
        }.store(in: &observers)
        NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)
            .sink { [weak self] _ in self?.refreshPermission() }.store(in: &observers)
    }

    /// The app's center: never in the local checks runner, whose shortcut would take keys
    /// from every app on the Mac.
    static func production(menuBar: MenuBarCoordinator) -> GlobalHotKeyCenter? {
        guard !MenuBarCoordinator.isLocalChecks else { return nil }
        let taps = EventTapModifierSource()
        let center = GlobalHotKeyCenter(preferences: menuBar.preferences, registrar: CarbonHotKeyRegistrar(), taps: taps,
                                        system: SymbolicHotKeys()) { [weak menuBar] in menuBar?.toggleMenu(focusSearch: true) }
        taps.onFailure = { [weak center] in center?.tapFailed() }
        return center
    }

    /// macOS disabled the tap twice: shown in Geral.
    func tapFailed() {
        guard preferences.menuShortcut?.isDoubleTap == true else { return }
        status = .tapUnavailable
    }

    private func fire() {
        guard !suspended else { return }
        trigger()
    }

    private func deactivate() {
        registrar.unregister()
        taps.stop()
        detector = nil
    }

    private func apply(_ shortcut: GlobalShortcut?) {
        deactivate()
        guard let shortcut else { status = .none; return }
        guard !suspended else { status = .suspended; return }
        switch shortcut {
        case .keys(let keyCode, let modifiers):
            let result = registrar.register(keyCode: keyCode, modifiers: modifiers)
            status = result == noErr ? .active : .failed(result)
        case .doubleTap(let modifier, let side):
            guard taps.hasAccess else { status = .waitingForPermission; return }
            detector = DoubleTapDetector(modifier: modifier, side: side)
            let started = taps.start(mask: DoubleTapDetector.eventMask) { [weak self] change in
                guard let self, var detector = self.detector else { return }
                let fired = detector.handle(change)
                self.detector = detector
                if fired { self.fire() }
            }
            status = started ? .active : .tapUnavailable
        }
    }

    /// While recording, the current shortcut neither opens the menu nor holds the keys.
    func suspend() {
        guard !suspended else { return }
        suspended = true
        deactivate()
        if preferences.menuShortcut != nil { status = .suspended }
    }

    func resume() {
        guard suspended else { return }
        suspended = false
        apply(preferences.menuShortcut)
    }

    /// Saves a recorded shortcut. A key shortcut is registered first: if macOS refuses it,
    /// nothing is saved and the error comes back.
    func save(_ shortcut: GlobalShortcut) -> OSStatus {
        if case .keys(let keyCode, let modifiers) = shortcut {
            suspended = false
            deactivate()
            let result = registrar.register(keyCode: keyCode, modifiers: modifiers)
            guard result == noErr else {
                registrar.unregister()
                apply(preferences.menuShortcut)
                return result
            }
            registrar.unregister()
        }
        suspended = false
        if preferences.menuShortcut == shortcut { apply(shortcut) } else { preferences.menuShortcut = shortcut }
        return noErr
    }

    func clear() {
        suspended = false
        preferences.menuShortcut = nil
        apply(nil)
    }

    /// Input Monitoring is read again when the app comes back to the front (from Ajustes).
    func refreshPermission() {
        guard !suspended, preferences.menuShortcut?.isDoubleTap == true,
              status == .waitingForPermission || status == .tapUnavailable else { return }
        apply(preferences.menuShortcut)
    }

    func requestPermission() { taps.requestAccess() }
}
