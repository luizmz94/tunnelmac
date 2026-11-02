import SwiftUI
import AppKit
import Carbon.HIToolbox

/// What the recorder makes of the keys pressed while it records. One recorder for the three
/// forms: a key with ⌘ or ⌃ (or an F key alone) is a combination, the same modifier tapped twice
/// alone is a double tap, and modifiers alone keep it recording.
struct ShortcutRecording {
    enum Outcome: Equatable {
        case recording
        case cancel
        case clear
        /// `side`: the side tapped, for "Qualquer lado" off.
        case recorded(GlobalShortcut, notice: String?, side: ModifierSide?)
        case rejected(String)
    }

    private var lastTap: (keyCode: UInt16, time: TimeInterval)?
    private var pressed: (keyCode: UInt16, time: TimeInterval)?
    let system: SystemShortcutProvider
    let translator: KeyTranslator

    init(system: SystemShortcutProvider, translator: KeyTranslator = SystemKeyTranslator()) {
        self.system = system
        self.translator = translator
    }

    static func carbonModifiers(_ flags: NSEvent.ModifierFlags) -> UInt32 {
        var result: UInt32 = 0
        if flags.contains(.command) { result |= UInt32(cmdKey) }
        if flags.contains(.option) { result |= UInt32(optionKey) }
        if flags.contains(.control) { result |= UInt32(controlKey) }
        if flags.contains(.shift) { result |= UInt32(shiftKey) }
        return result
    }

    mutating func keyDown(keyCode: UInt16, flags: NSEvent.ModifierFlags) -> Outcome {
        lastTap = nil
        pressed = nil
        let modifiers = Self.carbonModifiers(flags)
        if modifiers == 0, keyCode == UInt16(kVK_Escape) { return .cancel }
        if modifiers == 0, keyCode == UInt16(kVK_Delete) || keyCode == UInt16(kVK_ForwardDelete) { return .clear }
        let shortcut = GlobalShortcut.keys(keyCode: UInt32(keyCode), modifiers: modifiers)
        switch ShortcutValidator.validate(shortcut, system: system, translator: translator) {
        case .accepted(let notice): return .recorded(shortcut, notice: notice, side: nil)
        case .rejected(let message): return .rejected(message)
        }
    }

    /// Caps Lock and fn/🌐 count as taps here only to be refused.
    private static let tappable: Set<UInt16> = [UInt16(kVK_CapsLock), UInt16(kVK_Function)]

    mutating func flagsChanged(keyCode: UInt16, flags: NSEvent.ModifierFlags, time: TimeInterval) -> Outcome {
        let relevant = flags.intersection([.command, .option, .control, .shift, .function, .capsLock])
        let isModifier = ModifierKey.of(keyCode: keyCode) != nil || Self.tappable.contains(keyCode)
        guard isModifier else { return .recording }
        let down: Bool
        if let (key, _) = ModifierKey.of(keyCode: keyCode) {
            let own: NSEvent.ModifierFlags = key == .command ? .command : key == .option ? .option : key == .control ? .control : .shift
            down = relevant.contains(own)
            // Another modifier held at the same time: a combination in progress, not a tap.
            if relevant.subtracting([own, .capsLock]) != [] { pressed = nil; lastTap = nil; return .recording }
        } else {
            // Caps Lock toggles; fn reports its flag while held.
            down = keyCode == UInt16(kVK_CapsLock) ? pressed?.keyCode != keyCode : relevant.contains(.function)
        }
        if down { pressed = (keyCode, time); return .recording }
        guard let start = pressed, start.keyCode == keyCode else { pressed = nil; return .recording }
        pressed = nil
        guard time - start.time <= DoubleTapDetector.maxHold else { lastTap = nil; return .recording }
        if let last = lastTap, last.keyCode == keyCode || ModifierKey.of(keyCode: last.keyCode)?.0 == ModifierKey.of(keyCode: keyCode)?.0,
           time - last.time <= 0.4 + DoubleTapDetector.maxHold {
            lastTap = nil
            guard case .accepted = ShortcutValidator.validateDoubleTap(keyCode: keyCode), let (key, side) = ModifierKey.of(keyCode: keyCode) else {
                return .rejected(ShortcutValidator.doubleTapModifiers)
            }
            return .recorded(.doubleTap(modifier: key, side: .any), notice: nil, side: side)
        }
        // A single tap waits for the second one; otherwise it keeps recording.
        lastTap = (keyCode, time)
        return .recording
    }
}

/// The recorder's state: records with a local key monitor while Configurações is in front
/// (recording needs no permission; only using a double tap does) and saves through the center.
@MainActor
final class ShortcutRecorderModel: ObservableObject {
    @Published private(set) var recording = false
    /// Refusal or macOS error, shown in orange; nothing was saved.
    @Published var message: String?
    /// Kept after saving an F1–F12 key alone.
    @Published var notice: String?
    /// A double tap was saved without Input Monitoring: the explanation comes before asking.
    @Published var explainPermission = false
    /// Side of the last recorded double tap, for "Qualquer lado" off.
    @Published private(set) var tappedSide: ModifierSide?
    let center: GlobalHotKeyCenter
    private var logic: ShortcutRecording
    private var monitor: Any?
    private var resignObserver: NSObjectProtocol?

    init(center: GlobalHotKeyCenter, translator: KeyTranslator = SystemKeyTranslator()) {
        self.center = center
        logic = ShortcutRecording(system: center.system, translator: translator)
    }

    func start() {
        guard !recording else { return }
        recording = true
        message = nil
        explainPermission = false
        logic = ShortcutRecording(system: center.system, translator: logic.translator)
        center.suspend()
        monitor = NSEvent.addLocalMonitorForEvents(matching: [.keyDown, .flagsChanged]) { [weak self] event in
            let type = event.type, code = event.keyCode, flags = event.modifierFlags, time = event.timestamp
            let repeated = type == .keyDown && event.isARepeat
            MainActor.assumeIsolated {
                guard let self, !repeated else { return }
                self.handle(type == .keyDown ? self.logic.keyDown(keyCode: code, flags: flags)
                                             : self.logic.flagsChanged(keyCode: code, flags: flags, time: time))
            }
            return nil
        }
        // Losing the focus cancels.
        resignObserver = NotificationCenter.default.addObserver(forName: NSApplication.didResignActiveNotification, object: nil,
                                                                queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.cancel() }
        }
    }

    func cancel() {
        guard recording else { return }
        finish()
        center.resume()
    }

    private func finish() {
        if let monitor { NSEvent.removeMonitor(monitor) }
        if let resignObserver { NotificationCenter.default.removeObserver(resignObserver) }
        monitor = nil
        resignObserver = nil
        recording = false
    }

    func handle(_ outcome: ShortcutRecording.Outcome) {
        switch outcome {
        case .recording:
            break
        case .cancel:
            cancel()
        case .clear:
            finish()
            clear()
        case .rejected(let text):
            message = text // keeps recording
        case .recorded(let shortcut, let notice, let side):
            finish()
            let result = center.save(shortcut)
            guard result == noErr else {
                message = ShortcutValidator.registrationFailed(result)
                return
            }
            message = nil
            self.notice = notice
            tappedSide = side
            explainPermission = shortcut.isDoubleTap && !center.taps.hasAccess
        }
    }

    func clear() {
        message = nil
        notice = nil
        explainPermission = false
        center.clear()
    }

    /// "Permitir…": macOS asks and opens Privacy & Security › Input Monitoring.
    func allow() {
        explainPermission = false
        center.requestPermission()
        Self.openInputMonitoring()
    }

    /// "Usar uma combinação": drops the double tap and records again.
    func useCombination() {
        clear()
        start()
    }

    /// "Qualquer lado" off keeps the side that was tapped (left when unknown).
    func setAnySide(_ any: Bool) {
        guard case .doubleTap(let modifier, _) = center.preferences.menuShortcut else { return }
        _ = center.save(.doubleTap(modifier: modifier, side: any ? .any : (tappedSide ?? .left)))
    }

    static func openInputMonitoring() {
        if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_ListenEvent") {
            NSWorkspace.shared.open(url)
        }
    }
}

/// "Atalho" in Configurações › Geral.
struct ShortcutSettings: View {
    @ObservedObject var center: GlobalHotKeyCenter
    @ObservedObject var preferences: AppPreferences
    @ObservedObject var recorder: ShortcutRecorderModel

    var body: some View {
        SettingsSection(title: String(localized: "Atalho")) {
            SettingsRow(symbol: "command", color: .purple, title: String(localized: "Abrir o menu do TunnelMac"),
                        subtitle: String(localized: "Abre o menu com a busca pronta, de qualquer app.")) {
                ShortcutRecorderControl(shortcut: preferences.menuShortcut, recorder: recorder)
            }
            if case .doubleTap(_, let side) = preferences.menuShortcut {
                SettingsDivider()
                SettingsRow(symbol: "arrow.left.and.right", color: .gray, title: String(localized: "Qualquer lado"),
                            subtitle: String(localized: "Aceita a tecla da esquerda ou da direita.")) {
                    Toggle("Qualquer lado", isOn: Binding(get: { side == .any }, set: { recorder.setAnySide($0) }))
                        .toggleStyle(.switch).labelsHidden().controlSize(.mini).accessibilityLabel(String(localized: "Qualquer lado"))
                }
            }
            ForEach(notices, id: \.title) { notice in
                notice.padding(.horizontal, 14).padding(.bottom, 10)
            }
        }
    }

    private struct Notice: View {
        let title: String
        var tone: StatusTone = .warning
        var symbol = "exclamationmark.triangle.fill"
        var actions: [(String, () -> Void)] = []
        var body: some View {
            InlineNotice(tone: tone, symbol: symbol, title: title) {
                HStack(spacing: 6) {
                    ForEach(actions.indices, id: \.self) { index in
                        Button(actions[index].0, action: actions[index].1).adaptiveButtonStyle()
                    }
                }
            }
        }
    }

    private var notices: [Notice] {
        var list: [Notice] = []
        if let message = recorder.message { list.append(Notice(title: message)) }
        if recorder.explainPermission {
            list.append(Notice(title: String(localized: "Para reconhecer o toque duplo, o macOS precisa permitir que o TunnelMac monitore as teclas modificadoras. O app lê só ⌘ ⌥ ⌃ ⇧, nunca o que você digita."),
                               tone: .neutral, symbol: "hand.raised.fill",
                               actions: [(String(localized: "Permitir…"), recorder.allow), (String(localized: "Usar uma combinação"), recorder.useCombination)]))
        } else if center.status == .waitingForPermission {
            list.append(Notice(title: String(localized: "Aguardando permissão em Ajustes › Privacidade e Segurança › Monitoramento de Entrada"),
                               actions: [(String(localized: "Abrir Ajustes…"), ShortcutRecorderModel.openInputMonitoring)]))
        }
        if center.status == .tapUnavailable {
            list.append(Notice(title: String(localized: "O macOS ainda não entregou as teclas modificadoras ao TunnelMac; reabra o app para o toque duplo valer."),
                               actions: [(String(localized: "Reabrir agora"), { AppRelaunch.now() })]))
        }
        if case .failed = center.status {
            list.append(Notice(title: String(localized: "Não foi possível ativar o atalho; grave outro ou tente reabrir o app.")))
        }
        if let notice = recorder.notice, case .keys = preferences.menuShortcut {
            list.append(Notice(title: notice, tone: .neutral, symbol: "info.circle.fill"))
        }
        return list
    }
}

/// The capsule that records: "Gravar atalho", the shortcut in symbols, or the recording prompt.
struct ShortcutRecorderControl: View {
    let shortcut: GlobalShortcut?
    @ObservedObject var recorder: ShortcutRecorderModel

    var body: some View {
        HStack(spacing: 6) {
            Button { recorder.recording ? recorder.cancel() : recorder.start() } label: {
                Text(title).lineLimit(1).frame(minWidth: 90)
            }
            .adaptiveButtonStyle(prominent: recorder.recording)
            .controlSize(.small)
            .help(recorder.recording ? String(localized: "Esc cancela; ⌫ remove o atalho") : String(localized: "Clique e digite o atalho"))
            .accessibilityLabel(String(localized: "Atalho para abrir o menu"))
            .accessibilityValue(recorder.recording ? title : shortcut.map { KeyNames.spoken($0) } ?? String(localized: "Nenhum"))
            if shortcut != nil, !recorder.recording {
                Button { recorder.clear() } label: { Image(systemName: "xmark.circle.fill") }
                    .buttonStyle(.plain).foregroundStyle(.secondary)
                    .help("Remover atalho")
                    .accessibilityLabel(String(localized: "Remover atalho"))
            }
        }
    }

    private var title: String {
        if recorder.recording { return String(localized: "Digite o atalho ou toque duas vezes num modificador…") }
        return shortcut.map { KeyNames.symbols($0) } ?? String(localized: "Gravar atalho")
    }
}
