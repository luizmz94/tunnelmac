@testable import VPNApp
import Foundation
import AppKit
import Carbon.HIToolbox

/// Local checks for the global shortcut. Nothing here registers a real hot key or creates an
/// event tap: the registrar, the tap source, the system shortcuts and the layout are fakes.
@MainActor
enum GlobalHotKeyTests {
    static func run() -> Int {
        var failures = 0
        func test(_ name: String, _ block: () throws -> Void) {
            do { try block(); print("PASS: Atalho: \(name)") }
            catch { failures += 1; print("FAIL: Atalho: \(name): \(error.localizedDescription)") }
        }
        let require = TestSupport.require
        let cmd = UInt32(cmdKey), opt = UInt32(optionKey), ctrl = UInt32(controlKey), shift = UInt32(shiftKey)
        let us = FakeKeyTranslator([:])

        test("Modelo: os dois casos em JSON, JSON inválido vira nenhum, padrão nenhum e persiste na suíte descartável") {
            for shortcut in [GlobalShortcut.keys(keyCode: 40, modifiers: ctrl | opt | cmd), .doubleTap(modifier: .option, side: .right)] {
                let decoded = try JSONDecoder().decode(GlobalShortcut.self, from: JSONEncoder().encode(shortcut))
                try require(decoded == shortcut, "Ida e volta em JSON: \(shortcut)")
            }
            let preferences = AppPreferences.disposable()
            try require(preferences.menuShortcut == nil && preferences.defaults !== UserDefaults.standard, "Padrão não é nenhum")
            preferences.menuShortcut = .doubleTap(modifier: .command, side: .any)
            try require(AppPreferences(defaults: preferences.defaults).menuShortcut == .doubleTap(modifier: .command, side: .any), "Não persistiu")
            for garbage in [Data("{\"teclas\":1}".utf8), Data([0xFF, 0x00]), Data("{\"doubleTap\":{\"modifier\":\"capsLock\",\"side\":\"any\"}}".utf8)] {
                preferences.defaults.set(garbage, forKey: AppPreferences.Key.menuShortcut)
                try require(AppPreferences(defaults: preferences.defaults).menuShortcut == nil, "JSON inválido não virou nenhum")
            }
            preferences.menuShortcut = nil
            try require(preferences.defaults.object(forKey: AppPreferences.Key.menuShortcut) == nil, "Limpar não removeu a chave")
        }

        test("Validação: tabela da spec, caso a caso, com atalhos do sistema falsos") {
            let system = FakeSystemShortcuts([(17, ctrl | cmd), (96, shift)]) // ⌃⌘T and ⇧F5 in use by macOS
            func verdict(_ code: UInt32, _ modifiers: UInt32) -> ShortcutVerdict {
                ShortcutValidator.validate(.keys(keyCode: code, modifiers: modifiers), system: system, translator: us)
            }
            try require(verdict(40, ctrl | opt | cmd) == .accepted(notice: nil), "⌃⌥⌘K recusado")
            try require(verdict(105, 0) == .accepted(notice: nil), "F13 sozinha recusada")
            try require(verdict(96, 0) == .accepted(notice: ShortcutValidator.functionKeyNotice), "F5 sozinha sem o aviso de fn")
            try require(verdict(96, shift) == .rejected(ShortcutValidator.systemShortcut), "⇧F5 do sistema aceito")
            for (code, modifiers, name) in [(40, 0, "K"), (49, 0, "Espaço"), (38, opt, "⌥J"), (32, shift, "⇧U"), (37, opt | shift, "⌥⇧L"), (36, 0, "↩")] as [(UInt32, UInt32, String)] {
                try require(verdict(code, modifiers) == .rejected(ShortcutValidator.needsCommandOrControl), "\(name) aceito")
            }
            try require(verdict(17, ctrl | cmd) == .rejected(ShortcutValidator.systemShortcut), "Atalho do sistema aceito")
            for (code, modifiers, name) in [(12, cmd, "⌘Q"), (13, cmd, "⌘W"), (43, cmd, "⌘,"), (8, cmd, "⌘C"), (6, cmd | shift, "⇧⌘Z"),
                                            (48, cmd, "⌘Tab"), (49, cmd, "⌘Espaço"), (50, cmd, "⌘`"), (3, cmd, "⌘F")] as [(UInt32, UInt32, String)] {
                try require(verdict(code, modifiers) == .rejected(ShortcutValidator.commonShortcut), "\(name) aceito")
            }
            try require(verdict(40, cmd | shift) == .accepted(notice: nil) && verdict(12, cmd | opt) == .accepted(notice: nil), "Combinação válida recusada")
            // Layout: on AZERTY the M is where US has ";" (41): still ⌘M.
            try require(ShortcutValidator.validate(.keys(keyCode: 41, modifiers: cmd), system: system, translator: FakeKeyTranslator([41: "M"]))
                        == .rejected(ShortcutValidator.commonShortcut), "⌘M de outro layout aceito")
            try require(ShortcutValidator.validateDoubleTap(keyCode: 58) == .accepted(notice: nil), "Toque duplo de ⌥ recusado")
            for code in [57, 63] as [UInt16] { // Caps Lock, fn
                try require(ShortcutValidator.validateDoubleTap(keyCode: code) == .rejected(ShortcutValidator.doubleTapModifiers), "Toque duplo \(code) aceito")
            }
            try require(ShortcutValidator.registrationFailed(-9878).contains("-9878"), "Mensagem do erro sem o código")
        }

        test("Gravador: combinação, F, toque duplo, Caps Lock, só modificadores, Esc e Delete") {
            var recording = ShortcutRecording(system: FakeSystemShortcuts([]), translator: us)
            try require(recording.keyDown(keyCode: 40, flags: [.control, .option, .command])
                        == .recorded(.keys(keyCode: 40, modifiers: ctrl | opt | cmd), notice: nil, side: nil), "⌃⌥⌘K")
            try require(recording.keyDown(keyCode: 96, flags: [.function])
                        == .recorded(.keys(keyCode: 96, modifiers: 0), notice: ShortcutValidator.functionKeyNotice, side: nil), "F5 com fn")
            try require(recording.keyDown(keyCode: 40, flags: []) == .rejected(ShortcutValidator.needsCommandOrControl), "K sozinho")
            try require(recording.keyDown(keyCode: 53, flags: []) == .cancel && recording.keyDown(keyCode: 51, flags: []) == .clear, "Esc e Delete")
            try require(recording.flagsChanged(keyCode: 61, flags: [.option], time: 1) == .recording
                        && recording.flagsChanged(keyCode: 61, flags: [], time: 1.05) == .recording, "Primeiro toque")
            try require(recording.flagsChanged(keyCode: 61, flags: [.option], time: 1.2) == .recording, "Segundo toque, apertado")
            try require(recording.flagsChanged(keyCode: 61, flags: [], time: 1.25) == .recorded(.doubleTap(modifier: .option, side: .any), notice: nil, side: .right),
                        "Toque duplo de ⌥ direito")
            // Modifiers alone keep recording; a combination in progress is not a tap.
            try require(recording.flagsChanged(keyCode: 55, flags: [.command], time: 2) == .recording
                        && recording.flagsChanged(keyCode: 56, flags: [.command, .shift], time: 2.05) == .recording
                        && recording.flagsChanged(keyCode: 56, flags: [.command], time: 2.1) == .recording
                        && recording.flagsChanged(keyCode: 55, flags: [], time: 2.15) == .recording
                        && recording.flagsChanged(keyCode: 55, flags: [.command], time: 2.2) == .recording
                        && recording.flagsChanged(keyCode: 55, flags: [], time: 2.25) == .recording, "⌘⇧ virou toque duplo")
            var caps = ShortcutRecording(system: FakeSystemShortcuts([]), translator: us)
            _ = caps.flagsChanged(keyCode: 57, flags: [.capsLock], time: 3)
            _ = caps.flagsChanged(keyCode: 57, flags: [], time: 3.05)
            _ = caps.flagsChanged(keyCode: 57, flags: [.capsLock], time: 3.2)
            try require(caps.flagsChanged(keyCode: 57, flags: [], time: 3.25) == .rejected(ShortcutValidator.doubleTapModifiers), "Caps Lock aceito")
        }

        test("Toque duplo: dispara em ⌥↓⌥↑⌥↓⌥↑ e não em lento, segurado, outro modificador, lado errado, 3º toque ou ⌘C") {
            func run(_ detector: DoubleTapDetector, _ events: [(UInt16, CGEventFlags, TimeInterval, UInt32)]) -> [Bool] {
                var detector = detector
                detector.maxGap = 0.4
                return events.map { detector.handle(ModifierChange(keyCode: $0.0, flags: $0.1, time: $0.2, keyDowns: $0.3)) }
            }
            let option = DoubleTapDetector(modifier: .option, side: .any)
            let alt = CGEventFlags.maskAlternate
            let quick: [(UInt16, CGEventFlags, TimeInterval, UInt32)] = [(58, alt, 0, 0), (58, [], 0.05, 0), (58, alt, 0.2, 0), (58, [], 0.25, 0)]
            try require(run(option, quick) == [false, false, false, true], "Não disparou")
            try require(!run(option, [(58, alt, 0, 0), (58, [], 0.05, 0), (58, alt, 0.55, 0), (58, [], 0.6, 0)]).contains(true), "Lento disparou")
            try require(!run(option, [(58, alt, 0, 0), (58, [], 0.35, 0), (58, alt, 0.4, 0), (58, [], 0.45, 0)]).contains(true), "Segurado disparou")
            try require(!run(option, [(58, alt, 0, 0), (56, [alt, .maskShift], 0.02, 0), (56, alt, 0.03, 0), (58, [], 0.05, 0),
                                      (58, alt, 0.2, 0), (58, [], 0.25, 0)]).contains(true), "Com ⇧ no meio disparou")
            try require(!run(DoubleTapDetector(modifier: .option, side: .left), quick.map { (61, $0.1, $0.2, $0.3) }).contains(true), "Lado errado disparou")
            try require(run(DoubleTapDetector(modifier: .option, side: .right), quick.map { (61, $0.1, $0.2, $0.3) }).last == true, "Lado certo não disparou")
            let third = quick + [(58, alt, 0.35, 0), (58, [], 0.4, 0)]
            try require(run(option, third) == [false, false, false, true, false, false], "O 3º toque disparou de novo")
            // ⌘C then ⌘ again: the key pressed while ⌘ was held breaks the tap.
            let command = DoubleTapDetector(modifier: .command, side: .any)
            try require(!run(command, [(55, .maskCommand, 0, 10), (55, [], 0.1, 11), (55, .maskCommand, 0.2, 11), (55, [], 0.25, 11)]).contains(true),
                        "⌘C seguido de ⌘ disparou")
            try require(!run(command, [(55, .maskCommand, 0, 10), (55, [], 0.05, 10), (55, .maskCommand, 0.2, 10), (55, [], 0.3, 11)]).contains(true),
                        "⌘⌘C disparou")
            try require(DoubleTapDetector.eventMask == CGEventMask(1 << CGEventType.flagsChanged.rawValue), "Máscara além de flagsChanged")
        }

        test("Permissão: sem Monitoramento de Entrada explica e não cria o tap; com ela, o tap tem só flagsChanged") {
            let preferences = AppPreferences.disposable()
            let taps = FakeModifierTapSource(hasAccess: false)
            let center = GlobalHotKeyCenter(preferences: preferences, registrar: FakeHotKeyRegistrar(), taps: taps,
                                            system: FakeSystemShortcuts([])) {}
            let recorder = ShortcutRecorderModel(center: center, translator: us)
            recorder.handle(.recorded(.doubleTap(modifier: .option, side: .any), notice: nil, side: .left))
            try require(recorder.explainPermission && taps.masks.isEmpty && center.status == .waitingForPermission
                        && preferences.menuShortcut == .doubleTap(modifier: .option, side: .any), "Sem permissão: explicação, nenhum tap, salvo inativo")
            recorder.allow()
            try require(taps.requests == 1 && !recorder.explainPermission, "Permitir… não pediu ao macOS")
            taps.hasAccess = true
            center.refreshPermission()
            try require(taps.masks == [CGEventMask(1 << CGEventType.flagsChanged.rawValue)] && center.status == .active,
                        "Tap criado com máscara diferente de flagsChanged: \(taps.masks)")
            // The detector reaches the trigger through the tap.
            var fired = 0
            let firing = GlobalHotKeyCenter(preferences: AppPreferences.disposable(), registrar: FakeHotKeyRegistrar(),
                                            taps: FakeModifierTapSource(hasAccess: true), system: FakeSystemShortcuts([])) { fired += 1 }
            _ = firing.save(.doubleTap(modifier: .option, side: .any))
            let source = firing.taps as! FakeModifierTapSource
            for (flags, time) in [(CGEventFlags.maskAlternate, 0.0), ([], 0.05), (.maskAlternate, 0.2), ([], 0.25)] {
                source.handler?(ModifierChange(keyCode: 58, flags: flags, time: time, keyDowns: 0))
            }
            try require(fired == 1, "Toque duplo não abriu o menu")
            recorder.setAnySide(false)
            try require(preferences.menuShortcut == .doubleTap(modifier: .option, side: .left), "Qualquer lado desligado não guardou o lado tocado")
            recorder.clear()
            try require(taps.stops > 0 && preferences.menuShortcut == nil && center.status == .none, "Limpar não removeu o tap")
        }

        test("Centro: registra ao definir, cancela ao limpar, suspende ao gravar, reaplica ao cancelar; falha mantém salvo") {
            let preferences = AppPreferences.disposable()
            let registrar = FakeHotKeyRegistrar()
            let center = GlobalHotKeyCenter(preferences: preferences, registrar: registrar, taps: FakeModifierTapSource(hasAccess: false),
                                            system: FakeSystemShortcuts([])) {}
            try require(registrar.registered == nil && center.status == .none, "Registrou sem atalho")
            preferences.menuShortcut = .keys(keyCode: 40, modifiers: ctrl | opt | cmd)
            try require(registrar.registered?.keyCode == 40 && registrar.registered?.modifiers == ctrl | opt | cmd && center.status == .active, "Não registrou")
            let recorder = ShortcutRecorderModel(center: center, translator: us)
            recorder.start()
            try require(registrar.registered == nil && center.status == .suspended, "Não suspendeu durante a gravação")
            recorder.cancel()
            try require(registrar.registered?.keyCode == 40 && center.status == .active && !recorder.recording, "Não reaplicou ao cancelar")
            // macOS refuses a new one: nothing saved, the previous stays.
            registrar.refused[14] = OSStatus(eventHotKeyExistsErr)
            recorder.handle(.recorded(.keys(keyCode: 14, modifiers: ctrl | cmd), notice: nil, side: nil))
            try require(preferences.menuShortcut == .keys(keyCode: 40, modifiers: ctrl | opt | cmd)
                        && recorder.message == ShortcutValidator.registrationFailed(OSStatus(eventHotKeyExistsErr))
                        && registrar.registered?.keyCode == 40, "Recusa do macOS salvou ou perdeu o anterior")
            // At launch, a saved shortcut that fails stays saved and reports it.
            let failing = FakeHotKeyRegistrar()
            failing.refused[105] = -50
            let saved = AppPreferences.disposable()
            saved.menuShortcut = .keys(keyCode: 105, modifiers: 0)
            let launched = GlobalHotKeyCenter(preferences: saved, registrar: failing, taps: FakeModifierTapSource(hasAccess: false),
                                              system: FakeSystemShortcuts([])) {}
            try require(launched.status == .failed(-50) && saved.menuShortcut == .keys(keyCode: 105, modifiers: 0), "Falha na abertura apagou ou escondeu")
            recorder.clear()
            try require(registrar.registered == nil && preferences.menuShortcut == nil && center.status == .none, "Limpar não cancelou")
        }

        test("Disparo: o evento falso abre e fecha o menu com o foco na busca; com janela modal, é ignorado") {
            let (model, _) = try makeModel()
            let menuBar = MenuBarCoordinator(model: model)
            menuBar.announce = { _ in }
            let presenter = FakeMenuPresenter()
            menuBar.installMenuBar(host: FakeStatusItemHost(), presenter: presenter)
            let registrar = FakeHotKeyRegistrar()
            let preferences = AppPreferences.disposable()
            let center = GlobalHotKeyCenter(preferences: preferences, registrar: registrar, taps: FakeModifierTapSource(hasAccess: false),
                                            system: FakeSystemShortcuts([])) { menuBar.toggleMenu(focusSearch: true) }
            preferences.menuShortcut = .keys(keyCode: 40, modifiers: ctrl | opt | cmd)
            let focus = menuBar.searchFocusRequest
            registrar.onPressed?()
            try require(presenter.isOpen && menuBar.searchFocusRequest == focus + 1, "O atalho não abriu o menu na busca")
            registrar.onPressed?()
            try require(!presenter.isOpen, "O atalho não alternou")
            menuBar.hasModalWindow = { true }
            registrar.onPressed?()
            try require(!presenter.isOpen, "Abriu com janela modal")
            _ = center
        }

        test("Nomes: ⌃⌥⌘K, ⇧⌘F5, F13, layout não-US e VoiceOver por extenso") {
            try require(KeyNames.symbols(.keys(keyCode: 40, modifiers: ctrl | opt | cmd), translator: us) == "⌃⌥⌘K", "⌃⌥⌘K")
            try require(KeyNames.symbols(.keys(keyCode: 96, modifiers: shift | cmd), translator: us) == "⇧⌘F5", "⇧⌘F5")
            try require(KeyNames.symbols(.keys(keyCode: 105, modifiers: 0), translator: us) == "F13", "F13")
            try require(KeyNames.symbols(.keys(keyCode: 6, modifiers: cmd | opt), translator: FakeKeyTranslator([6: "Y"])) == "⌥⌘Y", "QWERTZ")
            try require(KeyNames.symbols(.keys(keyCode: 49, modifiers: ctrl), translator: us) == "⌃␣", "Espaço")
            try require(KeyNames.spoken(.keys(keyCode: 40, modifiers: ctrl | opt | cmd), translator: us) == "Control Option Command K", "Por extenso")
            try require(KeyNames.symbols(.doubleTap(modifier: .option, side: .any)) == "⌥ ⌥"
                        && KeyNames.symbols(.doubleTap(modifier: .option, side: .right)) == "⌥ ⌥ direito", "Toque duplo")
            try require(KeyNames.spoken(.doubleTap(modifier: .command, side: .any)) == "Command duas vezes", "Toque duplo por extenso")
        }

        test("Executor: o centro de produção não é criado e nenhum atalho ou tap real existe") {
            try require(MenuBarCoordinator.isLocalChecks, "Executor sem o identificador de verificações locais")
            let (model, _) = try makeModel()
            let menuBar = MenuBarCoordinator(model: model)
            try require(GlobalHotKeyCenter.production(menuBar: menuBar) == nil, "Centro de produção criado no executor")
            try require(menuBar.hotKeys == nil && menuBar.statusItem == nil && menuBar.progressPresenter == nil, "Coordenador com peças reais por padrão")
        }
        return failures
    }

    private static func makeModel() throws -> (AppModel, [Connection]) {
        let store = try JSONStore(directory: FileManager.default.temporaryDirectory.appendingPathComponent("VPNGUI-hotkey-\(UUID())"))
        let connections = [Connection(name: "A", server: "vpn.invalid", port: 443, username: "test"),
                           Connection(name: "B", server: "vpn2.invalid", port: 443, username: "test")]
        try store.save(SavedData(connections: connections))
        return (AppModel(store: store, passwords: PasswordStore(service: "com.luiz.vpngui.tests.hotkey.\(UUID())"),
                         service: HelperTests.readyService()), connections)
    }
}

@MainActor
final class FakeHotKeyRegistrar: HotKeyRegistrar {
    var onPressed: (() -> Void)?
    private(set) var registered: (keyCode: UInt32, modifiers: UInt32)?
    /// Key codes macOS "refuses", with the status it returns.
    var refused: [UInt32: OSStatus] = [:]
    func register(keyCode: UInt32, modifiers: UInt32) -> OSStatus {
        if let status = refused[keyCode] { return status }
        registered = (keyCode, modifiers)
        return noErr
    }
    func unregister() { registered = nil }
}

@MainActor
final class FakeModifierTapSource: ModifierTapSource {
    var hasAccess: Bool
    private(set) var requests = 0, stops = 0
    private(set) var masks: [CGEventMask] = []
    private(set) var handler: ((ModifierChange) -> Void)?
    init(hasAccess: Bool) { self.hasAccess = hasAccess }
    func requestAccess() { requests += 1 }
    func start(mask: CGEventMask, handler: @escaping (ModifierChange) -> Void) -> Bool {
        masks.append(mask)
        self.handler = handler
        return true
    }
    func stop() { stops += 1; handler = nil }
}

struct FakeSystemShortcuts: SystemShortcutProvider {
    let list: [(keyCode: UInt32, modifiers: UInt32)]
    init(_ list: [(UInt32, UInt32)]) { self.list = list.map { (keyCode: $0.0, modifiers: $0.1) } }
    func enabledShortcuts() -> [(keyCode: UInt32, modifiers: UInt32)] { list }
}

struct FakeKeyTranslator: KeyTranslator {
    let map: [UInt16: String]
    init(_ map: [UInt16: String]) { self.map = map }
    func character(for keyCode: UInt16) -> String? { map[keyCode] }
}
