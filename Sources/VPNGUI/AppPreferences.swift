import Foundation
import SwiftUI
import AppKit
import ServiceManagement
import VPNHelperShared

/// App preferences in the app's own UserDefaults. Nothing sensitive is stored here:
/// passwords and SAML cookies stay in the Keychain. Absent DNS preferences leave system DNS unchanged.
@MainActor
final class AppPreferences: ObservableObject {
    enum Key {
        static let showMenuBarIcon = "showMenuBarIcon"
        static let hideDockOnClose = "hideDockOnClose"
        static let checkForUpdates = "checkForUpdatesAutomatically"
        static let includePrereleases = "includePrereleaseUpdates"
        static let skippedVersion = "skippedUpdateVersion"
        static let lastUpdateAttempt = "lastUpdateCheckAttempt"
        static let lastUpdateSuccess = "lastUpdateCheckSuccess"
        static let cachedOffer = "pendingUpdateOffer"
        static let internetDNS = "internetDNSSelection"
        static let customDNS = "customInternetDNS"
        static let appearance = "appearance"
        /// Read by Foundation at launch: the app's own language order (as set by System
        /// Settings › Language & Region › Applications).
        static let languages = "AppleLanguages"
    }

    let defaults: UserDefaults
    /// Suite removed when this object goes away (local checks only).
    private let disposableSuite: String?

    @Published var showMenuBarIcon: Bool { didSet { defaults.set(showMenuBarIcon, forKey: Key.showMenuBarIcon) } }
    /// Stored choice; `hidesDockOnClose` is what the app applies.
    @Published var hideDockOnClose: Bool { didSet { defaults.set(hideDockOnClose, forKey: Key.hideDockOnClose) } }
    @Published var checkForUpdates: Bool { didSet { defaults.set(checkForUpdates, forKey: Key.checkForUpdates) } }
    @Published var includePrereleases: Bool { didSet { defaults.set(includePrereleases, forKey: Key.includePrereleases) } }
    @Published var skippedVersion: String? { didSet { store(skippedVersion, Key.skippedVersion) } }
    @Published var lastUpdateAttempt: Date? { didSet { store(lastUpdateAttempt, Key.lastUpdateAttempt) } }
    @Published var lastUpdateSuccess: Date? { didSet { store(lastUpdateSuccess, Key.lastUpdateSuccess) } }
    /// Id of the chosen "DNS da internet" (preset, custom or `InternetDNSOption.offID`).
    @Published var internetDNSSelection: String { didSet { defaults.set(internetDNSSelection, forKey: Key.internetDNS) } }
    /// Light, dark or following the system (the default).
    @Published var appearance: AppAppearance { didSet { defaults.set(appearance.rawValue, forKey: Key.appearance) } }
    /// Takes effect when the app opens again; `launchLanguage` is the one in use now.
    @Published var language: AppLanguage {
        didSet {
            if language == .system { languageDefaults.removeObject(forKey: Key.languages) }
            else { languageDefaults.set([language.rawValue], forKey: Key.languages) }
        }
    }
    let launchLanguage: AppLanguage
    @Published var customInternetDNS: [InternetDNSOption] {
        didSet { defaults.set(try? JSONEncoder().encode(customInternetDNS), forKey: Key.customDNS) }
    }

    /// Where AppleLanguages is kept: the preferences themselves, or the app's real domain
    /// for the demo, whose other preferences are disposable but whose relaunch must keep it.
    private let languageDefaults: UserDefaults

    init(defaults: UserDefaults, disposableSuite: String? = nil,
         currentVersion: String = HelperConstants.releaseVersion, realLanguage: Bool = false) {
        self.defaults = defaults
        self.disposableSuite = disposableSuite
        languageDefaults = realLanguage ? .standard : defaults
        showMenuBarIcon = defaults.object(forKey: Key.showMenuBarIcon) as? Bool ?? true
        hideDockOnClose = defaults.object(forKey: Key.hideDockOnClose) as? Bool ?? true
        checkForUpdates = defaults.object(forKey: Key.checkForUpdates) as? Bool ?? true
        // Testers of a release candidate keep receiving candidates; stable users do not.
        includePrereleases = defaults.object(forKey: Key.includePrereleases) as? Bool
            ?? (ReleaseVersion(currentVersion)?.isPrerelease ?? false)
        skippedVersion = defaults.string(forKey: Key.skippedVersion)
        lastUpdateAttempt = defaults.object(forKey: Key.lastUpdateAttempt) as? Date
        lastUpdateSuccess = defaults.object(forKey: Key.lastUpdateSuccess) as? Date
        internetDNSSelection = defaults.string(forKey: Key.internetDNS) ?? InternetDNSOption.defaultID
        appearance = defaults.string(forKey: Key.appearance).flatMap(AppAppearance.init(rawValue:)) ?? .automatic
        // Only the app's own domain: the global AppleLanguages is the system's choice.
        let domain = languageDefaults.persistentDomain(forName: (realLanguage ? nil : disposableSuite) ?? Bundle.main.bundleIdentifier ?? "")
        let saved = AppLanguage(tag: (domain?[Key.languages] as? [String])?.first)
        language = saved
        launchLanguage = saved
        customInternetDNS = defaults.data(forKey: Key.customDNS).flatMap { try? JSONDecoder().decode([InternetDNSOption].self, from: $0) } ?? []
    }

    var internetDNSOptions: [InternetDNSOption] { InternetDNSOption.presets + customInternetDNS }

    /// Servers sent with each connection; nil when the user chose not to change the DNS.
    /// An unknown selection leaves the system DNS unchanged.
    var internetDNSServers: [String]? {
        guard internetDNSSelection != InternetDNSOption.offID else { return nil }
        return internetDNSOptions.first { $0.id == internetDNSSelection }?.servers
    }

    func addCustomDNS(_ option: InternetDNSOption) {
        customInternetDNS.append(option)
        internetDNSSelection = option.id
    }

    func removeCustomDNS(_ id: String) {
        customInternetDNS.removeAll { $0.id == id }
        if internetDNSSelection == id { internetDNSSelection = InternetDNSOption.defaultID }
    }

    deinit {
        if let disposableSuite { UserDefaults.standard.removePersistentDomain(forName: disposableSuite) }
    }

    /// Real preferences in the app; an isolated, disposable suite in the local checks runner.
    static func forCurrentProcess() -> AppPreferences {
        if MenuBarCoordinator.isLocalChecks { return disposable() }
        return AppPreferences(defaults: .standard)
    }

    /// Isolated suite that never touches the user's preferences and is deleted afterwards.
    static func disposable(currentVersion: String = HelperConstants.releaseVersion,
                           realLanguage: Bool = false) -> AppPreferences {
        let name = "com.luiz.vpngui.tests.preferences.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: name)!
        return AppPreferences(defaults: defaults, disposableSuite: name, currentVersion: currentVersion,
                              realLanguage: realLanguage)
    }

    /// Binding for MenuBarExtra(isInserted:). SwiftUI writes the current value back while
    /// it builds the scenes; publishing that echo re-evaluated the App body, which wrote
    /// again, recursing until the stack overflowed (0.3.0-rc.4). Only real changes publish.
    func menuBarIconBinding(enabled: Bool = true) -> Binding<Bool> {
        Binding(get: { [weak self] in enabled && (self?.showMenuBarIcon ?? true) },
                set: { [weak self] value in
                    guard enabled, let self, self.showMenuBarIcon != value else { return }
                    self.showMenuBarIcon = value
                })
    }

    /// The app must never become invisible: without the menu bar icon it stays in the Dock.
    var hidesDockOnClose: Bool { showMenuBarIcon && hideDockOnClose }

    /// Last offer found, so the pending state survives a relaunch without a new request.
    var cachedOffer: UpdateOffer? {
        get { defaults.data(forKey: Key.cachedOffer).flatMap { try? JSONDecoder().decode(UpdateOffer.self, from: $0) } }
        set { store(newValue.flatMap { try? JSONEncoder().encode($0) }, Key.cachedOffer) }
    }

    private func store(_ value: Any?, _ key: String) {
        if let value { defaults.set(value, forKey: key) } else { defaults.removeObject(forKey: key) }
    }
}

// MARK: - Open at login

/// Login item API used by the controller. Production: SMAppService.mainApp.
@MainActor
protocol LoginItemService: AnyObject {
    var status: SMAppService.Status { get }
    func register() throws
    func unregister() throws
    func openSystemSettings()
}

@MainActor
final class MainAppLoginItem: LoginItemService {
    var status: SMAppService.Status { SMAppService.mainApp.status }
    func register() throws { try SMAppService.mainApp.register() }
    func unregister() throws { try SMAppService.mainApp.unregister() }
    func openSystemSettings() { SMAppService.openSystemSettingsLoginItems() }
}

/// "Abrir ao iniciar o Mac" (a login item). Reads the real registration state; never registers
/// anything in the local checks runner or in ad hoc builds.
@MainActor
final class LoginItemController: ObservableObject {
    @Published private(set) var status: SMAppService.Status = .notRegistered
    @Published var message: String?
    let unavailableReason: String?
    private let service: LoginItemService?

    init(service: LoginItemService?, unavailableReason: String? = nil) {
        self.service = service
        self.unavailableReason = service == nil ? (unavailableReason ?? String(localized: "Indisponível neste build.")) : unavailableReason
        refresh()
    }

    static func production() -> LoginItemController {
        if MenuBarCoordinator.isLocalChecks {
            return LoginItemController(service: nil, unavailableReason: String(localized: "Desativado no executor de verificações e na revisão visual."))
        }
        if case .unavailable = CodeTrust.localPolicy() {
            return LoginItemController(service: nil, unavailableReason: String(localized: "Build sem assinatura Apple (ad hoc): use o app instalado pelo Homebrew."))
        }
        return LoginItemController(service: MainAppLoginItem())
    }

    var available: Bool { service != nil && unavailableReason == nil }
    var enabled: Bool { status == .enabled || status == .requiresApproval }

    func refresh() {
        guard available, let service else { return }
        status = service.status
    }

    func setEnabled(_ enable: Bool) {
        guard available, let service else { return }
        message = nil
        do {
            if enable { try service.register() } else { try service.unregister() }
        } catch {
            message = (enable ? String(localized: "Não foi possível ativar: ") : String(localized: "Não foi possível desativar: ")) + error.localizedDescription
        }
        status = service.status
    }

    func openSystemSettings() { service?.openSystemSettings() }

    var detail: String? {
        if let unavailableReason { return unavailableReason }
        if let message { return message }
        switch status {
        case .enabled: return nil
        case .requiresApproval: return String(localized: "Aprove em Ajustes do Sistema › Itens de Início.")
        case .notFound: return String(localized: "Instale o app em Aplicativos para usar isto.")
        default: return nil
        }
    }
}

/// Language chosen in Configurações › Geral. System follows System Settings › Language &
/// Region; the others are written to the app's AppleLanguages and apply on the next launch.
enum AppLanguage: String, CaseIterable, Identifiable {
    case system, english = "en", german = "de", spanish = "es", french = "fr", hindi = "hi", portuguese = "pt-BR"
    var id: String { rawValue }

    /// A tag from AppleLanguages ("de", "pt-BR", "es-419"); unknown ones mean the system's choice.
    init(tag: String?) {
        guard let tag else { self = .system; return }
        let code = Locale(identifier: tag).language.languageCode?.identifier ?? tag
        self = code == "pt" ? .portuguese : AppLanguage(rawValue: code).flatMap { $0 == .system ? nil : $0 } ?? .system
    }

    /// Each language by its own name, so it can be found whatever the current one.
    var title: String {
        switch self {
        case .system: return String(localized: "Sistema")
        case .english: return "English"
        case .german: return "Deutsch"
        case .spanish: return "Español"
        case .french: return "Français"
        case .hindi: return "हिन्दी"
        case .portuguese: return "Português"
        }
    }
}

/// App-wide appearance chosen in Configurações › Geral. Automatic follows macOS.
enum AppAppearance: String, CaseIterable, Identifiable {
    case light, dark, automatic
    var id: String { rawValue }
    var title: String {
        switch self {
        case .automatic: return String(localized: "Automático")
        case .light: return String(localized: "Claro")
        case .dark: return String(localized: "Escuro")
        }
    }
    /// nil lets every window follow the system appearance.
    var nsAppearance: NSAppearance? {
        switch self {
        case .automatic: return nil
        case .light: return NSAppearance(named: .aqua)
        case .dark: return NSAppearance(named: .darkAqua)
        }
    }
}
