import AppKit
import Sparkle
import VPNHelperShared

// In-app installation of a release found by UpdateChecker, with Sparkle 2. Sparkle never
// schedules checks of its own (SUEnableAutomaticChecks is off): its feed is the appcast
// attached to the offered GitHub release, so the version it installs is always the one the
// app announced. Sparkle verifies the archive's EdDSA signature (SUPublicEDKey, also the
// signed feed) and the new bundle’s code signature before replacing it (Sparkle permits identity rotation);
// quitting goes through applicationShouldTerminate, which disconnects the VPNs first.

@MainActor
final class AppUpdater: NSObject, ObservableObject {
    /// Release asset with the appcast of one architecture (scripts/appcast.py).
    static var architecture: String {
        #if arch(arm64)
        "arm64"
        #else
        "x86_64"
        #endif
    }

    static func feedURL(for version: String) -> URL? {
        guard let release = ReleaseVersion(version) else { return nil }
        return URL(string: UpdateFeed.releasePagePrefix + "download/v\(release)/appcast-\(architecture).xml")
    }

    /// Bind even a validly signed feed to the release and architecture the user accepted.
    static func matchesOffer(_ item: SUAppcastItem, version: String?) -> Bool {
        guard let version, let release = ReleaseVersion(version) else { return false }
        let expected = UpdateFeed.releasePagePrefix + "download/v\(release)/TunnelMac-\(release)-\(architecture).zip"
        return item.fileURL?.absoluteString == expected && item.installationType == "application"
            && item.displayVersionString == "\(release.major).\(release.minor).\(release.patch)"
    }

    /// False in the local checks runner and when Sparkle refused to start (bundle without
    /// its key or framework); the settings then show the Homebrew and GitHub instructions.
    @Published private(set) var available = false
    /// A Sparkle session (check, download, install) is running.
    @Published private(set) var busy = false

    private weak var checker: UpdateChecker?
    private var controller: SPUStandardUpdaterController?
    private var feedVersion: String?
    private let activate: () -> Void

    init(checker: UpdateChecker?, enabled: Bool, activate: @escaping () -> Void = {}) {
        self.checker = checker
        self.activate = activate
        super.init()
        guard enabled else { return }
        let controller = SPUStandardUpdaterController(startingUpdater: false, updaterDelegate: self, userDriverDelegate: self)
        do {
            try controller.updater.start()
            // Never on its own schedule, even if an older default says otherwise.
            controller.updater.automaticallyChecksForUpdates = false
            controller.updater.automaticallyDownloadsUpdates = false
            self.controller = controller
            available = true
        } catch {
            NSLog("TunnelMac: atualização pelo app indisponível: %@", error.localizedDescription)
        }
    }

    /// Visual review only: the "Atualizar agora" layout, without Sparkle (install does nothing).
    static func preview(checker: UpdateChecker) -> AppUpdater {
        let updater = AppUpdater(checker: checker, enabled: false)
        updater.available = true
        return updater
    }

    static func production(checker: UpdateChecker, activate: @escaping () -> Void) -> AppUpdater {
        let bundled = Bundle.main.object(forInfoDictionaryKey: "SUPublicEDKey") != nil
        return AppUpdater(checker: checker, enabled: bundled && !MenuBarCoordinator.isLocalChecks, activate: activate)
    }

    var canInstall: Bool { available && !busy }

    /// "Atualizar agora": Sparkle shows the notes, downloads with progress and relaunches.
    func install(_ offer: UpdateOffer) {
        if busy { return activate() } // Sparkle's window is already open.
        guard let updater = controller?.updater, prepare(offer) else { return }
        activate()
        updater.checkForUpdates()
    }

    /// After the launch check: the same window, unless Sparkle has this version skipped.
    /// A missing or invalid appcast fails silently here; the card still offers the update.
    /// The app comes forward only when the window is about to be shown.
    func present(_ offer: UpdateOffer) {
        guard let updater = controller?.updater, prepare(offer) else { return }
        updater.checkForUpdatesInBackground()
    }

    private func prepare(_ offer: UpdateOffer) -> Bool {
        guard !busy, let updater = controller?.updater, updater.canCheckForUpdates,
              Self.feedURL(for: offer.version) != nil else { return false }
        feedVersion = offer.version
        busy = true
        return true
    }
}

extension AppUpdater: SPUUpdaterDelegate {
    nonisolated func feedURLString(for updater: SPUUpdater) -> String? {
        MainActor.assumeIsolated { feedVersion.flatMap(Self.feedURL(for:))?.absoluteString }
    }

    nonisolated func updater(_ updater: SPUUpdater, shouldProceedWithUpdate updateItem: SUAppcastItem,
                             updateCheck: SPUUpdateCheck) throws {
        try MainActor.assumeIsolated {
            guard Self.matchesOffer(updateItem, version: feedVersion) else {
                throw NSError(domain: "TunnelMac.Updater", code: 1,
                              userInfo: [NSLocalizedDescriptionKey: "A atualização não corresponde à versão oferecida. Tente verificar novamente."])
            }
        }
    }

    /// Our own choices mirror Sparkle's buttons: skip and "later" act on the card too.
    nonisolated func updater(_ updater: SPUUpdater, userDidMake choice: SPUUserUpdateChoice,
                             forUpdate updateItem: SUAppcastItem, state: SPUUserUpdateState) {
        MainActor.assumeIsolated {
            // A periodic check may have replaced the card while Sparkle was open.
            guard checker?.offer?.version == feedVersion else { return }
            switch choice {
            case .skip: checker?.skipOffer()
            case .dismiss: checker?.postpone()
            case .install: break
            @unknown default: break
            }
        }
    }

    nonisolated func updater(_ updater: SPUUpdater, didFinishUpdateCycleFor updateCheck: SPUUpdateCheck, error: Error?) {
        MainActor.assumeIsolated { busy = false }
    }
}

extension AppUpdater: SPUStandardUserDriverDelegate {
    /// The app activates itself before Sparkle shows a background-found update, so the
    /// window gets focus even while only the menu bar icon is visible.
    nonisolated var supportsGentleScheduledUpdateReminders: Bool { true }

    nonisolated func standardUserDriverShouldHandleShowingScheduledUpdate(_ update: SUAppcastItem, andInImmediateFocus immediateFocus: Bool) -> Bool {
        true
    }

    nonisolated func standardUserDriverWillHandleShowingUpdate(_ handleShowingUpdate: Bool, forUpdate update: SUAppcastItem,
                                                               state: SPUUserUpdateState) {
        MainActor.assumeIsolated { if handleShowingUpdate && !state.userInitiated { activate() } }
    }

    nonisolated func standardUserDriverRequestsVersionDisplayer() -> SUVersionDisplay? {
        MainActor.assumeIsolated { ReleaseVersionDisplay(update: feedVersion) }
    }
}

/// CFBundleShortVersionString has no -rc suffix: show the release versions instead,
/// "0.5.0-rc.6 (você tem 0.5.0-rc.5)" rather than "0.5.0 (você tem 0.5.0)".
final class ReleaseVersionDisplay: NSObject, SUVersionDisplay {
    let update: String?
    let installed: String
    init(update: String?, installed: String = HelperConstants.releaseVersion) {
        self.update = update
        self.installed = installed
    }

    func formatUpdateVersion(fromUpdate update: SUAppcastItem,
                            andBundleDisplayVersion inOutBundleDisplayVersion: AutoreleasingUnsafeMutablePointer<NSString>,
                            withBundleVersion bundleVersion: String) -> String {
        inOutBundleDisplayVersion.pointee = installed as NSString
        return self.update ?? update.displayVersionString
    }

    func formatBundleDisplayVersion(_ bundleDisplayVersion: String, withBundleVersion bundleVersion: String,
                                    matchingUpdate: SUAppcastItem?) -> String {
        installed
    }
}
