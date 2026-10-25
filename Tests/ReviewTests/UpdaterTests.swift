import XCTest
import Sparkle
@testable import VPNApp

final class UpdaterTests: XCTestCase {
    func testOnlyAuthenticatedUpdaterInActiveSessionCanQuitHiddenApp() {
        let updater = QuitRequest(senderBundleID: "org.sparkle-project.Sparkle.Updater",
                                  isTrustedUpdater: true, hasSystemReason: false)
        XCTAssertFalse(updater.isAutomaticQuit(menuBarIcon: true, windowVisible: false, updaterBusy: true))
        XCTAssertTrue(updater.isAutomaticQuit(menuBarIcon: true, windowVisible: false, updaterBusy: false))
        let impostor = QuitRequest(senderBundleID: "org.sparkle-project.Sparkle.Updater", hasSystemReason: false)
        XCTAssertTrue(impostor.isAutomaticQuit(menuBarIcon: true, windowVisible: false, updaterBusy: true))
        let utility = QuitRequest(senderBundleID: "example.autoquit", hasSystemReason: false)
        XCTAssertTrue(utility.isAutomaticQuit(menuBarIcon: true, windowVisible: false, updaterBusy: true))
    }

    @MainActor func testCancelledQuitWithoutInstallKeepsNormalState() {
        let updater = AppUpdater(checker: nil, enabled: false)
        updater.quitCancelled()
        XCTAssertFalse(updater.awaitingQuit)
        XCTAssertFalse(updater.busy)
    }

    @MainActor func testFeedMustMatchOfferedArchive() throws {
        let version = "0.5.0-rc.6"
        let url = "https://github.com/luizmz94/tunnelmac/releases/download/v\(version)/TunnelMac-\(version)-\(AppUpdater.architecture).zip"
        func item(_ url: String, short: String = "0.5.0", type: String = "application") throws -> SUAppcastItem {
            try XCTUnwrap(SUAppcastItem(dictionary: [
                "sparkle:version": "30", "sparkle:shortVersionString": short,
                "enclosure": ["url": url, "sparkle:installationType": type]
            ]))
        }
        XCTAssertTrue(AppUpdater.matchesOffer(try item(url), version: version))
        XCTAssertFalse(AppUpdater.matchesOffer(try item(url), version: nil))
        XCTAssertFalse(AppUpdater.matchesOffer(try item(url), version: "0.5.0-rc.7"))
        XCTAssertFalse(AppUpdater.matchesOffer(try item(url.replacingOccurrences(of: "github.com", with: "example.com")), version: version))
        XCTAssertFalse(AppUpdater.matchesOffer(try item(url + "?redirect=1"), version: version))
        XCTAssertFalse(AppUpdater.matchesOffer(try item(url, short: "0.6.0"), version: version))
        XCTAssertFalse(AppUpdater.matchesOffer(try item(url, type: "package"), version: version))
    }
}
