@testable import VPNApp
import Foundation
import VPNHelperCore
import VPNHelperShared

/// Checks that can run without a GUI, Keychain, sockets or privileged service.
/// This is additional coverage, never a substitute for the full graphical suite.
@MainActor
enum ReleaseTests {
    static func run() -> Int32 {
        var failures: Int32 = 0
        func test(_ name: String, _ work: () throws -> Void) {
            do { try work(); print("PASS: \(name)") }
            catch { failures += 1; print("FAIL: \(name): \(error.localizedDescription)") }
        }
        test("Bundle name, preserved identifiers, version, icon and all three binaries") {
            guard let path = ProcessInfo.processInfo.environment["TUNNELMAC_REVIEW_APP"], let app = Bundle(path: path) else {
                throw TestSupport.Failure("Set TUNNELMAC_REVIEW_APP to the production bundle under test")
            }
            try TestSupport.require(app.bundleURL.lastPathComponent == "TunnelMac.app", "Wrong bundle name")
            try TestSupport.require(app.bundleIdentifier == "com.luiz.vpngui", "App identity changed")
            try TestSupport.require(app.object(forInfoDictionaryKey: "CFBundleName") as? String == "TunnelMac", "Product name")
            try TestSupport.require(app.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String == HelperConstants.version, "Version mismatch")
            for leaf in ["VPNGUI", "VPNHelper", "VPNSupervisor"] {
                try TestSupport.require(FileManager.default.isExecutableFile(atPath: app.bundleURL.appendingPathComponent("Contents/MacOS/" + leaf).path), "Missing binary")
            }
            try TestSupport.require(app.url(forResource: "AppIcon", withExtension: "icns") != nil, "Missing icon")
            try TestSupport.require(HelperConstants.machServiceName == "com.luiz.vpngui.helper" && HelperConstants.stateDirectory == "/private/var/db/com.luiz.vpngui.helper", "Legacy state changed")
            if case .trusted = CodeTrust.localPolicy() { /* certificate-backed build */ }
            else { try TestSupport.require(!ServiceController.production().canConnect, "Ad hoc enabled privileges") }
        }
        test("Absent service detection rejects permission errors and legacy registrations") {
            let missing = "Could not find service \"com.luiz.vpngui.helper\" in domain for system"
            try TestSupport.require(Maintenance.absentServiceReply(status: 113, stderr: missing), "Missing service not recognized")
            try TestSupport.require(!Maintenance.absentServiceReply(status: 0, stderr: missing), "Live registration accepted")
            try TestSupport.require(!Maintenance.absentServiceReply(status: 1, stderr: "Operation not permitted"), "Access failure accepted")
            try TestSupport.require(!Maintenance.absentServiceReply(status: 113, stderr: "Could not find domain"), "Unknown domain accepted")
        }
        test("Rename preserves persisted profile UUID and bytes without migration") {
            let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
            defer { try? FileManager.default.removeItem(at: root) }
            let store = try JSONStore(directory: root.appendingPathComponent("VPNGUI"))
            let profile = Connection(name: "Example", server: "vpn.example.invalid", username: "example")
            try store.save(SavedData(connections: [profile]))
            let before = try Data(contentsOf: store.file)
            let reopened = try JSONStore(directory: root.appendingPathComponent("VPNGUI"))
            try TestSupport.require(try reopened.load().connections == [profile], "Profile changed")
            try TestSupport.require(try Data(contentsOf: reopened.file) == before, "Data rewritten during rename")
            try TestSupport.require(PasswordStore().service == "com.luiz.vpngui.password", "Password service changed")
        }
        test("Global maintenance handshake, start gate, owner cancellation and disconnect recovery") {
            let root = try HelperFixture.temporaryRoot()
            defer { try? FileManager.default.removeItem(atPath: root) }
            let core = HelperCore(HelperCore.Configuration(stateDirectory: root + "/state",
                ownership: TrustedOwnership(owners: [getuid()], anchor: root), supervisorSource: SupervisorLocator.path,
                supervisorRequirement: nil, helperVersion: HelperConstants.fullVersion, probeIdentity: nil,
                authorizer: FakeAuthorizer(), idleTimeout: 3600))
            defer { core.shutdown(timeout: 2) }
            let one = core.connect(uid: getuid(), auditSession: 1) { _, ack in ack() }
            let two = core.connect(uid: getuid(), auditSession: 1) { _, ack in ack() }
            @MainActor func send(_ request: HelperRequest, _ client: HelperCore.Client) throws -> HelperResponse {
                let box = ResponseBox()
                core.handle(MessageCodec.encode(request), from: client) { data in
                    box.set(try? MessageCodec.decode(HelperResponse.self, from: data, limit: HelperConstants.maximumBatchSize))
                }
                guard TestSupport.spin(3, until: { box.done }), let reply = box.value else { throw TestSupport.Failure("Core timeout") }
                return reply
            }
            guard case .failure(let missing) = try send(.prepareForMaintenance, one), missing.code == .handshakeRequired else {
                throw TestSupport.Failure("Missing handshake accepted")
            }
            _ = try send(.hello(HelloRequest(appVersion: HelperConstants.fullVersion)), one)
            _ = try send(.hello(HelloRequest(appVersion: HelperConstants.fullVersion)), two)
            try TestSupport.require(try send(.prepareForMaintenance, one) == .done, "Idle not accepted")
            _ = try send(.cancelMaintenance, two)
            guard case .failure(let busy) = try send(.prepareForMaintenance, two), busy.code == .busy else {
                throw TestSupport.Failure("Another peer released maintenance")
            }
            let request = ConnectionRequest(connectionID: UUID(), host: "vpn.invalid", port: 443, username: "example",
                authentication: .password, trustedCertificate: "", password: "fixture", mode: .none, cookie: nil)
            guard case .failure(let blocked) = try send(.start(request), two), blocked.code == .busy else {
                throw TestSupport.Failure("Start gate bypassed")
            }
            _ = try send(.cancelMaintenance, one)
            try TestSupport.require(try send(.prepareForMaintenance, two) == .done, "Owner cancel failed")
            core.disconnect(two)
            try TestSupport.require(try send(.prepareForMaintenance, one) == .done, "Crashed caller left lock")
            core.disconnect(one)
        }
        print("Release checks: \(failures) failure(s); full GUI suite is separate")
        return failures
    }
}
