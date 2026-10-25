import XCTest
import Darwin
import ProcessBridge
import VPNHelperShared
@testable import VPNHelperCore
@testable import VPNApp

final class DNSHost: WireGuardHost {
    var values: [String: [String: Any]] = ["primary": ["ServerAddresses": ["192.0.2.53"]]]
    var primary: String? = "primary"
    var failWrites = false
    var writes = 0
    /// What System Settings has saved for the service; nil = unknown.
    var configured: [String]?
    func configuredDNSServers(service: String) -> [String]? { configured }
    func run(_ tool: String, _ arguments: [String]) -> CommandResult { .init(status: 0, output: "") }
    func resolve(_ host: String, port: Int) -> [String] { [] }
    func uapi(interface: String, pid: pid_t, request: String) throws -> String { "errno=0\n\n" }
    func primaryService() -> String? { primary }
    func dnsSetup(service: String) -> [String: Any]? { values[service] }
    func setDNSSetup(service: String, value: [String: Any]?) -> Bool {
        writes += 1
        guard !failWrites else { return false }
        values[service] = value
        return true
    }
}

final class ReviewTests: XCTestCase {
    func temporary() throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("TunnelMac-regression-\(UUID())")
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: url) }
        return url
    }
    func testMachOFat64ExtremeOffsetsAndTruncations() throws {
        for offset in [UInt64.max, UInt64(Int.max), UInt64(Int.max) - 16, 40] {
            var bytes = Data([0xca, 0xfe, 0xba, 0xbf, 0, 0, 0, 1])
            func append32(_ n: UInt32) { var n = n.bigEndian; withUnsafeBytes(of: &n) { bytes.append(contentsOf: $0) } }
            func append64(_ n: UInt64) { var n = n.bigEndian; withUnsafeBytes(of: &n) { bytes.append(contentsOf: $0) } }
            append32(MachOImage.hostCPU); append32(0); append64(offset); append64(UInt64.max); append32(0); append32(0)
            XCTAssertThrowsError(try MachOImage(file: bytes))
        }
        for size in 0..<40 { XCTAssertThrowsError(try MachOImage(file: Data(repeating: 0, count: size))) }
    }
    func testShortMachOStringCommandRejected() throws {
        var bytes = Data()
        for word: UInt32 in [0xfeedfacf, MachOImage.hostCPU, 0, 2, 1, 8, 0, 0, 0xc, 8] {
            var value = word.littleEndian
            withUnsafeBytes(of: &value) { bytes.append(contentsOf: $0) }
        }
        XCTAssertThrowsError(try MachOImage(file: bytes))
    }
    /// Thin Mach-O of this host with dylib-style string commands, each sized exactly like ld does.
    func machO(fileType: UInt32, _ commands: [(MachOImage.Command, String)]) throws -> MachOImage {
        var body = Data()
        func append32(_ n: UInt32, _ data: inout Data) { var n = n.littleEndian; withUnsafeBytes(of: &n) { data.append(contentsOf: $0) } }
        for (command, value) in commands {
            let size = (24 + value.utf8.count + 1 + 7) / 8 * 8
            append32(command.rawValue, &body); append32(UInt32(size), &body); append32(24, &body)
            for _ in 0..<3 { append32(0, &body) }
            body.append(contentsOf: Array(value.utf8)); body.append(contentsOf: [UInt8](repeating: 0, count: size - 24 - value.utf8.count))
        }
        var bytes = Data()
        for word in [0xfeedfacf, MachOImage.hostCPU, 0, fileType, UInt32(commands.count), UInt32(body.count), 0, 0] { append32(word, &bytes) }
        return try MachOImage(file: bytes + body)
    }
    func managedLeaf(prefix: String) throws -> String? {
        let name = prefix + "/opt/lz4/lib/liblz4.1.dylib", target = prefix + "/Cellar/lz4/1.10.0/lib/liblz4.1.10.0.dylib"
        var executable = InspectedImage(role: .executable, resolvedPath: prefix + "/Cellar/openvpn/2.7.8_1/sbin/openvpn", original: Data(),
                                        image: try machO(fileType: MachOImage.executable, [(.loadDylib, name)]), sha256: "", ownerUID: 0, mutableLocation: false)
        executable.resolvedDependencies = [name: target]
        let library = InspectedImage(role: .library, resolvedPath: target, original: Data(),
                                     image: try machO(fileType: MachOImage.dylib, [(.idDylib, name)]), sha256: "", ownerUID: 0, mutableLocation: false)
        return RuntimeStore.managedLeaves([executable, library])[target]
    }
    func testManagedLibraryNameFitsIntelAndKeepsAppleSiliconLayout() throws {
        // /opt/homebrew leaves room for the Cellar file name; /usr/local only for the install name.
        XCTAssertEqual(try managedLeaf(prefix: "/opt/homebrew"), "liblz4.1.10.0.dylib")
        XCTAssertEqual(try managedLeaf(prefix: "/usr/local"), "liblz4.1.dylib")
    }
    func testDNSBaselineRestoresTheUserDNSAfterTheLastVPN() throws {
        let host = DNSHost(), path = try temporary().appendingPathComponent("baseline").path
        let baseline = DNSBaseline(host: host, recordPath: path)
        host.configured = ["192.0.2.53"]
        baseline.capture()
        host.values["primary"] = ["ServerAddresses": ["10.8.0.1"]]   // first VPN
        baseline.capture()                                         // second VPN: same snapshot
        host.values["primary"] = ["ServerAddresses": ["10.9.0.1"]]
        XCTAssertEqual(baseline.settle(), .restored(servers: ["192.0.2.53"]))
        XCTAssertEqual(WireGuardTunnel.servers(host.values["primary"]), ["192.0.2.53"])
        XCTAssertFalse(FileManager.default.fileExists(atPath: path))
        XCTAssertNil(baseline.settle())
    }
    func testDNSBaselineLeavesARestoredOrUserChangedDNSAlone() throws {
        let host = DNSHost(), path = try temporary().appendingPathComponent("baseline").path
        let baseline = DNSBaseline(host: host, recordPath: path)
        baseline.capture()
        XCTAssertEqual(baseline.settle(), .unchanged)
        XCTAssertEqual(host.writes, 0)
        baseline.capture()
        host.values["primary"] = ["ServerAddresses": ["9.9.9.9"]]
        host.configured = ["9.9.9.9"]                                // set in System Settings meanwhile
        XCTAssertEqual(baseline.settle(), .keptUserChange(servers: ["9.9.9.9"]))
        XCTAssertEqual(WireGuardTunnel.servers(host.values["primary"]), ["9.9.9.9"])
        XCTAssertEqual(host.writes, 0)
        host.configured = nil                                        // settings unreadable: leave it
        baseline.capture()
        host.values["primary"] = ["ServerAddresses": ["10.8.0.1"]]
        XCTAssertEqual(baseline.settle(), .unchanged)
        XCTAssertEqual(host.writes, 0)
    }
    func testDNSBaselineSurvivesAHelperRestartAndRemovesAVPNDNSOverDHCP() throws {
        let host = DNSHost(), path = try temporary().appendingPathComponent("baseline").path
        host.values["primary"] = nil                                 // automatic DNS (DHCP)
        DNSBaseline(host: host, recordPath: path).capture()
        host.values["primary"] = ["ServerAddresses": ["10.8.0.1"]]
        host.configured = []
        let restarted = DNSBaseline(host: host, recordPath: path)
        XCTAssertEqual(restarted.settle(), .restored(servers: []))
        XCTAssertNil(host.values["primary"])
        host.failWrites = true
        restarted.capture()
        host.values["primary"] = ["ServerAddresses": ["10.8.0.1"]]
        XCTAssertEqual(restarted.settle(), .failed)
        XCTAssertTrue(FileManager.default.fileExists(atPath: path))  // kept for the retry
    }
    func testDNSJournalWriteFailureDoesNotChangeDNS() throws {
        let host = DNSHost(), root = try temporary()
        let dns = InternetDNS(host: host, recordPath: root.appendingPathComponent("missing/journal").path)
        dns.otherOwner = { false }
        _ = dns.acquire(token: "a", servers: ["9.9.9.9"])
        XCTAssertEqual(host.writes, 0)
        XCTAssertEqual(WireGuardTunnel.servers(host.values["primary"]), ["192.0.2.53"])
        _ = dns.release(token: "a")
    }
    func testDNSFailedRestoreSurvivesRestart() throws {
        let root = try temporary(), host = DNSHost()
        let path = root.appendingPathComponent("journal").path
        let dns = InternetDNS(host: host, recordPath: path); dns.otherOwner = { false }
        _ = dns.acquire(token: "a", servers: ["9.9.9.9"])
        host.failWrites = true
        _ = dns.release(token: "a")
        XCTAssertTrue(dns.active)
        XCTAssertTrue(FileManager.default.fileExists(atPath: path))
        host.failWrites = false
        let recovered = InternetDNS(host: host, recordPath: path); recovered.otherOwner = { false }
        recovered.recover()
        XCTAssertFalse(recovered.active)
        XCTAssertEqual(WireGuardTunnel.servers(host.values["primary"]), ["192.0.2.53"])
    }
    func testDeferredDNSStartsMonitor() throws {
        let root = try temporary(), host = DNSHost()
        let lock = NSLock(); var owned = true
        let dns = InternetDNS(host: host, recordPath: root.appendingPathComponent("journal").path)
        dns.interval = 0.02; dns.otherOwner = { lock.withLock { owned } }
        _ = dns.acquire(token: "a", servers: ["9.9.9.9"])
        XCTAssertEqual(host.writes, 0)
        lock.withLock { owned = false }
        // Waits for the monitor's first tick (bounded): slow CI runners can miss a fixed sleep.
        let deadline = Date().addingTimeInterval(5)
        while !dns.active, Date() < deadline { Thread.sleep(forTimeInterval: 0.02) }
        XCTAssertTrue(dns.active, "Monitor did not apply the deferred DNS")
        _ = dns.release(token: "a") // Synchronizes with the timer before assertions.
        XCTAssertGreaterThanOrEqual(host.writes, 2)
    }
    func testPreparingDirectoriesPreservesLiveNameFile() throws {
        let root = try temporary()
        let store = RuntimeStore(root: root.path, ownership: .init(owners: [getuid()], anchor: root.path), probeIdentity: nil)
        try store.prepareDirectories()
        let name = URL(fileURLWithPath: store.work).appendingPathComponent("wg.live.name")
        try Data("utun42".utf8).write(to: name)
        try store.prepareDirectories()
        XCTAssertTrue(FileManager.default.fileExists(atPath: name.path))
    }
    func testEndpointContainmentIncludesSplitDefaultAndPartialNetworks() throws {
        XCTAssertTrue(try WireGuardCIDR.parse("128.0.0.0/1").contains("203.0.113.1"))
        XCTAssertTrue(try WireGuardCIDR.parse("203.0.113.0/24").contains("203.0.113.9"))
        XCTAssertFalse(try WireGuardCIDR.parse("203.0.113.0/24").contains("198.51.100.1"))
        XCTAssertTrue(try WireGuardCIDR.parse("2001:db8::/32").contains("2001:db8:1::1"))
    }
    func testProbeDescendantPipeDoesNotDefeatDeadline() throws {
        let start = Date()
        XCTAssertThrowsError(try Probe.run("/bin/sh", ["-c", "sleep 5 & exit 0"], environment: ["PATH=/usr/bin:/bin"], identity: nil, timeout: 100))
        XCTAssertLessThan(Date().timeIntervalSince(start), 2)
    }
    func testBoundedReadRejectsExcessAndJSONHasPrivateMode() throws {
        let root = try temporary(), file = root.appendingPathComponent("large")
        try Data(repeating: 1, count: 100).write(to: file)
        XCTAssertThrowsError(try BoundedFile.read(file, limit: 20))
        let store = try JSONStore(directory: root)
        try store.save(SavedData())
        let attrs = try FileManager.default.attributesOfItem(atPath: store.file.path)
        XCTAssertEqual((attrs[.posixPermissions] as? NSNumber)?.intValue, 0o600)
    }
    @MainActor func testNewDNSChoiceLeavesSystemUntouched() throws {
        let preferences = AppPreferences.disposable()
        XCTAssertEqual(preferences.internetDNSSelection, InternetDNSOption.offID)
        XCTAssertNil(preferences.internetDNSServers)
    }
    func testClientCertificateChangesCookieIdentity() {
        var connection = Connection(name: "A", server: "vpn.example.invalid", port: 443, authentication: .saml)
        let before = SAMLCookieIdentity(connection)
        connection.name = "Renamed"
        XCTAssertEqual(before, SAMLCookieIdentity(connection))
        connection.clientCertificate = .init(sha1: String(repeating: "a", count: 40), name: "Client")
        XCTAssertNotEqual(before, SAMLCookieIdentity(connection))
    }
    func testOpenVPNRequiresServerRoleAndPreservesCustomVerifier() throws {
        let text = "client\ndev tun\nremote vpn.example.invalid 1194\n<ca>\n-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n</ca>\n"
        XCTAssertThrowsError(try OpenVPNProfile.validated(text))
        XCTAssertNoThrow(try OpenVPNProfile.validated(text + "remote-cert-tls server\n"))
        XCTAssertThrowsError(try OpenVPNImporter.importText(text + "remote-cert-tls server\ntls-verify check.sh\n", baseDirectory: try temporary(), suggestedName: "Test", source: "fixture"))
    }
}

final class MemorySecrets {
    var staged: [UUID: String] = [:]
    var passwords: [UUID: String] = [:]
    var cookies: Set<UUID> = []
    var hooks: ConnectionTransaction.Secrets {
        .init(readStaged: { self.staged[$0] }, writeStaged: { self.staged[$1] = $0 },
              deleteStaged: { self.staged.removeValue(forKey: $0) },
              writePassword: { self.passwords[$1] = $0 }, deletePassword: { self.passwords.removeValue(forKey: $0) },
              deleteCookie: { self.cookies.remove($0) })
    }
}

extension ReviewTests {
    func testInterruptedSaveRecoversEveryPersistedPhase() throws {
        struct Crash: Error {}
        for phase in ["intent", "staged", "prepared", "profiles", "credentials", "cleanup", "json", "committed"] {
            let store = try JSONStore(directory: temporary())
            let secrets = MemorySecrets()
            let old = Connection(name: "Old", server: "old.example.invalid", username: "test")
            var next = old; next.name = "New"; next.server = "new.example.invalid"
            try store.save(.init(connections: [old]))
            secrets.passwords[old.id] = "old-secret"
            secrets.cookies.insert(old.id)
            let transaction = ConnectionTransaction(store: store, passwords: PasswordStore(), cookies: SAMLCookieStore(),
                secrets: secrets.hooks, checkpoint: { if $0 == phase { throw Crash() } })
            XCTAssertThrowsError(try transaction.save(connection: next, updated: .init(connections: [next]),
                password: "new-secret", openVPN: nil, wireGuard: nil), phase)
            try ConnectionTransaction(store: store, passwords: PasswordStore(), cookies: SAMLCookieStore(), secrets: secrets.hooks).recover()
            let committed = !["intent", "staged"].contains(phase)
            XCTAssertEqual(try store.load().connections, [committed ? next : old], phase)
            XCTAssertEqual(secrets.passwords[old.id], committed ? "new-secret" : "old-secret", phase)
            XCTAssertTrue(secrets.staged.isEmpty, phase)
            XCTAssertEqual(secrets.cookies.contains(old.id), !committed, phase)
            XCTAssertFalse(FileManager.default.fileExists(atPath: store.directory.appendingPathComponent("pending-operation.json").path))
        }
    }
    func testInterruptedDeletionIsRecoverable() throws {
        struct Crash: Error {}
        for phase in ["prepared", "credentials", "cleanup", "json", "committed"] {
            let store = try JSONStore(directory: temporary()), secrets = MemorySecrets()
            let old = Connection(name: "Old", server: "old.example.invalid", username: "test")
            try store.save(.init(connections: [old]))
            try ProfileStore.wireGuard(store).write("synthetic-private-material", id: old.id)
            secrets.passwords[old.id] = "old-secret"; secrets.cookies.insert(old.id)
            let transaction = ConnectionTransaction(store: store, passwords: PasswordStore(), cookies: SAMLCookieStore(),
                secrets: secrets.hooks, checkpoint: { if $0 == phase { throw Crash() } })
            XCTAssertThrowsError(try transaction.delete(old.id, updated: .init()), phase)
            try ConnectionTransaction(store: store, passwords: PasswordStore(), cookies: SAMLCookieStore(), secrets: secrets.hooks).recover()
            XCTAssertTrue(try store.load().connections.isEmpty)
            XCTAssertNil(secrets.passwords[old.id]); XCTAssertFalse(secrets.cookies.contains(old.id))
            XCTAssertFalse(FileManager.default.fileExists(atPath: ProfileStore.wireGuard(store).file(old.id).path))
        }
    }
}

final class CountingUpdates: UpdateTransport {
    var count = 0
    func fetch(_ request: URLRequest, limit: Int, completion: @escaping (Result<(Int, Data), Error>) -> Void) {
        count += 1
        completion(.success((200, Data(#"{"versions":{"stable":"2.0.0"}}"#.utf8))))
    }
}
extension ReviewTests {
    @MainActor func testHomebrewAutomaticQueriesRespectPreferenceAndManualRemainsAvailable() {
        let transport = CountingUpdates()
        let checker = ClientVersionChecker(transport: transport, automaticUpdates: { false })
        checker.refresh(status: nil)
        XCTAssertEqual(transport.count, 0)
        checker.refresh(status: nil, force: true)
        XCTAssertEqual(transport.count, RuntimeKind.allCases.count)
    }
    func testDependencyDriftWithoutExecutableChange() throws {
        let root = try temporary(), executable = root.appendingPathComponent("executable"), library = root.appendingPathComponent("library")
        try Data("exe".utf8).write(to: executable); try Data("lib".utf8).write(to: library)
        let sources = [InventoryItem(role: .executable, sourcePath: executable.path, sha256: Digest.sha256(Data("exe".utf8)), size: 3, ownerUID: getuid(), mutableLocation: true),
                       InventoryItem(role: .library, sourcePath: library.path, sha256: Digest.sha256(Data("lib".utf8)), size: 3, ownerUID: getuid(), mutableLocation: true)]
        let runtime = RuntimeSummary(id: "test", version: "1", approvedAt: Date(), capabilities: RuntimeCapabilities(help: ""), sourcePath: executable.path, sourceSHA256: sources[0].sha256, sources: sources)
        XCTAssertFalse(RuntimeSourceCheck.changed(runtime))
        try Data("new-library".utf8).write(to: library)
        XCTAssertTrue(RuntimeSourceCheck.changed(runtime))
    }
}

extension ReviewTests {
    func testInstalledRuntimeInventoriesRemainAccepted() throws {
        for kind in RuntimeKind.allCases {
            let path = BinaryLocator.defaultPath(for: kind)
            guard FileManager.default.isExecutableFile(atPath: path) else { continue }
            let inventory = try RuntimeInspector.inspect(candidate: path, requester: getuid(), kind: kind)
            XCTAssertFalse(inventory.report.items.isEmpty, kind.rawValue)
            XCTAssertEqual(inventory.report.kind, kind)
            XCTAssertEqual(inventory.digest.count, 64)
        }
    }
}

extension ReviewTests {
    func testOversizedSaveFailsBeforePreparingAnyMutation() throws {
        let store = try JSONStore(directory: temporary()), secrets = MemorySecrets()
        let connection = Connection(name: "Valid", server: "vpn.example.invalid", username: "test")
        try store.save(.init(connections: [connection]))
        var huge = connection
        huge.name = String(repeating: "x", count: JSONStore.maximumSize)
        let transaction = ConnectionTransaction(store: store, passwords: PasswordStore(), cookies: SAMLCookieStore(), secrets: secrets.hooks)
        XCTAssertThrowsError(try transaction.save(connection: connection, updated: .init(connections: [huge]), password: "new-secret", openVPN: nil, wireGuard: nil))
        XCTAssertEqual(try store.load().connections, [connection])
        XCTAssertTrue(secrets.staged.isEmpty)
        XCTAssertFalse(FileManager.default.fileExists(atPath: store.directory.appendingPathComponent("pending-operation.json").path))
    }
}

extension ReviewTests {
    func testOnboardingHomebrewCommandsCoverOnlyChosenClients() {
        let states: [RuntimeKind: ClientState] = [
            .openfortivpn: .notInstalled,
            .openvpn: .notApproved(installed: "2.7.8", latest: "2.7.10"),
            .wireguard: .notApproved(installed: "0.0.20250522", latest: nil),
        ]
        let all = ServiceOnboarding.commands(RuntimeKind.allCases) { states[$0]! }
        XCTAssertEqual(all, ["brew install openfortivpn", "brew upgrade openvpn"])
        XCTAssertEqual(ServiceOnboarding.commands([.wireguard]) { states[$0]! }, [])
        XCTAssertEqual(ServiceOnboarding.commands([.wireguard, .openfortivpn]) { _ in .notInstalled }, ["brew install openfortivpn wireguard-go"])
        XCTAssertFalse(ServiceOnboarding.installed(states[.openvpn]!))
        XCTAssertTrue(ServiceOnboarding.installed(states[.wireguard]!))
        XCTAssertEqual(ServiceOnboarding.step(.ready), .approve)
    }
}

extension ReviewTests {
    func testAdminPromptNamesTheClientAndOldDescriptionsAreRewritten() {
        let prompts = RuntimeKind.allCases.map { SystemAdminAuthorizer.approvalPrompt($0, path: "/opt/homebrew/bin/\($0.executableName)") }
        XCTAssertEqual(Set(prompts).count, RuntimeKind.allCases.count)
        XCTAssertTrue(prompts.allSatisfy { $0.hasPrefix("TunnelMac ") && !$0.contains("VPN GUI") })
        XCTAssertTrue(prompts[1].contains("OpenVPN") && prompts[1].contains("/opt/homebrew/bin/openvpn"))
        let old: [String: Any] = ["class": "rule", "rule": ["authenticate-admin"],
                                  "default-prompt": ["": "VPN GUI quer aprovar ou remover a cópia protegida do openfortivpn."]]
        XCTAssertTrue(SystemAdminAuthorizer.definitionIsExpected(old))
        XCTAssertFalse(SystemAdminAuthorizer.descriptionIsCurrent(old))
        var current = old
        current["default-prompt"] = ["": SystemAdminAuthorizer.description]
        XCTAssertTrue(SystemAdminAuthorizer.descriptionIsCurrent(current))
    }
}

extension ReviewTests {
    func testDowngradedInstallationKeepsTheCurrentApprovedCopy() {
        let state = ClientState.evaluate(approved: "1.24.1", installed: "1.24.0", installedExists: true, sourceChanged: true, latest: "1.24.1")
        XCTAssertEqual(state, .upToDate("1.24.1"))
        XCTAssertEqual(ClientState.evaluate(approved: "1.24.0", installed: "1.23.1", installedExists: true, sourceChanged: true, latest: "1.24.1"),
                       .updateAvailable(current: "1.24.0", latest: "1.24.1"))
        XCTAssertEqual(ClientState.evaluate(approved: "1.24.1", installed: "1.24.1", installedExists: true, sourceChanged: true, latest: "1.24.1"),
                       .approvalOutdated(approved: "1.24.1", installed: "1.24.1"))
    }
}
