import XCTest
import Darwin
import VPNHelperShared
@testable import VPNHelperCore
@testable import VPNApp

/// Records the system commands of Check Point sessions and answers `route -n get` and
/// `ifconfig` from its own tables. Nothing reaches the real routing table or interfaces.
final class CheckPointHost: WireGuardHost, @unchecked Sendable {
    private let lock = NSLock()
    private var _commands: [[String]] = []
    /// Address → router of a host route outside the tunnel.
    var hostRoutes: [String: String] = [:]
    var interfaces: Set<String> = []
    var commands: [[String]] { lock.withLock { _commands } }
    func run(_ tool: String, _ arguments: [String]) -> CommandResult {
        lock.withLock {
            _commands.append([tool] + arguments)
            if tool == WireGuardTools.ifconfig { return .init(status: interfaces.contains(arguments.first ?? "") ? 0 : 1, output: "") }
            if tool == WireGuardTools.route, arguments.starts(with: ["-n", "get", "-inet"]), let address = arguments.last {
                guard let router = hostRoutes[address] else { return .init(status: 0, output: "   route to: \(address)\ndestination: default\n    gateway: 192.0.2.1\n  interface: en0\n      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING>\n") }
                return .init(status: 0, output: "   route to: \(address)\ndestination: \(address)\n    gateway: \(router)\n  interface: en0\n      flags: <UP,GATEWAY,HOST,DONE,STATIC>\n")
            }
            if tool == WireGuardTools.route, arguments.contains("delete"), let index = arguments.firstIndex(of: "-host") {
                hostRoutes.removeValue(forKey: arguments[index + 1])
            }
            return .init(status: 0, output: "")
        }
    }
    func resolve(_ host: String, port: Int) -> [String] { [] }
    func uapi(interface: String, pid: pid_t, request: String) throws -> String { "" }
    func primaryService() -> String? { nil }
    func dnsSetup(service: String) -> [String: Any]? { nil }
    func setDNSSetup(service: String, value: [String: Any]?) -> Bool { true }
}

/// TunnelMac's own resolvers, in memory: the helper's start-up recovery never sees the real store.
final class MemorySupplementalDNS: SupplementalDNS, @unchecked Sendable {
    func set(token: String, value: [String: Any]) -> Bool { true }
    func remove(token: String) {}
    func tokens() -> [String] { [] }
    func flush() {}
}

/// Refuses every administrator prompt (none is expected in these tests).
final class RefusingAuthorizer: AdminAuthorizing {
    func authorize(_ externalForm: Data, prompt: String) -> Bool { false }
}

final class LineBox: @unchecked Sendable {
    private let lock = NSLock()
    private var values: [String] = []
    func append(_ line: String) { lock.withLock { values.append(line) } }
    var lines: [String] { lock.withLock { values } }
}

/// snx-rs DNS keys of the dynamic store, in memory.
final class FakeCheckPointDNS: CheckPointDNSStore, @unchecked Sendable {
    private let lock = NSLock()
    private var keys: Set<String> = []
    private(set) var removed: [String] = []
    func publish(_ interface: String) { lock.withLock { _ = keys.insert(interface) } }
    func interfaces() -> [String] { lock.withLock { keys.sorted() } }
    func remove(interface: String) { lock.withLock { if keys.remove(interface) != nil { removed.append(interface) } } }
}

final class CheckPointTests: XCTestCase {
    /// `snx-rs -m info` as printed by 6.6.1 (labels as in en-US; documentation address and
    /// made-up fingerprint words instead of the real gateway's).
    static let info = """
             Server address: 203.0.113.58
                  Server IP: 203.0.113.58
             Client enabled: true
        Supported protocols: IPSec, SSL, L2TP, IKEv1_Only
         Preferred protocol: IPSec
                  TCPT port: 443
                  NATT port: 4500
    Internal CA fingerprint: BOAT HIT GAS MOLD ICY FEN AWE TOOL BIT RAN SOD WAND
                 [Standard]: vpn (user_defined)
    """

    /// Excerpt of `snx-rs --help` (6.6.1).
    static let help = """
    VPN client for Check Point security gateway

    Usage: snx-rs [OPTIONS]

    Options:
      -s, --server-name <SERVER_NAME>
      -o, --login-type <LOGIN_TYPE>
      -m, --mode <MODE>
      -u, --user-name <USER_NAME>
      -p, --password <PASSWORD>
      -c, --config-file <CONFIG_FILE>
      -X, --ignore-server-cert <IGNORE_SERVER_CERT>
      -k, --ca-cert <CA_CERT>
    """

    // MARK: Config

    func testConfigHasOnlyFixedKeysAndThePasswordInBase64() throws {
        let config = try CheckPointConfigRenderer.render(host: "vpn.example.invalid", port: 443, username: "user", password: "pa ss=word",
                                                         loginType: "vpn", authorityPath: "/private/var/db/x/checkpoint/a.pem", allTraffic: false)
        let lines = config.split(separator: "\n").map(String.init)
        XCTAssertEqual(lines, ["server-name=vpn.example.invalid", "user-name=user", "password=" + Data("pa ss=word".utf8).base64EncodedString(),
                               "login-type=vpn", "tunnel-type=ipsec", "ca-cert=/private/var/db/x/checkpoint/a.pem", "default-route=false",
                               "keychain=false", "ike-persist=false", "no-keepalive=false", "log-level=info"])
        XCTAssertFalse(config.contains("pa ss=word"))
        for line in lines { XCTAssertTrue(CheckPointConfigRenderer.keys.contains(String(line.prefix { $0 != "=" })), line) }
        let other = try CheckPointConfigRenderer.render(host: "203.0.113.58", port: 4443, username: "u", password: "p", loginType: "vpn_Username_Password",
                                                        authorityPath: nil, allTraffic: true)
        XCTAssertTrue(other.contains("server-name=203.0.113.58:4443\n"))
        XCTAssertTrue(other.contains("default-route=true\n"))
        XCTAssertFalse(other.contains("ca-cert"))
        XCTAssertFalse(other.contains("ignore-server-cert"))
        XCTAssertFalse(config.contains("ignore-server-cert"))
    }

    func testConfigRefusesValuesThatWouldChangeItsLines() {
        func render(user: String = "u", password: String = "p", type: String = "vpn", path: String? = nil, host: String = "vpn.example.invalid") throws {
            _ = try CheckPointConfigRenderer.render(host: host, port: 443, username: user, password: password, loginType: type,
                                                    authorityPath: path, allTraffic: false)
        }
        for user in ["a\nignore-server-cert=true", "a\rb", "a\0b", " a", "a ", "\"a\"", "'a", "", "a\tb"] {
            XCTAssertThrowsError(try render(user: user), user.debugDescription)
        }
        for password in ["", "a\nb", "a\u{0}", String(repeating: "x", count: 4097)] {
            XCTAssertThrowsError(try render(password: password), password.prefix(8).debugDescription)
        }
        for type in ["", "vpn x", "vpn\n", String(repeating: "a", count: 65), "a=b"] {
            XCTAssertThrowsError(try render(type: type), type.debugDescription)
        }
        for path in ["relative.pem", "/a,b.pem", "/a b.pem", "/a\nb"] { XCTAssertThrowsError(try render(path: path), path) }
        for host in ["-X", "https://vpn.example.invalid", "a/b", ""] { XCTAssertThrowsError(try render(host: host), host) }
        XCTAssertThrowsError(try CheckPointRules.server(host: "2001:db8::1", port: 4443))
        XCTAssertEqual(try CheckPointRules.server(host: "[2001:db8::1]", port: 4443), "[2001:db8::1]:4443")
    }

    func testRequestValidation() throws {
        let request = CheckPointRequest(connectionID: UUID(), host: " vpn.example.invalid ", port: 443, username: "user", password: "secret",
                                        loginType: "vpn", authorityDER: nil, allTraffic: false)
        XCTAssertEqual(try request.validated().host, "vpn.example.invalid")
        var bad = request; bad.loginType = "vpn;x"
        XCTAssertThrowsError(try bad.validated())
        bad = request; bad.password = ""
        XCTAssertThrowsError(try bad.validated())
        bad = request; bad.password = String(repeating: "x", count: CheckPointRules.maximumPassword + 1)
        XCTAssertThrowsError(try bad.validated())
        bad = request; bad.authorityDER = Data("not a certificate".utf8)
        XCTAssertThrowsError(try bad.validated())
        bad = request; bad.authorityDER = Data(count: CheckPointRules.maximumAuthorityDER + 1)
        XCTAssertThrowsError(try bad.validated())
        bad = request; bad.host = "vpn.example.invalid/x"
        XCTAssertThrowsError(try bad.validated())
        bad = request; bad.port = 0
        XCTAssertThrowsError(try bad.validated())
        let query = CheckPointGatewayQuery(host: "203.0.113.58", port: 443, authorityDER: Data([1, 2, 3]))
        XCTAssertThrowsError(try query.validated())
    }

    // MARK: Gateway info

    func testLoginOptionsAndFingerprintFromInfo() {
        let options = CheckPointRules.loginOptions(fromInfo: Self.info)
        XCTAssertEqual(options, [CheckPointLoginOption(displayName: "Standard", id: "vpn", factors: ["user_defined"])])
        XCTAssertEqual(CheckPointRules.fingerprintWords(fromInfo: Self.info), "BOAT HIT GAS MOLD ICY FEN AWE TOOL BIT RAN SOD WAND")
        XCTAssertEqual(CheckPointRules.supportedProtocols(fromInfo: Self.info), "IPSec, SSL, L2TP, IKEv1_Only")
        // The labels follow the macOS language of the process; the values do not.
        let german = Self.info.replacingOccurrences(of: "Internal CA fingerprint", with: "Fingerabdruck der internen CA")
            .replacingOccurrences(of: "Supported protocols", with: "Unterstützte Protokolle")
        XCTAssertEqual(CheckPointRules.loginOptions(fromInfo: german), options)
        XCTAssertEqual(CheckPointRules.fingerprintWords(fromInfo: german), "BOAT HIT GAS MOLD ICY FEN AWE TOOL BIT RAN SOD WAND")
        let more = Self.info + "\n          [Token]: vpn_RSA (password, password)\n  [SSO]: vpn_Azure (identity_provider)\n [Cert]: vpn_Cert (certificate)\n [Pass]: vpn_Username_Password (password)\n"
        let parsed = CheckPointRules.loginOptions(fromInfo: more)
        XCTAssertEqual(parsed.map(\.id), ["vpn", "vpn_RSA", "vpn_Azure", "vpn_Cert", "vpn_Username_Password"])
        XCTAssertEqual(parsed.map(CheckPointRules.isSupported), [true, false, false, false, true])
        XCTAssertEqual(parsed.map(CheckPointGateway.unsupportedReason), [nil, "exige MFA", "exige navegador", "exige certificado", nil])
        for garbage in ["[x]: vpn; rm (password)", "[]: vpn (password)", "[a]: vpn (Password)", "Error: [a]: vpn (password) x", "random text"] {
            XCTAssertTrue(CheckPointRules.loginOptions(fromInfo: garbage).isEmpty, garbage)
        }
        XCTAssertNil(CheckPointRules.fingerprintWords(fromInfo: "Internal CA fingerprint: FIRE DUN DRUB"))
        XCTAssertNil(CheckPointRules.fingerprintWords(fromInfo: "x: fire dun drub did mill hugh lac bear at hilt isle dell"))
    }

    func testQueryAnswerAndArguments() {
        let arguments = CheckPointNetwork.infoArguments(server: "203.0.113.58", authorityPath: "/q/a.pem")
        XCTAssertEqual(arguments, ["-m", "info", "-s", "203.0.113.58", "-k", "/q/a.pem"])
        XCTAssertFalse(arguments.contains("-X") || arguments.contains { $0.contains("ignore-server-cert") })
        XCTAssertEqual(CheckPointNetwork.infoArguments(server: "vpn.example.invalid", authorityPath: nil), ["-m", "info", "-s", "vpn.example.invalid"])
        let ok = CheckPointNetwork.gatewayInfo(Self.info, status: 0)
        XCTAssertNil(ok.failure)
        XCTAssertEqual(ok.loginOptions.first?.id, "vpn")
        let tls = CheckPointNetwork.gatewayInfo("Error: TLS certificate validation failed. The server’s certificate is invalid, expired, or not trusted.\n", status: 1)
        XCTAssertEqual(tls.failure, "O gateway não apresentou um certificado válido para este endereço com a autoridade confiada.")
        let openssl = CheckPointNetwork.gatewayInfo("Error: error:0A000086:SSL routines::certificate verify failed (hostname mismatch)\n", status: 1)
        XCTAssertEqual(openssl.failure, tls.failure)
        let other = CheckPointNetwork.gatewayInfo("Error: could not resolve to any address\n", status: 1)
        XCTAssertEqual(other.failure, "Não foi possível consultar o gateway Check Point: could not resolve to any address")
    }

    func testRuntimeRecognition() {
        XCTAssertTrue(RuntimeCapabilities.looksLikeSnxRs(help: Self.help, version: "snx-rs 6.6.1\n"))
        XCTAssertFalse(RuntimeCapabilities.looksLikeSnxRs(help: Self.help, version: "snxctl 6.6.1"))
        XCTAssertFalse(RuntimeCapabilities.looksLikeSnxRs(help: Self.help.replacingOccurrences(of: "--ca-cert", with: "--ca"), version: "snx-rs 6.6.1"))
        XCTAssertFalse(RuntimeCapabilities.looksLikeSnxRs(help: "OpenConnect version v9.21 --config", version: "snx-rs 6.6.1"))
        XCTAssertFalse(RuntimeCapabilities.looksLikeSnxRs(help: "", version: ""))
        XCTAssertEqual(RuntimeKind.snxrs.executableName, "snx-rs")
        XCTAssertEqual(VPNProtocol.checkPoint.runtime, .snxrs)
        XCTAssertEqual(BinaryLocator.defaultPath(for: .snxrs).hasSuffix("/bin/snx-rs"), true)
        XCTAssertEqual(ServicePanel.clientTitle(.snxrs), "Check Point (snx-rs)")
        XCTAssertEqual(ServicePanel.presentation(.snxrs, .notInstalled).command, "brew install snx-rs")
    }

    // MARK: Output of snx-rs

    func testEverySnxRsLanguageIsRecognized() {
        XCTAssertEqual(CheckPointOutput.connected.count, 17)
        XCTAssertEqual(CheckPointOutput.needsTTY.count, 17)
        XCTAssertEqual(CheckPointOutput.authenticationFailed.count, 17)
        XCTAssertEqual(CheckPointOutput.unsupportedLoginType.count, 17)
        for line in CheckPointOutput.connected { XCTAssertEqual(CheckPointOutput.classify(line), .connected, line) }
        for line in CheckPointOutput.needsTTY { XCTAssertEqual(CheckPointOutput.classify("Error: " + line), .needsTTY, line) }
        for line in CheckPointOutput.authenticationFailed { XCTAssertEqual(CheckPointOutput.classify("Error: " + line), .authenticationFailed, line) }
        for line in CheckPointOutput.unsupportedLoginType { XCTAssertEqual(CheckPointOutput.classify("Error: " + line), .unsupportedLoginType, line) }
        for line in CheckPointOutput.certificateFailed { XCTAssertEqual(CheckPointOutput.classify("Error: " + line), .certificateFailed, line) }
        XCTAssertNil(CheckPointOutput.classify("INFO IPsec authentication succeeded"))
        XCTAssertEqual(CheckPointOutput.interface("            Interface: utun8"), "utun8")
        XCTAssertEqual(CheckPointOutput.interface("        Schnittstelle: utun12"), "utun12")
        XCTAssertNil(CheckPointOutput.interface("Interface: en0"))
        XCTAssertNil(CheckPointOutput.interface("[Standard]: utun8"))
    }

    // MARK: Session observer

    private func session(dns: FakeCheckPointDNS, host: CheckPointHost, record: CheckPointNetwork.Record = .init(gateway: "203.0.113.58", hadHostRoute: false, interface: nil),
                         work: String) -> (CheckPointSession, () -> [String], () -> Int) {
        let token = UUID().uuidString
        let lines = LineBox(), failures = LineBox()
        let observer = CheckPointSession(token: token, record: record, recordPath: CheckPointNetwork.recordPath(work: work, token: token),
                                         dns: dns, host: host) {}
        observer.interval = 0.05
        observer.timeout = 3
        observer.emit = { lines.append($0) }
        observer.fail = { failures.append("fail") }
        return (observer, { lines.lines }, { failures.lines.count })
    }

    private func wait(_ condition: () -> Bool) {
        let deadline = Date().addingTimeInterval(3)
        while !condition() && Date() < deadline { RunLoop.current.run(until: Date().addingTimeInterval(0.02)) }
    }

    func testReadyWhenTheDNSKeyAppearsAndCleanupAfterAKill() throws {
        let work = try temporaryDirectory()
        let dns = FakeCheckPointDNS(), host = CheckPointHost()
        let (observer, lines, failures) = session(dns: dns, host: host, work: work)
        observer.clientStarted(pid: 1234)
        observer.clientOutput("INFO Connecting to 203.0.113.58")
        XCTAssertTrue(lines().isEmpty)
        host.interfaces = ["utun8"]
        dns.publish("utun8")
        // snx-rs added its host route to the gateway; then it was killed (SIGKILL).
        host.hostRoutes["203.0.113.58"] = "192.0.2.1"
        wait { lines().contains(CheckPointRules.networkReady + "utun8") }
        XCTAssertEqual(lines(), [CheckPointRules.networkReady + "utun8"])
        XCTAssertEqual(observer.readySource, .dns)
        // Later lines never mark it again.
        observer.clientOutput("            Interface: utun8")
        observer.clientOutput(CheckPointOutput.connected[3])
        XCTAssertEqual(lines().count, 1)
        XCTAssertEqual(failures(), 0)
        observer.clientEnded()
        XCTAssertEqual(dns.removed, ["utun8"])
        XCTAssertTrue(host.commands.contains([WireGuardTools.route, "-q", "-n", "delete", "-inet", "-host", "203.0.113.58", "192.0.2.1"]), "\(host.commands)")
        XCTAssertTrue(host.commands.contains([WireGuardTools.dscacheutil, "-flushcache"]))
        XCTAssertTrue((try FileManager.default.contentsOfDirectory(atPath: work)).isEmpty)
    }

    func testARouteThatExistedBeforeTheSessionStays() throws {
        let work = try temporaryDirectory()
        let dns = FakeCheckPointDNS(), host = CheckPointHost()
        host.hostRoutes["203.0.113.58"] = "192.0.2.1"
        let (observer, _, _) = session(dns: dns, host: host, record: .init(gateway: "203.0.113.58", hadHostRoute: true, interface: nil), work: work)
        observer.clientEnded()
        XCTAssertFalse(host.commands.contains { $0.contains("delete") })
        XCTAssertEqual(host.hostRoutes["203.0.113.58"], "192.0.2.1")
    }

    /// A gateway without DNS: the connection block or cli-tunnel-connected, in any language.
    func testReadyFromTheOutputWithoutDNS() throws {
        let work = try temporaryDirectory()
        for connected in CheckPointOutput.connected {
            let dns = FakeCheckPointDNS(), host = CheckPointHost()
            host.interfaces = ["utun9"]
            let (observer, lines, _) = session(dns: dns, host: host, work: work)
            observer.clientOutput(connected) // Interface still unknown: nothing yet.
            XCTAssertTrue(lines().isEmpty)
            observer.clientOutput("        Rozhraní: utun9")
            XCTAssertEqual(lines().last, CheckPointRules.networkReady + "utun9", connected)
            XCTAssertEqual(observer.readySource, .output)
            observer.clientEnded()
        }
        // The interface line alone (labels translated, value stable).
        let dns = FakeCheckPointDNS(), host = CheckPointHost()
        host.interfaces = ["utun3"]
        let (observer, lines, _) = session(dns: dns, host: host, work: work)
        observer.clientOutput("            Interface: utun3")
        XCTAssertEqual(lines().last, CheckPointRules.networkReady + "utun3")
        observer.clientEnded()
    }

    func testAMissingInterfaceStopsTheSession() throws {
        let work = try temporaryDirectory()
        let dns = FakeCheckPointDNS(), host = CheckPointHost()
        let (observer, lines, failures) = session(dns: dns, host: host, work: work)
        observer.clientOutput("            Interface: utun7")
        XCTAssertEqual(lines(), [CheckPointRules.networkFailure + " utun7"])
        XCTAssertEqual(failures(), 1)
        XCTAssertNil(observer.readySource)
        observer.clientEnded()
    }

    func testRecoverCleansOnlyDeadSessions() throws {
        let work = try temporaryDirectory()
        let dead = UUID().uuidString, live = UUID().uuidString
        CheckPointNetwork.write(.init(gateway: "203.0.113.58", hadHostRoute: false, interface: "utun8"), to: CheckPointNetwork.recordPath(work: work, token: dead))
        let dns = FakeCheckPointDNS(), host = CheckPointHost()
        dns.publish("utun8")
        host.hostRoutes["203.0.113.58"] = "192.0.2.1"
        var authorities: [String] = []
        CheckPointNetwork.recover(work: work, live: [], dns: dns, host: host) { authorities.append($0) }
        XCTAssertEqual(dns.removed, ["utun8"])
        XCTAssertNil(host.hostRoutes["203.0.113.58"])
        XCTAssertEqual(authorities, [dead])
        XCTAssertFalse(FileManager.default.fileExists(atPath: CheckPointNetwork.recordPath(work: work, token: dead)))
        // While a Check Point session runs, its DNS key and route are its own.
        CheckPointNetwork.write(.init(gateway: "203.0.113.58", hadHostRoute: false, interface: "utun8"), to: CheckPointNetwork.recordPath(work: work, token: dead))
        CheckPointNetwork.write(.init(gateway: "203.0.113.58", hadHostRoute: false, interface: "utun9"), to: CheckPointNetwork.recordPath(work: work, token: live))
        dns.publish("utun9")
        host.hostRoutes["203.0.113.58"] = "192.0.2.1"
        CheckPointNetwork.recover(work: work, live: [live], dns: dns, host: host) { _ in }
        XCTAssertEqual(dns.interfaces(), ["utun9"])
        XCTAssertEqual(host.hostRoutes["203.0.113.58"], "192.0.2.1")
        XCTAssertFalse(FileManager.default.fileExists(atPath: CheckPointNetwork.recordPath(work: work, token: dead)))
        XCTAssertTrue(FileManager.default.fileExists(atPath: CheckPointNetwork.recordPath(work: work, token: live)))
    }

    private func temporaryDirectory() throws -> String {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("cp-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: url) }
        return url.path
    }
}

// MARK: App

extension CheckPointTests {
    @MainActor func testSessionStatesFromSnxRsAndTheHelper() {
        func session() -> Session { let s = Session(id: UUID()); s.begin(client: "snx-rs"); s.cleanExitIsDrop = true; return s }
        let ready = session()
        ready.acceptCheckPoint("            Interface: utun8")
        ready.acceptCheckPoint(CheckPointOutput.connected[6])
        XCTAssertNotEqual(ready.state, .connected) // snx-rs text alone is not the helper's confirmation.
        ready.acceptCheckPoint(CheckPointRules.networkReady + "utun8")
        XCTAssertEqual(ready.state, .connected)
        XCTAssertEqual(ready.logs.last, "[+] TunnelMac: túnel Check Point pronto em utun8.")
        // A clean exit without a disconnect request after the tunnel was up: a drop, retried.
        ready.finish(exit: 0)
        XCTAssertEqual(ready.state, .failed)
        XCTAssertNotNil(ready.retryDelay)
        let asked = session()
        asked.acceptCheckPoint(CheckPointRules.networkReady + "utun8")
        asked.wantsDisconnect = true
        asked.finish(exit: 0)
        XCTAssertEqual(asked.state, .disconnected)

        let password = session()
        password.acceptCheckPoint("Error: " + CheckPointOutput.authenticationFailed[11])
        XCTAssertTrue(password.authenticationRejected && password.retryBlocked)
        let tls = session()
        tls.acceptCheckPoint("Error: " + CheckPointOutput.certificateFailed[3])
        XCTAssertTrue(tls.certificateValidationFailed && tls.retryBlocked && !tls.authenticationRejected)
        let mfa = session()
        mfa.acceptCheckPoint("Error: " + CheckPointOutput.needsTTY[0])
        XCTAssertTrue(mfa.retryBlocked && !mfa.authenticationRejected)
        XCTAssertTrue(mfa.logs.last?.contains("segundo fator (MFA)") == true)
        let type = session()
        type.acceptCheckPoint("Error: " + CheckPointOutput.unsupportedLoginType[3])
        XCTAssertTrue(type.retryBlocked)
        let broken = session()
        broken.acceptCheckPoint(CheckPointRules.networkFailure + " utun7")
        XCTAssertTrue(broken.setupFailed && broken.retryBlocked)
        XCTAssertNotEqual(broken.state, .connected)
    }

    func testConnectionCodableAndValidation() throws {
        var connection = Connection(name: " Matriz ", server: "203.0.113.58", username: "user", kind: .checkPoint)
        XCTAssertTrue(connection.usesPassword)
        XCTAssertFalse(connection.usesProfile)
        XCTAssertEqual(connection.endpoint, "203.0.113.58")
        XCTAssertThrowsError(try connection.validated()) // No login type yet.
        connection.checkPoint = CheckPointSettings(loginType: "vpn")
        connection.trustedCertificate = String(repeating: "a", count: 64)
        connection.internalNetworks = ["10.0.0.0/8"]
        connection.allTraffic = true
        let valid = try connection.validated()
        XCTAssertEqual(valid.name, "Matriz")
        XCTAssertEqual(valid.trustedCertificate, "")
        XCTAssertNil(valid.internalNetworks)
        XCTAssertTrue(valid.allTraffic)
        var realm = connection; realm.realm = "x"
        XCTAssertThrowsError(try realm.validated())
        var noUser = connection; noUser.username = ""
        XCTAssertThrowsError(try noUser.validated())
        var badType = connection; badType.checkPoint?.loginType = "a b"
        XCTAssertThrowsError(try badType.validated())
        var badAuthority = connection
        badAuthority.checkPoint?.authority = CheckPointAuthority(der: Data([1, 2]), sha256: CheckPointAuthority.digest(Data([1, 2])), subject: "x", notAfter: nil)
        XCTAssertThrowsError(try badAuthority.validated())

        let data = try JSONEncoder().encode(valid)
        let decoded = try JSONDecoder().decode(Connection.self, from: data)
        XCTAssertEqual(decoded, valid)
        XCTAssertEqual(decoded.checkPoint?.loginType, "vpn")
        // Connections saved before Check Point support have no such key.
        var object = try JSONSerialization.jsonObject(with: JSONEncoder().encode(Connection(name: "F", server: "vpn.example.invalid", username: "u"))) as! [String: Any]
        object.removeValue(forKey: "checkPoint")
        let old = try JSONDecoder().decode(Connection.self, from: JSONSerialization.data(withJSONObject: object))
        XCTAssertNil(old.checkPoint)
        XCTAssertEqual(old.kind, .fortinet)
        // Other kinds never keep Check Point settings.
        var fortinet = Connection(name: "F", server: "vpn.example.invalid", username: "u")
        fortinet.checkPoint = CheckPointSettings(loginType: "vpn")
        XCTAssertNil(try fortinet.validated().checkPoint)
    }

    /// The helper filters the password and its base64 (the config line) out of every line.
    func testPasswordAndItsBase64NeverReachTheLog() {
        let password = "S3cret!pass"
        let encoded = Data(password.utf8).base64EncodedString()
        var filter = OutputLineFilter(captureCookie: false, secrets: [password, encoded])
        let events = filter.feed(Data("INFO connecting\ndebug password=\(encoded)\nError: bad \(password) here\nInterface: utun8\n".utf8)) + filter.finish()
        let lines = events.compactMap { event -> String? in if case .line(let line) = event { return line }; return nil }
        XCTAssertEqual(lines, ["INFO connecting", "Interface: utun8"])
        XCTAssertFalse(OutputRules.safe("user-name=u password=\(encoded)", secret: password).contains(encoded))
    }
}

// MARK: Helper

extension CheckPointTests {
    /// A real HelperCore in a temporary state directory with an snx-rs stand-in (a script that
    /// prints what snx-rs prints and never touches the network), fake DNS and host.
    final class Fixture {
        let root: String
        let core: HelperCore
        let dns = FakeCheckPointDNS()
        let host = CheckPointHost()
        let client: HelperCore.Client
        private let output = LineBox()
        var lines: [String] { output.lines }

        init() throws {
            let path = FileManager.default.temporaryDirectory.appendingPathComponent("cp-helper-\(UUID().uuidString)").path
            guard mkdir(path, 0o755) == 0, let real = realpath(path, nil) else { throw CocoaError(.fileWriteUnknown) }
            root = String(cString: real); free(real)
            let supervisor = URL(fileURLWithPath: FileManager.default.currentDirectoryPath).appendingPathComponent(".build/debug/VPNSupervisor").path
            core = HelperCore(HelperCore.Configuration(stateDirectory: root + "/state", ownership: TrustedOwnership(owners: [getuid()], anchor: root),
                                                       supervisorSource: supervisor, supervisorRequirement: nil, helperVersion: "test",
                                                       probeIdentity: nil, authorizer: RefusingAuthorizer(), idleTimeout: 3600,
                                                       wireGuardHost: host, supplementalDNS: MemorySupplementalDNS(), checkPointDNS: dns))
            client = core.connect(uid: getuid(), auditSession: 0) { [output] batch, acknowledged in
                for event in batch.events { if case .line(let line) = event.kind { output.append(line) } }
                acknowledged()
            }
            _ = send(.hello(HelloRequest(appVersion: "test")))
        }

        func send(_ request: HelperRequest) -> HelperResponse? {
            let done = DispatchSemaphore(value: 0)
            var response: HelperResponse?
            core.handle(MessageCodec.encode(request), from: client) { data in
                response = try? MessageCodec.decode(HelperResponse.self, from: data, limit: HelperConstants.maximumBatchSize)
                done.signal()
            }
            _ = done.wait(timeout: .now() + 30)
            return response
        }

        static let script = """
        #!/bin/sh
        if [ "$1" = "-m" ] && [ "$2" = "info" ]; then
          echo "ARGS:$*"
          /bin/cat <<'EOF'
        \(CheckPointTests.info)
        EOF
          exit 0
        fi
        echo "ARGS:$*"
        /bin/cat /dev/fd/3 | /usr/bin/sed -n 's/^login-type=/LOGIN:/p'
        echo "            Interface: utun99"
        trap 'echo "Tunnel disconnected"; exit 0' TERM
        while :; do /bin/sleep 1 & wait $!; done
        """

        /// Writes an approved snx-rs copy in the store's format.
        func installStandIn() throws {
            let store = core.stateStore
            try store.prepareDirectories()
            let id = "0123456789abcdef0123cafe"
            let base = store.runtimes + "/" + id
            for directory in [base, base + "/bin", base + "/lib", base + "/lib/ossl-modules", base + "/lib/engines", base + "/etc"] {
                mkdir(directory, 0o755)
            }
            func write(_ relative: String, _ data: Data, _ mode: Int) -> [String: Any] {
                let path = base + "/" + relative
                FileManager.default.createFile(atPath: path, contents: data)
                chmod(path, mode_t(mode))
                return ["path": relative, "sha256": CheckPointAuthority.digest(data), "mode": mode]
            }
            let files = [write("bin/snx-rs", Data(Self.script.utf8), 0o555), write("etc/openssl.cnf", Data("# vazio\n".utf8), 0o444)]
            let manifest: [String: Any] = [
                "format": 1, "id": id, "approvedAt": Date().timeIntervalSince1970, "approvedByUID": getuid(), "version": "6.6.1",
                "inventoryDigest": "fixture", "sourcePath": "/fixture/snx-rs", "sourceSHA256": "0", "kind": "snxrs",
                "capabilities": ["cookieOnStdin": false, "captureCookie": false, "samlPort": false],
                "files": files, "sources": [], "systemLibraries": [], "notes": []]
            FileManager.default.createFile(atPath: base + "/manifest.json", contents: try JSONSerialization.data(withJSONObject: manifest))
            chmod(base + "/manifest.json", 0o444)
            let state: [String: Any] = ["format": 1, "activeSnxRuntime": id, "authorizedUsers": [getuid()]]
            FileManager.default.createFile(atPath: store.statePath, contents: try JSONSerialization.data(withJSONObject: state))
            chmod(store.statePath, 0o644)
        }

        func tearDown() {
            core.shutdown(timeout: 10)
            try? FileManager.default.removeItem(atPath: root)
        }
    }

    func testHelperQueriesTheGatewayWithoutRootOrIgnoreServerCert() throws {
        let fixture = try Fixture()
        defer { fixture.tearDown() }
        let query = CheckPointGatewayQuery(host: "203.0.113.58", port: 443, authorityDER: nil)
        guard case .failure(let unauthorized)? = fixture.send(.queryCheckPointGateway(query)) else { return XCTFail("Consulta sem usuário autorizado") }
        XCTAssertEqual(unauthorized.code, .userNotAuthorized)
        let store = fixture.core.stateStore
        try store.prepareDirectories()
        FileManager.default.createFile(atPath: store.statePath, contents: Data(#"{"format":1,"authorizedUsers":[\#(getuid())]}"#.utf8))
        guard case .failure(let missing)? = fixture.send(.queryCheckPointGateway(query)) else { return XCTFail("Consulta sem runtime aprovado") }
        XCTAssertEqual(missing.code, .runtimeUnavailable)
        unlink(store.statePath)
        try fixture.installStandIn()
        guard case .checkPointGateway(let info)? = fixture.send(.queryCheckPointGateway(query)) else { return XCTFail("Consulta falhou") }
        XCTAssertNil(info.failure)
        XCTAssertEqual(info.loginOptions, [CheckPointLoginOption(displayName: "Standard", id: "vpn", factors: ["user_defined"])])
        XCTAssertEqual(info.fingerprintWords, "BOAT HIT GAS MOLD ICY FEN AWE TOOL BIT RAN SOD WAND")
        guard case .status(let status)? = fixture.send(.status) else { return XCTFail("Status") }
        XCTAssertEqual(status.snxRuntime?.version, "6.6.1")
        XCTAssertTrue(FileManager.default.fileExists(atPath: fixture.core.stateStore.root))
    }

    func testOneCheckPointSessionAtATime() throws {
        let fixture = try Fixture()
        defer { fixture.tearDown() }
        try fixture.installStandIn()
        fixture.host.interfaces = ["utun99"]
        fixture.dns.publish("utun5") // Left by an earlier snx-rs: removed before the start.
        func request() -> CheckPointRequest {
            CheckPointRequest(connectionID: UUID(), host: "203.0.113.58", port: 443, username: "user", password: "secret-pass",
                              loginType: "vpn", authorityDER: nil, allTraffic: false)
        }
        guard case .started(let token, _)? = fixture.send(.startCheckPoint(request())) else { return XCTFail("Primeira sessão") }
        XCTAssertEqual(fixture.dns.removed, ["utun5"])
        let deadline = Date().addingTimeInterval(5)
        while !fixture.lines.contains(CheckPointRules.networkReady + "utun99") && Date() < deadline { usleep(50_000) }
        XCTAssertTrue(fixture.lines.contains("ARGS:-m standalone -c /dev/fd/3"), "\(fixture.lines)")
        XCTAssertTrue(fixture.lines.contains("LOGIN:vpn"), "\(fixture.lines)")
        XCTAssertTrue(fixture.lines.contains(CheckPointRules.networkReady + "utun99"), "\(fixture.lines)")
        XCTAssertFalse(fixture.lines.contains { $0.contains("secret-pass") || $0.contains(Data("secret-pass".utf8).base64EncodedString()) })
        guard case .failure(let refused)? = fixture.send(.startCheckPoint(request())) else { return XCTFail("Segunda sessão aceita") }
        XCTAssertEqual(refused.code, .busy)
        XCTAssertEqual(refused.message, "Já existe uma conexão Check Point ativa; desconecte-a antes.")
        _ = fixture.send(.stop(token: token))
        let stopped = Date().addingTimeInterval(10)
        while fixture.core.sessionCount > 0 && Date() < stopped { usleep(50_000) }
        XCTAssertEqual(fixture.core.sessionCount, 0)
        XCTAssertTrue(fixture.lines.contains("Tunnel disconnected"))
        let work = fixture.core.stateStore.work
        XCTAssertFalse(((try? FileManager.default.contentsOfDirectory(atPath: work)) ?? []).contains { $0.hasPrefix("cp.") })
    }

    /// The editor queries the gateway by itself once the address is complete.
    func testCompleteGatewayAddressStartsTheQuery() {
        for complete in ["203.0.113.10", "203.0.113.10:4443", "vpn.example.com", "vpn.example.com:10443", "[2001:db8::1]", " vpn.example.com "] {
            XCTAssertTrue(CheckPointGateway.isCompleteAddress(complete), complete)
        }
        for partial in ["", "203", "203.0.113", "203.0.113.", "203.0.113.256", "vpn", "vpn.", "vpn.example.c", "vpn.example.123",
                        "vpn.example.com/realm", "vpn.example.com:"] {
            XCTAssertFalse(CheckPointGateway.isCompleteAddress(partial), partial)
        }
    }
}
