import XCTest
import Darwin
import VPNHelperShared
@testable import VPNHelperCore
@testable import VPNApp

final class RouteHost: WireGuardHost {
    var commands: [[String]] = []
    func run(_ tool: String, _ arguments: [String]) -> CommandResult { commands.append([tool] + arguments); return .init(status: 0, output: "") }
    func resolve(_ host: String, port: Int) -> [String] { [] }
    func uapi(interface: String, pid: pid_t, request: String) throws -> String { "" }
    func primaryService() -> String? { nil }
    func dnsSetup(service: String) -> [String: Any]? { nil }
    func setDNSSetup(service: String, value: [String: Any]?) -> Bool { true }
}

final class GlobalProtectTests: XCTestCase {
    private func callback(_ payload: String) -> String {
        "globalprotectcallback:" + Data(payload.utf8).base64EncodedString()
    }

    func testCallbackInsideHTMLCommentAsReturnedByPANOS() throws {
        let html = "<html><!-- <saml-auth-status>1</saml-auth-status><saml-username>test@example.invalid</saml-username><prelogin-cookie>FAKE+/==</prelogin-cookie> --></html>"
        let cookie = try GlobalProtectRules.parseCallback(callback(html))
        XCTAssertEqual(cookie, GlobalProtectCookie(username: "test@example.invalid", kind: .preloginCookie, value: "FAKE+/=="))
    }

    func testCallbackJSONAndURLSafeBase64() throws {
        let json = #"{"username":"test","portalUserauthcookie":"fake"}"#
        let encoded = Data(json.utf8).base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            .trimmingCharacters(in: CharacterSet(charactersIn: "="))
        let cookie = try GlobalProtectRules.parseCallback("globalprotectcallback:cas-as=" + encoded)
        XCTAssertEqual(cookie.kind, .portalUserauthcookie)
        XCTAssertEqual(cookie.value, "fake")
    }

    func testRejectedOrIncompleteCallbacks() {
        for raw in ["bad", "globalprotectcallback:???", "https://example.invalid",
                    callback("<saml-auth-status>-1</saml-auth-status><saml-username>x</saml-username><prelogin-cookie>c</prelogin-cookie>"),
                    callback("<saml-auth-status>1</saml-auth-status><saml-username>x</saml-username>"),
                    callback("<saml-auth-status>1</saml-auth-status><saml-username>x\ny</saml-username><prelogin-cookie>c</prelogin-cookie>"),
                    callback("<saml-auth-status>1</saml-auth-status><saml-username>x</saml-username><prelogin-cookie>a b</prelogin-cookie>"),
                    "globalprotectcallback:" + String(repeating: "A", count: GlobalProtectRules.maximumCallback)] {
            XCTAssertThrowsError(try GlobalProtectRules.parseCallback(raw), raw.prefix(60).description)
        }
    }

    func testPreloginRedirectPostAndPassword() throws {
        func response(_ body: String) -> Data { Data("<?xml version=\"1.0\"?><prelogin-response>\(body)</prelogin-response>".utf8) }
        let url = Data("https://login.example.invalid/saml?x=1".utf8).base64EncodedString()
        let redirect = try GlobalProtectPrelogin.parse(response("<status>Success</status><saml-auth-method>REDIRECT</saml-auth-method><saml-request>\(url)</saml-request><saml-default-browser>yes</saml-default-browser>"))
        XCTAssertEqual(redirect.method, .redirect)
        XCTAssertEqual(redirect.request, "https://login.example.invalid/saml?x=1")
        XCTAssertTrue(redirect.defaultBrowser)
        let password = try GlobalProtectPrelogin.parse(response("<status>Success</status>"))
        XCTAssertNil(password.method)
        let plain = Data("http://login.example.invalid/".utf8).base64EncodedString()
        XCTAssertThrowsError(try GlobalProtectPrelogin.parse(response("<status>Success</status><saml-auth-method>REDIRECT</saml-auth-method><saml-request>\(plain)</saml-request>")))
        XCTAssertThrowsError(try GlobalProtectPrelogin.parse(response("<status>Error</status><msg>nope</msg>")))
        XCTAssertThrowsError(try GlobalProtectPrelogin.parse(Data("<html>".utf8)))
    }

    func testOpenConnectConfigHasOnlyFixedOptions() throws {
        let config = try OpenConnectConfigRenderer.render(username: "test@example.invalid", cookieKind: .preloginCookie,
                                                          trustedCertificate: String(repeating: "A", count: 64), script: "/private/var/db/x/vpnc/s")
        let lines = config.split(separator: "\n").map(String.init)
        XCTAssertEqual(lines, ["protocol=gp", "os=mac-intel", "non-inter", "disable-ipv6", "no-system-trust",
                               "cafile=/private/etc/ssl/cert.pem", "user=test@example.invalid", "usergroup=gateway:prelogin-cookie",
                               "servercert=sha256:" + String(repeating: "a", count: 64), "script=/private/var/db/x/vpnc/s"])
        XCTAssertThrowsError(try OpenConnectConfigRenderer.render(username: "a\nscript=/tmp/x", cookieKind: nil, trustedCertificate: "", script: "/s"))
        XCTAssertThrowsError(try OpenConnectConfigRenderer.render(username: "a", cookieKind: nil, trustedCertificate: "", script: "/s; rm"))
        XCTAssertEqual(try OpenConnectConfigRenderer.server(host: "vpn.example.invalid", port: 443), "vpn.example.invalid")
        XCTAssertEqual(try OpenConnectConfigRenderer.server(host: "vpn.example.invalid", port: 4443), "vpn.example.invalid:4443")
        XCTAssertThrowsError(try OpenConnectConfigRenderer.server(host: "-x", port: 443))
    }

    func testRequestValidationKeepsSecretsOffTheConfig() throws {
        let id = UUID()
        let saml = GlobalProtectRequest(connectionID: id, host: "vpn.example.invalid", port: 443, username: "", authentication: .saml,
                                        trustedCertificate: "", password: nil,
                                        cookie: GlobalProtectCookie(username: "u@example.invalid", kind: .preloginCookie, value: "COOKIE"))
        let login = try saml.validated()
        XCTAssertEqual(login.username, "u@example.invalid")
        XCTAssertEqual(login.secret, "COOKIE")
        XCTAssertEqual(login.cookieKind, .preloginCookie)
        var withPassword = saml; withPassword.password = "x"
        XCTAssertThrowsError(try withPassword.validated())
        var noCookie = saml; noCookie.cookie = nil
        XCTAssertThrowsError(try noCookie.validated())
        let password = GlobalProtectRequest(connectionID: id, host: "vpn.example.invalid", port: 443, username: "user", authentication: .password,
                                            trustedCertificate: "", password: "secret", cookie: nil)
        XCTAssertNil(try password.validated().cookieKind)
        var newline = password; newline.password = "a\nb"
        XCTAssertThrowsError(try newline.validated())
        var empty = password; empty.username = ""
        XCTAssertThrowsError(try empty.validated())
    }

    func testRecordedRoutesAreParsedStrictlyAndRemoved() throws {
        let text = "host 203.0.113.10 192.168.18.1\nnet 150.171.40.0/22 192.168.18.1\nnet 1.2.3.4/8; rm 192.168.18.1\nroute x y\n"
        let routes = GlobalProtectNetwork.recordedRoutes(text)
        XCTAssertEqual(routes.map(\.destination), ["203.0.113.10", "150.171.40.0/22"])
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("gp-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let token = UUID().uuidString, live = UUID().uuidString
        try Data(text.utf8).write(to: URL(fileURLWithPath: GlobalProtectNetwork.routesFile(work: directory.path, token: token)))
        try Data(text.utf8).write(to: URL(fileURLWithPath: GlobalProtectNetwork.routesFile(work: directory.path, token: live)))
        let host = RouteHost()
        GlobalProtectNetwork.recover(work: directory.path, live: [live], host: host)
        XCTAssertEqual(host.commands.count, 2)
        XCTAssertEqual(host.commands[0], [WireGuardTools.route, "-q", "-n", "delete", "-inet", "-host", "203.0.113.10", "192.168.18.1"])
        XCTAssertFalse(FileManager.default.fileExists(atPath: GlobalProtectNetwork.routesFile(work: directory.path, token: token)))
        XCTAssertTrue(FileManager.default.fileExists(atPath: GlobalProtectNetwork.routesFile(work: directory.path, token: live)))
    }

    /// The embedded vpnc-script parses with /bin/sh and refuses to run without a session.
    func testVPNCScriptSyntaxAndGuards() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("gp-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let script = directory.appendingPathComponent("script")
        try Data(GlobalProtectNetwork.script.utf8).write(to: script)
        func run(_ arguments: [String], environment: [String: String]) throws -> (Int32, String) {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/bin/sh")
            process.arguments = arguments
            process.environment = environment
            let pipe = Pipe()
            process.standardOutput = pipe
            process.standardError = pipe
            try process.run()
            process.waitUntilExit()
            return (process.terminationStatus, String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self))
        }
        XCTAssertEqual(try run(["-n", script.path], environment: [:]).0, 0)
        let (status, output) = try run([script.path], environment: ["reason": "connect", "TUNNELMAC_TOKEN": "$(touch /tmp/x)"])
        XCTAssertEqual(status, 1)
        XCTAssertTrue(output.contains("sessão inválida"))
        // A bad interface name stops "connect" before any system change.
        let routes = directory.appendingPathComponent("oc.routes").path
        let (refused, message) = try run([script.path], environment: ["reason": "connect", "TUNNELMAC_TOKEN": UUID().uuidString,
                                                                       "TUNNELMAC_ROUTES": routes, "TUNDEV": "en0;x"])
        XCTAssertEqual(refused, 1)
        XCTAssertTrue(message.contains("Interface inesperada"))
        XCTAssertFalse(FileManager.default.fileExists(atPath: routes))
    }

    func testGlobalProtectConnectionValidation() throws {
        var connection = Connection(name: " Matriz ", server: "vpn.example.invalid", authentication: .saml, kind: .globalProtect)
        connection.realm = "x"
        let valid = try connection.validated()
        XCTAssertEqual(valid.name, "Matriz")
        XCTAssertEqual(valid.realm, "")
        XCTAssertFalse(valid.usesProfile)
        XCTAssertFalse(valid.usesPassword)
        XCTAssertEqual(valid.kind.runtime, .openconnect)
        var password = connection; password.authentication = .password
        XCTAssertThrowsError(try password.validated())
        password.username = "user"
        XCTAssertTrue(try password.validated().usesPassword)
    }

    @MainActor func testSessionMarksTheTunnelFromOpenConnectOutput() {
        let session = Session(id: UUID())
        session.begin(client: "OpenConnect")
        session.acceptGlobalProtect("Connected as 10.0.0.2", saml: true)
        XCTAssertNotEqual(session.state, .connected)
        session.acceptGlobalProtect("Configured as 172.19.202.72, with SSL connected and ESP disabled", saml: true)
        XCTAssertEqual(session.state, .connected)
        let failed = Session(id: UUID())
        failed.begin(client: "OpenConnect")
        failed.acceptGlobalProtect("Login failed.", saml: false)
        XCTAssertTrue(failed.authenticationRejected)
        XCTAssertTrue(failed.retryBlocked)
    }
}

extension GlobalProtectTests {
    /// PAN-OS sends 0.0.0.0/0 next to /32 includes (its DNS servers): that is a full tunnel.
    /// Runs the script's connect phase with stub tools that only record their arguments.
    func testDefaultNetworkAmongIncludesMakesAFullTunnel() throws {
        let (recorded, output) = try runConnect(networks: nil)
        XCTAssertTrue(recorded.contains("route -q -n add -inet -net 0.0.0.0/1 -interface utun8"), recorded)
        XCTAssertTrue(recorded.contains("route -q -n add -inet -net 128.0.0.0/1 -interface utun8"), recorded)
        XCTAssertTrue(recorded.contains("route -q -n add -inet -net 172.16.2.31/32 -interface utun8"), recorded)
        XCTAssertTrue(recorded.contains("-net 13.107.6.171/32 192.168.18.1"), recorded)
        XCTAssertFalse(recorded.contains("172.19.202.73/32"), recorded)
        XCTAssertTrue(output.contains("para todos os nomes"), output)
    }

    /// "Só redes internas": only those networks and the gateway's domains use the tunnel.
    func testInternalNetworksOverrideTheGatewayDefaultRoute() throws {
        let (recorded, output) = try runConnect(networks: "10.0.0.0/8 172.16.0.0/12")
        XCTAssertFalse(recorded.contains("0.0.0.0/1"), recorded)
        XCTAssertTrue(recorded.contains("route -q -n add -inet -net 10.0.0.0/8 -interface utun8"), recorded)
        XCTAssertTrue(recorded.contains("route -q -n add -inet -net 172.16.0.0/12 -interface utun8"), recorded)
        XCTAssertFalse(recorded.contains("13.107.6.171"), recorded)
        XCTAssertTrue(recorded.contains("-host 203.0.113.1 192.168.18.1"), recorded)
        XCTAssertTrue(output.contains("para example.invalid"), output)
    }

    private func runConnect(networks: String?) throws -> (String, String) {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("gp-\(UUID().uuidString)")
        let bin = directory.appendingPathComponent("bin")
        try FileManager.default.createDirectory(at: bin, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let calls = directory.appendingPathComponent("calls").path
        for tool in ["ifconfig", "route", "scutil", "dscacheutil", "killall"] {
            let stub = bin.appendingPathComponent(tool)
            try Data("#!/bin/sh\necho \"\(tool) $*\" >> \(calls)\ncat >/dev/null 2>&1 </dev/null\n".utf8).write(to: stub)
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: stub.path)
        }
        let netstat = bin.appendingPathComponent("netstat")
        try Data("#!/bin/sh\necho 'default            192.168.18.1       UGScg                 en0'\n".utf8).write(to: netstat)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: netstat.path)
        // The script fixes PATH itself; run a copy that points it at the stubs first.
        let script = directory.appendingPathComponent("script")
        try Data(GlobalProtectNetwork.script.replacingOccurrences(of: "PATH=/usr/bin:/bin:/usr/sbin:/sbin", with: "PATH=\(bin.path):/usr/bin:/bin").utf8).write(to: script)
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sh")
        process.arguments = [script.path]
        process.environment = ["reason": "connect", "TUNNELMAC_TOKEN": UUID().uuidString,
                               "TUNNELMAC_ROUTES": directory.appendingPathComponent("routes").path,
                               "TUNDEV": "utun8", "INTERNAL_IP4_ADDRESS": "172.19.202.73", "VPNGATEWAY": "203.0.113.1",
                               "INTERNAL_IP4_DNS": "172.16.2.30 172.16.2.31", "CISCO_DEF_DOMAIN": "example.invalid",
                               "CISCO_SPLIT_INC": "4",
                               "CISCO_SPLIT_INC_0_ADDR": "172.19.202.73", "CISCO_SPLIT_INC_0_MASKLEN": "32",
                               "CISCO_SPLIT_INC_1_ADDR": "172.16.2.31", "CISCO_SPLIT_INC_1_MASKLEN": "32",
                               "CISCO_SPLIT_INC_2_ADDR": "172.16.2.30", "CISCO_SPLIT_INC_2_MASKLEN": "32",
                               "CISCO_SPLIT_INC_3_ADDR": "0.0.0.0", "CISCO_SPLIT_INC_3_MASKLEN": "0",
                               "CISCO_SPLIT_EXC": "1", "CISCO_SPLIT_EXC_0_ADDR": "13.107.6.171", "CISCO_SPLIT_EXC_0_MASKLEN": "32",
                               "TUNNELMAC_INTERNAL_NETWORKS": networks ?? ""]
        let pipe = Pipe()
        process.standardOutput = pipe
        try process.run()
        process.waitUntilExit()
        let output = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        return ((try? String(contentsOfFile: calls, encoding: .utf8)) ?? "", output)
    }
}

extension GlobalProtectTests {
    func testInternalNetworksAreCanonicalAndBounded() throws {
        XCTAssertEqual(try GlobalProtectRules.internalNetworks(["10.1.2.3/8", " 172.16.0.0/12", "10.0.0.0/8", "192.0.2.7"]),
                       ["10.0.0.0/8", "172.16.0.0/12", "192.0.2.7/32"])
        for bad in [["0.0.0.0/0"], ["10.0.0.0/33"], ["10.0.0.0/8; rm"], ["fe80::/10"], []] {
            XCTAssertThrowsError(try GlobalProtectRules.internalNetworks(bad), bad.description)
        }
        var connection = Connection(name: "GEQ", server: "vpn.example.invalid", authentication: .saml, kind: .globalProtect)
        connection.internalNetworks = ["10.9.9.9/8"]
        XCTAssertEqual(try connection.validated().internalNetworks, ["10.0.0.0/8"])
        let decoded = try JSONDecoder().decode(Connection.self, from: JSONEncoder().encode(connection))
        XCTAssertEqual(decoded.internalNetworks, ["10.9.9.9/8"])
        XCTAssertFalse(decoded.allTraffic)
        // A new connection routes only the default internal networks; all traffic is opt-in.
        let fresh = Connection(name: "Nova", server: "vpn.example.invalid", authentication: .saml, kind: .globalProtect)
        XCTAssertFalse(fresh.allTraffic)
        XCTAssertEqual(fresh.routedNetworks, GlobalProtectRules.defaultInternalNetworks)
    }
}

extension GlobalProtectTests {
    func testScriptLinesAreReadableInTheLog() {
        XCTAssertEqual(GlobalProtectMarkers.display("[#] DNS da VPN ( 10.0.0.53 10.0.0.54 ) para todos os nomes."),
                       "[#] DNS da VPN (10.0.0.53 10.0.0.54) para todos os nomes.")
        XCTAssertEqual(GlobalProtectMarkers.display("[#] DNS da VPN ( 10.0.0.53 ) para a.example b.example; os demais nomes seguem no DNS atual."),
                       "[#] DNS da VPN (10.0.0.53) para a.example b.example; os demais nomes seguem no DNS atual.")
        XCTAssertEqual(GlobalProtectMarkers.display("[#] route add -net 10.0.0.0/8 -interface utun8"), "[#] route add -net 10.0.0.0/8 -interface utun8")
    }
}
