import XCTest
import Darwin
import VPNHelperShared
@testable import VPNHelperCore
@testable import VPNApp

final class NetworkHost: WireGuardHost {
    var dns: [String: Any]? = ["ServerAddresses": ["192.0.2.53"]]
    var failDNS = false
    var failDelete = false
    var failAdd = false
    var routes: [String: String] = [:]
    var commands: [[String]] = []
    var endpoint = "203.0.113.10:51820"
    var journal: String?
    var observedIntent = false
    var defaultGateway: String? = "192.0.2.1"
    func run(_ tool: String, _ args: [String]) -> CommandResult {
        commands.append(args)
        if tool == WireGuardTools.netstat { return .init(status: 0, output: defaultGateway.map { "default \($0) UGScg en0\n" } ?? "") }
        if tool == WireGuardTools.route {
            if args.contains("get") {
                let destination = args.last!
                if let gateway = routes[destination] { return .init(status: 0, output: "destination: \(destination)\ngateway: \(gateway)\ninterface: en0\n") }
                return .init(status: 1, output: "not found")
            }
            if let index = args.firstIndex(of: "-gateway") {
                let destination = args[index - 1], gateway = args[index + 1]
                if args.contains("add") {
                    if let journal, let data = try? Data(contentsOf: URL(fileURLWithPath: journal)),
                       let record = try? JSONDecoder().decode(WireGuardTunnel.Record.self, from: data) {
                        observedIntent = record.routes.contains { $0.destination == destination && $0.gateway == gateway }
                    }
                    if failAdd { return .init(status: 1, output: "injected failure") }
                    routes[destination] = gateway
                } else if args.contains("delete") {
                    if failDelete { return .init(status: 2, output: "injected failure") }
                    routes.removeValue(forKey: destination)
                }
            }
        }
        return .init(status: 0, output: "")
    }
    func resolve(_ host: String, port: Int) -> [String] { ["203.0.113.10"] }
    func uapi(interface: String, pid: pid_t, request: String) throws -> String {
        request.hasPrefix("get=") ? "endpoint=\(endpoint)\nlast_handshake_time_sec=1\nerrno=0\n\n" : "errno=0\n\n"
    }
    func primaryService() -> String? { "primary" }
    func dnsSetup(service: String) -> [String: Any]? { dns }
    func setDNSSetup(service: String, value: [String: Any]?) -> Bool {
        guard !failDNS else { return false }; dns = value; return true
    }
}

extension ReviewTests {
    func tunnel(_ root: URL, _ host: NetworkHost, token: String = UUID().uuidString, dns: Bool = true) throws -> WireGuardTunnel {
        let key = Data(repeating: 1, count: 32).base64EncodedString()
        let profile = try WireGuardProfile.validated("""
        [Interface]
        PrivateKey = \(key)
        Address = 10.0.0.2/32
        MTU = 1420
        \(dns ? "DNS = 10.0.0.1" : "")
        [Peer]
        PublicKey = \(Data(repeating: 2, count: 32).base64EncodedString())
        Endpoint = 203.0.113.10:51820
        AllowedIPs = 0.0.0.0/1, 128.0.0.0/1
        """)
        let name = root.appendingPathComponent(token + ".name")
        try Data("utun42\n".utf8).write(to: name)
        let journal = root.appendingPathComponent(token + ".json").path
        host.journal = journal
        let tunnel = WireGuardTunnel(token: token, profile: profile, host: host, nameFile: name.path, recordPath: journal)
        tunnel.interval = 60
        return tunnel
    }
    func testWireGuardIntentPrecedesBypassAndFailedCleanupSurvivesRestart() throws {
        let root = try temporary(), host = NetworkHost()
        let tunnel = try tunnel(root, host)
        let ready = expectation(description: "ready")
        tunnel.ready = { ready.fulfill() }
        tunnel.clientStarted(pid: getpid())
        wait(for: [ready], timeout: 2)
        XCTAssertTrue(host.observedIntent)
        XCTAssertEqual(host.routes["203.0.113.10"], "192.0.2.1")
        let bypass = host.commands.firstIndex { $0.contains("-gateway") && $0.contains("add") }!
        let captured = host.commands.firstIndex { $0.contains("0.0.0.0/1") && $0.contains("add") }!
        XCTAssertLessThan(bypass, captured)
        host.failDNS = true; host.failDelete = true
        tunnel.clientEnded()
        XCTAssertNotNil(tunnel.cleanupFailure)
        XCTAssertTrue(FileManager.default.fileExists(atPath: tunnel.recordPath))
        host.failDNS = false; host.failDelete = false
        WireGuardTunnel.recover(directory: root.path, host: host, live: [])
        XCTAssertFalse(FileManager.default.fileExists(atPath: tunnel.recordPath))
        XCTAssertTrue(host.routes.isEmpty)
        XCTAssertEqual(host.dns?["ServerAddresses"] as? [String], ["192.0.2.53"])
    }
    func testWireGuardBypassFailureNeverReportsReady() throws {
        let root = try temporary(), host = NetworkHost()
        host.failAdd = true
        let tunnel = try tunnel(root, host)
        let failed = expectation(description: "failed")
        var ready = false
        tunnel.fail = { failed.fulfill() }; tunnel.ready = { ready = true }
        tunnel.clientStarted(pid: getpid())
        wait(for: [failed], timeout: 2)
        tunnel.clientEnded()
        XCTAssertFalse(ready)
        XCTAssertEqual(host.dns?["ServerAddresses"] as? [String], ["192.0.2.53"])
        XCTAssertFalse(host.commands.contains { $0.contains("0.0.0.0/1") && $0.contains("add") })
    }
    func testWireGuardRequiredDNSFailureNeverReportsReady() throws {
        let root = try temporary(), host = NetworkHost()
        host.failDNS = true
        let tunnel = try tunnel(root, host)
        let failed = expectation(description: "failed")
        var ready = false
        tunnel.fail = { failed.fulfill() }; tunnel.ready = { ready = true }
        tunnel.clientStarted(pid: getpid())
        wait(for: [failed], timeout: 2)
        tunnel.clientEnded()
        XCTAssertFalse(ready)
    }
    func testConnectedTunnelSurvivesLosingTheDefaultRouteAndFollowsTheNewGateway() throws {
        let root = try temporary(), host = NetworkHost()
        let tunnel = try tunnel(root, host, dns: false)
        let ready = expectation(description: "ready")
        var failed = false
        tunnel.interval = 0.05
        tunnel.ready = { ready.fulfill() }; tunnel.fail = { failed = true }
        tunnel.clientStarted(pid: getpid())
        wait(for: [ready], timeout: 2)
        host.defaultGateway = nil // Sleep or Wi-Fi roaming: no physical default route for a while.
        RunLoop.current.run(until: Date().addingTimeInterval(0.4))
        XCTAssertFalse(failed)
        host.defaultGateway = "192.0.2.254"
        let moved = Date().addingTimeInterval(2)
        while host.routes["203.0.113.10"] != "192.0.2.254" && Date() < moved { RunLoop.current.run(until: Date().addingTimeInterval(0.05)) }
        XCTAssertEqual(host.routes["203.0.113.10"], "192.0.2.254")
        XCTAssertFalse(failed)
        tunnel.clientEnded()
        XCTAssertTrue(host.routes.isEmpty)
    }
    func testSharedEndpointRouteSurvivesUntilLastTunnelEnds() throws {
        let root = try temporary(), host = NetworkHost()
        let first = try tunnel(root, host, dns: false)
        let a = expectation(description: "first ready"); first.ready = { a.fulfill() }
        first.clientStarted(pid: getpid()); wait(for: [a], timeout: 2)
        let second = try tunnel(root, host, dns: false)
        let b = expectation(description: "second ready"); second.ready = { b.fulfill() }
        second.clientStarted(pid: getpid()); wait(for: [b], timeout: 2)
        first.clientEnded()
        XCTAssertEqual(host.routes["203.0.113.10"], "192.0.2.1")
        second.clientEnded()
        XCTAssertTrue(host.routes.isEmpty)
    }
}
