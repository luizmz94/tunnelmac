@testable import VPNApp
import SwiftUI
import AppKit
import Combine
import VPNHelperShared

/// README demo: the real interface over fictitious connections. Conectar goes through the
/// app's own session logic with the local checks harness, which replays client output
/// instead of reaching the helper. No VPN, no privileges, no network, no service
/// registration; passwords use a disposable Keychain service deleted at quit.
///
///   --showcase              interactive demo (menu bar icon included)
///   --showcase-capture DIR  scripted tour that writes the README images to DIR, then quits
struct ShowcaseApp: App {
    static var requested: Bool { CommandLine.arguments.contains { $0 == "--showcase" || $0 == "--showcase-capture" } }
    static var captureDirectory: URL? {
        guard let index = CommandLine.arguments.firstIndex(of: "--showcase-capture"),
              CommandLine.arguments.indices.contains(index + 1) else { return nil }
        return URL(fileURLWithPath: CommandLine.arguments[index + 1], isDirectory: true)
    }

    @NSApplicationDelegateAdaptor(AppDelegate.self) var delegate
    @StateObject private var demo = ShowcaseDemo()

    init() { signal(SIGPIPE, SIG_IGN) }

    var body: some Scene {
        WindowGroup("TunnelMac · \(HelperConstants.version)", id: MenuBarCoordinator.sceneID) {
            MainView(model: demo.model, menuBar: demo.menuBar)
                .frame(minWidth: 850, minHeight: 550)
                .onAppear {
                    delegate.attach(model: demo.model, menuBar: demo.menuBar)
                    demo.started()
                }
                .background(WindowCloseGuard(delegate: delegate, menuBar: demo.menuBar))
        }
        .commands {
            CommandGroup(replacing: .newItem) {}
            AppCommands(menuBar: demo.menuBar)
        }
        Window("Configurações", id: MenuBarCoordinator.settingsSceneID) {
            SettingsView(menuBar: demo.menuBar)
                .background(SettingsWindowBinding(menuBar: demo.menuBar))
        }
        .defaultSize(width: 760, height: 540)
    }
}

@MainActor
final class ShowcaseDemo: ObservableObject {
    let model: AppModel
    let menuBar: MenuBarCoordinator
    private let passwords = PasswordStore(service: "com.luiz.vpngui.showcase.password")
    private let root = FileManager.default.temporaryDirectory.appendingPathComponent("TunnelMac-showcase-\(UUID())")
    private var connections: [String: Connection] = [:]
    private var observers: [AnyCancellable] = []
    private var didStart = false

    init() {
        let service = ServiceController(policy: .unavailable(reason: "Demonstração"), registrar: nil, client: nil)
        let status = ShowcaseDemo.status
        service.useForLocalChecks(status: status)
        let store = try! JSONStore(directory: root)
        model = AppModel(store: store, passwords: passwords,
                         cookies: SAMLCookieStore(service: "com.luiz.vpngui.showcase.cookie"), service: service)
        // The demo bundle has its own identifier: the language survives "Reabrir agora".
        let preferences = AppPreferences.disposable(realLanguage: true)
        model.manager.internetDNS = { [weak preferences] in preferences?.internetDNSServers }
        model.manager.officialCheckPointClientInstalled = { false }
        menuBar = MenuBarCoordinator(model: model, preferences: preferences)
        // The window and the menu bar re-read the real status when they appear; this demo
        // has no service behind it, so it keeps the fictitious one.
        service.objectWillChange.sink { [weak service] in
            DispatchQueue.main.async {
                guard let service, service.health != .ready else { return }
                service.useForLocalChecks(status: status)
            }
        }.store(in: &observers)
        model.manager.harness = VPNManager.LaunchHarness(help: SAMLCookieTests.help, launched: { [weak self] session, _, _ in
            self?.play(session, ShowcaseDemo.fortinetOutput)
        }, openVPNLaunched: { [weak self] session, _ in
            self?.play(session, ShowcaseDemo.openVPNOutput)
        }, wireGuardLaunched: { [weak self] session, _ in
            self?.play(session, ShowcaseDemo.wireGuardOutput)
        }, globalProtectLaunched: { [weak self] session, _ in
            self?.play(session, ShowcaseDemo.globalProtectOutput)
        }, checkPointLaunched: { [weak self] session, _ in
            self?.play(session, ShowcaseDemo.checkPointOutput)
        }, globalProtectLogin: { _ in
            // Stands in for the browser login (SAML in the default browser).
            try? await Task.sleep(nanoseconds: 300_000_000)
            return GlobalProtectCookie(username: "alex.morgan@globex.example", kind: .preloginCookie, value: "demo-only")
        })
        do { try seed() } catch { model.error = "Demonstração: \(error.localizedDescription)" }
        NotificationCenter.default.addObserver(forName: NSApplication.willTerminateNotification, object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.cleanUp() }
        }
    }

    private static var status: HelperStatus {
        func runtime(_ id: String, _ version: String, _ path: String, help: String = SAMLCookieTests.help) -> RuntimeSummary {
            RuntimeSummary(id: id, version: version, approvedAt: Date().addingTimeInterval(-86_400 * 3),
                           capabilities: RuntimeCapabilities(help: help), sourcePath: path, sourceSHA256: "0")
        }
        return HelperStatus(protocolVersion: HelperConstants.protocolVersion, helperVersion: HelperConstants.fullVersion,
                            runtime: runtime("openfortivpn", "1.24.1", "/opt/homebrew/Cellar/openfortivpn/1.24.1/bin/openfortivpn"),
                            runtimeProblem: nil, userAuthorized: true, activeSessions: 0, stoppingConnections: [],
                            openVPNRuntime: runtime("openvpn", "2.7.8", "/opt/homebrew/Cellar/openvpn/2.7.8_1/sbin/openvpn", help: ""),
                            wireGuardRuntime: runtime("wireguard-go", "0.0.20250522", "/opt/homebrew/Cellar/wireguard-go/0.0.20250522/bin/wireguard-go", help: ""),
                            openConnectRuntime: runtime("openconnect", "9.21", "/opt/homebrew/Cellar/openconnect/9.21/bin/openconnect", help: ""),
                            snxRuntime: runtime("snx-rs", "6.6.1", "/opt/homebrew/Cellar/snx-rs/6.6.1/bin/snx-rs", help: ""))
    }

    // MARK: Fictitious connections (reserved .example names and documentation addresses)

    private func seed() throws {
        func fortinet(_ name: String, _ server: String, port: Int = 443, user: String, saml: Bool = false) throws {
            let connection = Connection(name: name, server: server, port: port, username: saml ? "" : user,
                                        authentication: saml ? .saml : .password)
            try model.save(connection, password: saml ? "" : "demo-only")
            connections[name] = connection
        }
        try fortinet("Head Office", "vpn.acme.example", user: "alex.morgan")
        try fortinet("Horizon Client", "sso.horizon.example", port: 10443, user: "", saml: true)
        try fortinet("Staging", "vpn-staging.acme.example", port: 8443, user: "alex.morgan")

        let ovpn = OpenVPNTests.singleFile
            .replacingOccurrences(of: "auth RSA-SHA256", with: "auth SHA256")
            .replacingOccurrences(of: "cipher AES-256-CBC", with: "cipher AES-256-GCM")
            .replacingOccurrences(of: "remote sslvpn1.example.invalid 2400 tcp", with: "remote vpn.cloud.example 1194 tcp")
            .replacingOccurrences(of: "remote sslvpn2.example.invalid 2400 tcp\n", with: "")
            .replacingOccurrences(of: "comp-lzo adaptive\n", with: "")
        let imported = try OpenVPNImporter.importText(ovpn, baseDirectory: root, suggestedName: "Production Cloud",
                                                      source: "~/Downloads/production-cloud.ovpn")
        let openVPN = Connection(name: "Production Cloud", kind: .openvpn, openVPN: imported.summary)
        try model.save(openVPN, password: "", openVPNProfile: imported.profile.text)
        connections[openVPN.name] = openVPN

        func wireGuard(_ name: String, address: String, endpoint: String, allowed: String, dns: String) throws {
            let text = """
            [Interface]
            PrivateKey = \(WireGuardTests.privateKey)
            Address = \(address)
            DNS = \(dns)

            [Peer]
            PublicKey = \(WireGuardTests.serverKey)
            AllowedIPs = \(allowed)
            Endpoint = \(endpoint)
            PersistentKeepalive = 25
            """
            let imported = try WireGuardImporter.importText(text, suggestedName: name, source: "~/Downloads/\(name).conf")
            let connection = Connection(name: name, kind: .wireguard, wireGuard: imported.summary)
            try model.save(connection, password: "", wireGuardProfile: imported.profile.text)
            connections[name] = connection
        }
        try wireGuard("Home", address: "10.8.0.3/32", endpoint: "198.51.100.24:51820", allowed: "0.0.0.0/0, ::/0", dns: "10.8.0.1")
        try wireGuard("Lab", address: "10.44.0.7/32", endpoint: "203.0.113.77:51820",
                      allowed: "10.44.0.0/16, 172.20.0.0/16", dns: "10.44.0.1")

        let globalProtect = Connection(name: "Branch Office", server: "vpn.globex.example", authentication: .saml, kind: .globalProtect)
        try model.save(globalProtect, password: "")
        connections[globalProtect.name] = globalProtect

        // "Head Office" is already the Fortinet demo; the Check Point one has its own name.
        let checkPoint = Connection(name: "Initech HQ", server: "vpn.initech.example", username: "alex.morgan", kind: .checkPoint,
                                    checkPoint: CheckPointSettings(loginType: "vpn"))
        try model.save(checkPoint, password: "demo-only")
        connections[checkPoint.name] = checkPoint

        for connection in connections.values { observeDisconnect(connection) }
    }

    func started() {
        guard !didStart else { return }
        didStart = true
        // The app's own menu bar icon and menu panel (a demo, not the local checks).
        menuBar.installMenuBar(host: SystemStatusItemHost(), presenter: MenuBarPanelController(menuBar: menuBar))
        menuBar.installProgressPanel(ConnectionProgressPanelController(menuBar: menuBar))
        // Recording a shortcut in the demo's Configurações is the user's own action.
        menuBar.installHotKeys(GlobalHotKeyCenter(preferences: menuBar.preferences, registrar: CarbonHotKeyRegistrar(),
                                                  taps: EventTapModifierSource(), system: SymbolicHotKeys()) { [weak self] in
            self?.menuBar.toggleMenu(focusSearch: true)
        })
        // Two tunnels already up for a while, through the same connect path as the button.
        connect("Head Office", fast: true, since: 4_325)
        connect("Home", fast: true, since: 1_268)
        connect("Branch Office", fast: true, since: 2_140)
        connect("Initech HQ", fast: true, since: 812)
        if let directory = ShowcaseApp.captureDirectory {
            Task { await ShowcaseTour(demo: self, directory: directory).run() }
        } else {
            showFailure("Staging")
        }
    }

    func connection(_ name: String) -> Connection { connections[name]! }

    /// The interactive demo opens with one recent failure, as after an unreachable gateway.
    private func showFailure(_ name: String) {
        let session = model.manager.session(connection(name).id)
        session.begin()
        session.log("ERROR:  connect: Operation timed out")
        session.log("ERROR:  Could not connect to gateway (vpn-staging.acme.example:8443).")
        session.log("INFO:   Closed connection to gateway.")
        session.state = .failed
    }

    func connect(_ name: String, fast: Bool = false, since: TimeInterval? = nil) {
        let connection = connection(name)
        fastForward[connection.id] = fast
        model.connect(connection)
        if let since {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) { [weak self] in
                self?.model.manager.session(connection.id).connectedAt = Date().addingTimeInterval(-since)
            }
        }
    }

    // MARK: Replayed client output

    private var fastForward: [UUID: Bool] = [:]

    private func play(_ session: Session, _ output: [(TimeInterval, String, ConnectionState?)]) {
        guard let connection = connections.values.first(where: { $0.id == session.id }) else { return }
        let fast = fastForward[session.id] ?? false
        let generation = session.generation
        session.state = .connecting
        var delay: TimeInterval = 0
        for (pause, line, state) in output {
            delay += fast ? 0.01 : pause
            DispatchQueue.main.asyncAfter(deadline: .now() + delay) {
                guard session.generation == generation, session.state.active, !session.wantsDisconnect else { return }
                if let state { session.state = state }
                session.accept(line, connection: connection) { _ in }
            }
        }
    }

    private func observeDisconnect(_ connection: Connection) {
        let session = model.manager.session(connection.id)
        session.$state.removeDuplicates().sink { [weak self] state in
            guard state == .disconnecting else { return }
            let generation = session.generation
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.9) {
                guard let self, session.generation == generation, session.state == .disconnecting else { return }
                for line in ShowcaseDemo.closing(connection) { session.accept(line, connection: connection) { _ in } }
                self.model.manager.end(session, exit: 0)
            }
        }.store(in: &observers)
    }

    private static let fortinetOutput: [(TimeInterval, String, ConnectionState?)] = [
        (0.5, "INFO:   Connected to gateway.", nil),
        (0.5, "INFO:   Authenticated.", nil),
        (0.4, "INFO:   Remote gateway has allocated a VPN.", nil),
        (0.4, "INFO:   Got addresses: [10.212.134.21], ns [10.0.0.10, 10.0.0.11], ns_suffix [acme.example]", nil),
        (0.3, "INFO:   Negotiation complete.", nil),
        (0.3, "INFO:   Interface ppp0 is UP.", nil),
        (0.2, "INFO:   Setting new routes...", nil),
        (0.2, "INFO:   Adding VPN nameservers...", nil),
        (0.3, "INFO:   Tunnel is up and running.", nil)
    ]

    /// snx-rs standalone (en-US labels) and the helper's ready marker.
    private static let checkPointOutput: [(TimeInterval, String, ConnectionState?)] = [
        (0.4, "INFO snxcore::platform::macos: Cleaning up stale DNS entries", nil),
        (0.5, "INFO snxcore::tunnel::ipsec::connector: IPsec authentication succeeded", nil),
        (0.4, "         Server name: vpn.initech.example", nil),
        (0.1, "           User name: alex.morgan", nil),
        (0.1, "          Login type: vpn", nil),
        (0.1, "         Tunnel type: IPSec", nil),
        (0.1, "IPsec transport type: UDP TUN", nil),
        (0.1, "          IP address: 172.16.10.19/24", nil),
        (0.1, "         DNS servers: 198.51.100.53, 198.51.100.54", nil),
        (0.1, "      Search domains: initech.example", nil),
        (0.1, "           Interface: utun7", nil),
        (0.1, "      DNS configured: true", nil),
        (0.1, "  Routing configured: true", nil),
        (0.1, "       Default route: false", nil),
        (0.2, "Tunnel connected, press Ctrl-C to exit.", nil),
        (0.2, CheckPointRules.networkReady + "utun7", nil)
    ]

    private static let globalProtectOutput: [(TimeInterval, String, ConnectionState?)] = [
        (0.4, "POST https://vpn.globex.example/ssl-vpn/prelogin.esp?tmp=tmp&clientVer=4100&clientos=Mac", nil),
        (0.3, "Connected to 203.0.113.60:443", nil),
        (0.3, "Connected to HTTPS on vpn.globex.example with ciphersuite (TLS1.3)-(ECDHE-SECP256R1)-(RSA-PSS-RSAE-SHA256)-(AES-256-GCM)", nil),
        (0.4, "POST https://vpn.globex.example/ssl-vpn/getconfig.esp", nil),
        (0.3, "Configured as 10.31.4.18, with SSL connected and ESP disabled", nil),
        (0.2, "[#] ifconfig utun9 inet 10.31.4.18 mtu 1361 up", nil),
        (0.2, "[#] route add -host 203.0.113.60 192.168.1.1", nil),
        (0.2, "[i] O gateway pede todo o tráfego pela VPN; só as redes internas escolhidas usarão o túnel.", nil),
        (0.2, "[#] route add -net 10.0.0.0/8 -interface utun9", nil),
        (0.2, "[#] route add -net 172.16.0.0/12 -interface utun9", nil),
        (0.2, "[#] DNS da VPN ( 10.31.0.53 10.31.0.54 ) para globex.example; os demais nomes seguem no DNS atual.", nil),
        (0.1, "[+] TunnelMac: rede do túnel configurada em utun9.", nil)
    ]

    private static let openVPNOutput: [(TimeInterval, String, ConnectionState?)] = [
        (0.4, "OpenVPN 2.7.8 aarch64-apple-darwin [SSL (OpenSSL)] [LZO] [LZ4] [PKCS11] [MH/RECVDA] [AEAD]", nil),
        (0.4, "TCP/UDP: Preserving recently used remote address: [AF_INET]203.0.113.40:1194", nil),
        (0.4, "TCP connection established with [AF_INET]203.0.113.40:1194", nil),
        (0.5, "[vpn.cloud.example] Peer Connection Initiated with [AF_INET]203.0.113.40:1194", nil),
        (0.4, "Data Channel: cipher 'AES-256-GCM', peer-id: 3", nil),
        (0.3, "net_iface_up: set utun7 up", nil),
        (0.2, "net_route_v4_add: 10.20.0.0/16 via 10.20.0.1 dev [NULL] table 0 metric -1", nil),
        (0.2, "dns-updown: tunnel DNS applied (cloud.example → 10.20.0.2)", nil),
        (0.3, "Initialization Sequence Completed", nil)
    ]

    private static let wireGuardOutput: [(TimeInterval, String, ConnectionState?)] = [
        (0.3, "[+] WireGuard interface: utun6", nil),
        (0.3, "[#] ifconfig utun6 inet 10.8.0.3/32 10.8.0.3 alias", nil),
        (0.2, "[#] ifconfig utun6 mtu 1420", nil),
        (0.2, "[#] route -q -n add -inet 198.51.100.24 -gateway 192.168.1.1", nil),
        (0.2, "[#] route -q -n add -inet 0.0.0.0/1 -interface utun6", nil),
        (0.2, "[#] route -q -n add -inet 128.0.0.0/1 -interface utun6", nil),
        (0.2, "[#] DNS 10.8.0.1 on the primary network service", nil),
        (0.2, "\(WireGuardMarkers.ready) em utun6.", nil),
        (0.6, "\(WireGuardMarkers.handshake) com 198.51.100.24:51820.", nil)
    ]

    private static func closing(_ connection: Connection) -> [String] {
        switch connection.kind {
        case .fortinet: return ["INFO:   Cancelling threads...", "INFO:   Setting ppp interface down.", "INFO:   Restoring routes...",
                                "INFO:   Removing VPN nameservers...", "INFO:   Logged out."]
        case .openvpn: return ["SIGTERM[hard,] received, process exiting"]
        case .wireguard: return ["[#] Routes and DNS restored; interface removed."]
        case .globalProtect: return ["Logout successful.", "[#] Rotas e DNS da VPN removidos."]
        case .checkPoint: return ["Tunnel disconnected"]
        }
    }

    func cleanUp() {
        for connection in connections.values { try? passwords.delete(connection.id) }
        try? FileManager.default.removeItem(at: root)
    }
}

/// Scripted tour for the README images. Captures only this app's own windows.
@MainActor
struct ShowcaseTour {
    let demo: ShowcaseDemo
    let directory: URL

    func run() async {
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        await pause(1.5)
        guard let window = demo.menuBar.mainWindow ?? NSApp.windows.first(where: { $0.identifier == MenuBarCoordinator.windowIdentifier }) else {
            print("Showcase: janela principal não encontrada"); NSApp.terminate(nil); return
        }
        window.setContentSize(NSSize(width: 1180, height: 640))
        window.center()
        await activate(window)
        widenSidebar(window)
        await pause(0.5)

        for (appearance, suffix) in [(NSAppearance.Name.aqua, "light"), (.darkAqua, "dark")] {
            NSApp.appearance = NSAppearance(named: appearance)
            let dark = appearance == .darkAqua
            select("Head Office")
            await pause(1.2)
            await capture([window], key: window, "main-\(suffix)")
            select("Home")
            await pause(1.0)
            await capture([window], key: window, "wireguard-\(suffix)")
            select("Branch Office")
            await pause(1.0)
            await capture([window], key: window, "globalprotect-\(suffix)")
            select("Initech HQ")
            await pause(1.0)
            await capture([window], key: window, "checkpoint-\(suffix)")

            await activate(window)
            demo.menuBar.showMenu()
            await pause(1.5)
            if let panel = (demo.menuBar.menuPresenter as? MenuBarPanelController)?.panel {
                await captureGlass(panel, key: panel, dark: dark, "menubar-\(suffix)")
            }
            demo.menuBar.closeMenu()
            await pause(0.5)

            // The progress panel (top right corner of the screen) while a profile connects.
            await activate(window)
            demo.connect("Production Cloud")
            await pause(0.9)
            if let panel = (demo.menuBar.progressPresenter as? ConnectionProgressPanelController)?.panel, panel.isVisible {
                await captureGlass(panel, key: nil, dark: dark, "progress-\(suffix)")
            }
            demo.model.manager.disconnect(demo.connection("Production Cloud").id)
            await pause(1.5)

            await activate(window)
            press("n", keyCode: 45, in: window)
            await pause(1.2)
            if let sheet = window.attachedSheet {
                await capture([sheet, window], key: window, "new-connection-\(suffix)")
                press("\u{1b}", keyCode: 53, in: sheet, command: false)
                await pause(0.8)
                if let sheet = window.attachedSheet { window.endSheet(sheet) }
            }
            await pause(0.5)

            await captureOnboarding(over: window, suffix)
            await captureSettings(.backup, "backup-\(suffix)", height: 470)
            await activate(window)
        }
        NSApp.appearance = nil

        // Animated connect and disconnect of a Fortinet profile.
        NSApp.appearance = NSAppearance(named: .aqua)
        select("Staging")
        await activate(window)
        await pause(0.8)
        _ = await ensureActive(window, "connect.gif")
        let frames = directory.appendingPathComponent("frames-connect", isDirectory: true)
        try? FileManager.default.removeItem(at: frames)
        try? FileManager.default.createDirectory(at: frames, withIntermediateDirectories: true)
        var index = 0
        let recorder = Timer.scheduledTimer(withTimeInterval: 1.0 / 12, repeats: true) { _ in
            MainActor.assumeIsolated {
                index += 1
                ShowcaseTour.write([window], shadow: false, to: frames.appendingPathComponent(String(format: "%04d.png", index)))
            }
        }
        await pause(1.2)
        demo.connect("Staging")
        await pause(5.5)
        demo.model.manager.disconnect(demo.connection("Staging").id)
        await pause(2.5)
        recorder.invalidate()
        _ = await ensureActive(window, "connect.gif")

        // showcase.sh copies the images only when the tour got here.
        try? Data().write(to: directory.appendingPathComponent(".complete"))
        print("Showcase: imagens em \(directory.path)")
        fflush(stdout)
        demo.model.manager.disconnectAll()
        await pause(1.5)
        NSApp.terminate(nil)
    }

    /// The first-run guide at its first step on a fresh Mac: nothing approved yet,
    /// openfortivpn installed, OpenVPN behind Homebrew's formula, wireguard-go missing.
    private func captureOnboarding(over window: NSWindow, _ suffix: String) async {
        let service = ServiceController(policy: .unavailable(reason: "Demonstração"), registrar: nil, client: nil)
        service.useForLocalChecks(status: HelperStatus(protocolVersion: HelperConstants.protocolVersion,
                                                       helperVersion: HelperConstants.fullVersion, runtime: nil, runtimeProblem: nil,
                                                       userAuthorized: false, activeSessions: 0, stoppingConnections: []))
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("TunnelMac-showcase-guide-\(UUID())")
        defer { try? FileManager.default.removeItem(at: root) }
        guard let store = try? JSONStore(directory: root) else { return }
        let model = AppModel(store: store, passwords: PasswordStore(service: "com.luiz.vpngui.showcase.password"), service: service)
        let versions = ClientVersionChecker(transport: DisabledUpdateTransport())
        func fake() {
            versions.setForChecks(local: [.openfortivpn: .init(path: "/opt/homebrew/bin/openfortivpn", exists: true, version: "1.24.1", sourceChanged: false),
                                          .openvpn: .init(path: "/opt/homebrew/sbin/openvpn", exists: true, version: "2.7.8", sourceChanged: false),
                                          .wireguard: .init(path: "/opt/homebrew/bin/wireguard-go", exists: false, version: nil, sourceChanged: false),
                                          .openconnect: .init(path: "/opt/homebrew/bin/openconnect", exists: true, version: "9.21", sourceChanged: false),
                                          .snxrs: .init(path: "/opt/homebrew/bin/snx-rs", exists: true, version: "6.6.1", sourceChanged: false)],
                                  latest: [.openfortivpn: "1.24.1", .openvpn: "2.7.10", .wireguard: "0.0.20250522", .openconnect: "9.21", .snxrs: "6.6.1"])
        }
        fake()
        let guide = ServiceOnboardingSheet(model: model, versions: versions, forcedStep: .clients,
                                           chosen: [.openfortivpn, .openvpn, .wireguard, .openconnect, .snxrs]) { _ in }
        let controller = NSHostingController(rootView: guide)
        await activate(window)
        window.contentViewController?.presentAsSheet(controller)
        await pause(0.8)
        fake() // The guide reads this Mac's installations on appear.
        await pause(1.0)
        if let sheet = window.attachedSheet { await capture([sheet, window], key: window, "onboarding-\(suffix)") }
        window.contentViewController?.dismiss(controller)
        await pause(0.8)
    }

    /// Configurações on the given tab. The Window scene opens only through SwiftUI's
    /// openWindow, so the same view is hosted in a window of its own.
    private func captureSettings(_ tab: SettingsTab, _ name: String, height: CGFloat) async {
        demo.menuBar.preferences.internetDNSSelection = InternetDNSOption.cloudflare.id
        demo.menuBar.settingsTab = tab
        let settings = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 780, height: height),
                                styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
                                backing: .buffered, defer: false)
        settings.isReleasedWhenClosed = false
        settings.title = "Configurações"
        settings.titlebarAppearsTransparent = true
        settings.isOpaque = false
        settings.backgroundColor = .clear
        settings.contentViewController = NSHostingController(rootView: SettingsView(menuBar: demo.menuBar))
        settings.setContentSize(NSSize(width: 780, height: height))
        settings.center()
        await activate(settings)
        await pause(1.1)
        await capture([settings], key: settings, name)
        settings.orderOut(nil)
        await pause(0.5)
    }

    private func select(_ name: String) { demo.menuBar.pendingSelection = demo.connection(name).id }

    private func pause(_ seconds: Double) async { try? await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000)) }

    private func press(_ character: String, keyCode: UInt16, in window: NSWindow, command: Bool = true) {
        for type in [NSEvent.EventType.keyDown, .keyUp] {
            guard let event = NSEvent.keyEvent(with: type, location: .zero, modifierFlags: command ? .command : [],
                                               timestamp: ProcessInfo.processInfo.systemUptime, windowNumber: window.windowNumber,
                                               context: nil, characters: character, charactersIgnoringModifiers: character,
                                               isARepeat: false, keyCode: keyCode) else { continue }
            NSApp.sendEvent(event)
        }
    }

    /// The split view opens narrow after the resize; give the sidebar its ideal width.
    private func widenSidebar(_ window: NSWindow) {
        func splits(_ view: NSView) -> [NSSplitView] {
            if let split = view as? NSSplitView { return [split] }
            return view.subviews.flatMap(splits)
        }
        if let split = window.contentView.flatMap(splits)?.first { split.setPosition(300, ofDividerAt: 0) }
    }

    /// This app in front and `window` key: a background app draws inactive windows (gray
    /// traffic lights and switches), which must never become README images.
    private func activate(_ window: NSWindow?) async {
        if #available(macOS 14, *) { NSApp.activate() } else { NSApp.activate(ignoringOtherApps: true) }
        window?.makeKeyAndOrderFront(nil)
        await pause(0.4)
    }

    /// The app is active and `key` (or its sheet, or the window owning it) has the keyboard.
    /// One more try; otherwise the tour stops without a .complete mark, so showcase.sh copies
    /// nothing and the previous images stay.
    @discardableResult
    private func ensureActive(_ key: NSWindow?, _ name: String) async -> Bool {
        func active() -> Bool {
            guard NSApp.isActive else { return false }
            guard let key else { return true }
            return key.isKeyWindow || key.attachedSheet?.isKeyWindow == true || key.sheetParent?.isKeyWindow == true
        }
        if active() { return true }
        await activate(key)
        if active() { return true }
        print("Showcase: o app perdeu o foco em \(name); rode de novo sem usar o Mac")
        fflush(stdout)
        demo.model.manager.disconnectAll()
        demo.cleanUp()
        exit(3)
    }

    private func capture(_ windows: [NSWindow], key: NSWindow?, _ name: String) async {
        await ensureActive(key, name)
        Self.write(windows, shadow: true, to: directory.appendingPathComponent("\(name).png"))
        print("Showcase: \(name).png")
    }

    /// The menu and the progress panel are glass: alone in a capture there is nothing behind
    /// them and the glass comes out flat gray. A fixed backdrop window of this demo goes behind
    /// the panel (nothing of the desktop or of other apps) and the capture is cropped to the
    /// panel and its shadow, below the menu bar.
    private func captureGlass(_ panel: NSWindow, key: NSWindow?, dark: Bool, _ name: String) async {
        let backdrop = ShowcaseBackdrop.window(around: panel.frame, dark: dark)
        backdrop.order(.below, relativeTo: panel.windowNumber)
        await pause(0.8)
        await ensureActive(key, name)
        // Shadow room on the sides and below; only 4 pt above, so the menu bar stays out.
        let area = NSRect(x: panel.frame.minX - 28, y: panel.frame.minY - 44,
                          width: panel.frame.width + 56, height: panel.frame.height + 48)
        let trial = directory.appendingPathComponent("glass-trial", isDirectory: true)
        try? FileManager.default.createDirectory(at: trial, withIntermediateDirectories: true)
        Self.write([panel, backdrop], area: area, to: directory.appendingPathComponent("\(name).png"))
        Self.writeScreen(below: panel, area: area, to: trial.appendingPathComponent("\(name)-screen.png"))
        print("Showcase: \(name).png")
        backdrop.orderOut(nil)
    }

    /// Global display coordinates (origin top left) of a Cocoa screen rectangle.
    private static func displayRect(_ rect: NSRect) -> CGRect {
        let height = NSScreen.screens.first?.frame.height ?? 0
        return CGRect(x: rect.minX, y: height - rect.maxY, width: rect.width, height: rect.height)
    }

    /// The given windows composited by the window server, cropped to `area`.
    static func write(_ windows: [NSWindow], area: NSRect, to url: URL) {
        let ids = windows.map { UnsafeRawPointer(bitPattern: UInt($0.windowNumber)) }
        let array = ids.withUnsafeBufferPointer { CFArrayCreate(nil, UnsafeMutablePointer(mutating: $0.baseAddress), $0.count, nil) }
        guard let array, let image = CGImage.windowListImage(array, bounds: displayRect(area), options: [.nominalResolution]) else {
            print("Showcase: falha ao capturar \(url.lastPathComponent)"); return
        }
        try? NSBitmapImageRep(cgImage: image).representation(using: .png, properties: [:])?.write(to: url)
    }

    /// The screen in `area`: `window` and everything below it (here, only the backdrop).
    static func writeScreen(below window: NSWindow, area: NSRect, to url: URL) {
        guard let image = CGImage.screenImage(displayRect(area), below: CGWindowID(window.windowNumber)) else {
            print("Showcase: falha ao capturar \(url.lastPathComponent)"); return
        }
        try? NSBitmapImageRep(cgImage: image).representation(using: .png, properties: [:])?.write(to: url)
    }

    /// Composites only the given windows of this app (no other app, no desktop).
    static func write(_ windows: [NSWindow], shadow: Bool, to url: URL) {
        let ids = windows.map { UnsafeRawPointer(bitPattern: UInt($0.windowNumber)) }
        let array = ids.withUnsafeBufferPointer { CFArrayCreate(nil, UnsafeMutablePointer(mutating: $0.baseAddress), $0.count, nil) }
        var options: CGWindowImageOption = [.nominalResolution]
        if !shadow { options.insert(.boundsIgnoreFraming) }
        guard let array, let image = CGImage.windowListImage(array, options: options) else {
            print("Showcase: falha ao capturar \(url.lastPathComponent)"); return
        }
        let png = NSBitmapImageRep(cgImage: image).representation(using: .png, properties: [:])
        try? png?.write(to: url)
    }
}

extension CGImage {
    @available(macOS, deprecated: 14.0)
    static func windowListImage(_ windows: CFArray, bounds: CGRect = .null, options: CGWindowImageOption) -> CGImage? {
        CGImage(windowListFromArrayScreenBounds: bounds, windowArray: windows, imageOption: options)
    }

    @available(macOS, deprecated: 14.0)
    static func screenImage(_ bounds: CGRect, below window: CGWindowID) -> CGImage? {
        CGWindowListCreateImage(bounds, [.optionOnScreenBelowWindow, .optionIncludingWindow], window, [.nominalResolution])
    }
}

/// Fixed background for the glass captures: a soft gradient with a few blurred brand-colored
/// shapes, so the glass has something to show. Same in every run; light and dark versions.
enum ShowcaseBackdrop {
    @MainActor static func window(around frame: NSRect, dark: Bool) -> NSWindow {
        let window = NSWindow(contentRect: frame.insetBy(dx: -90, dy: -90), styleMask: [.borderless], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        window.level = .floating
        window.hasShadow = false
        window.isOpaque = true
        window.ignoresMouseEvents = true
        window.appearance = NSAppearance(named: dark ? .darkAqua : .aqua)
        window.contentView = NSHostingView(rootView: View(dark: dark))
        return window
    }

    struct View: SwiftUI.View {
        let dark: Bool
        var body: some SwiftUI.View {
            GeometryReader { proxy in
                let size = proxy.size
                ZStack {
                    LinearGradient(colors: dark ? [Color(red: 0.10, green: 0.11, blue: 0.17), Color(red: 0.16, green: 0.12, blue: 0.22)]
                                                : [Color(red: 0.86, green: 0.90, blue: 0.97), Color(red: 0.95, green: 0.89, blue: 0.93)],
                                   startPoint: .topLeading, endPoint: .bottomTrailing)
                    // TunnelMac's arc colors: blue, orange and red.
                    blob(Color(red: 0.18, green: 0.58, blue: 0.84), at: CGPoint(x: size.width * 0.25, y: size.height * 0.22), size.width * 0.55)
                    blob(Color(red: 0.93, green: 0.54, blue: 0.20), at: CGPoint(x: size.width * 0.80, y: size.height * 0.55), size.width * 0.50)
                    blob(Color(red: 0.82, green: 0.26, blue: 0.25), at: CGPoint(x: size.width * 0.30, y: size.height * 0.85), size.width * 0.45)
                }
            }
            .ignoresSafeArea()
        }

        private func blob(_ color: Color, at point: CGPoint, _ diameter: CGFloat) -> some SwiftUI.View {
            Circle().fill(color.opacity(dark ? 0.55 : 0.45))
                .frame(width: diameter, height: diameter)
                .blur(radius: diameter * 0.18)
                .position(point)
        }
    }
}
