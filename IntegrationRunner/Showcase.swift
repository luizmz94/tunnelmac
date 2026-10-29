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
        MenuBarExtra {
            MenuBarView(menuBar: demo.menuBar)
        } label: {
            MenuBarLabel(menuBar: demo.menuBar)
        }
        .menuBarExtraStyle(.window)
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
                            wireGuardRuntime: runtime("wireguard-go", "0.0.20250522", "/opt/homebrew/Cellar/wireguard-go/0.0.20250522/bin/wireguard-go", help: ""))
    }

    // MARK: Fictitious connections (reserved .example names and documentation addresses)

    private func seed() throws {
        func fortinet(_ name: String, _ server: String, port: Int = 443, user: String, saml: Bool = false) throws {
            let connection = Connection(name: name, server: server, port: port, username: saml ? "" : user,
                                        authentication: saml ? .saml : .password)
            try model.save(connection, password: saml ? "" : "demo-only")
            connections[name] = connection
        }
        try fortinet("Escritório São Paulo", "vpn.acme.example", user: "ana.souza")
        try fortinet("Cliente Horizonte", "sso.horizonte.example", port: 10443, user: "", saml: true)
        try fortinet("Homologação", "vpn-hml.acme.example", port: 8443, user: "ana.souza")

        let ovpn = OpenVPNTests.singleFile
            .replacingOccurrences(of: "auth RSA-SHA256", with: "auth SHA256")
            .replacingOccurrences(of: "cipher AES-256-CBC", with: "cipher AES-256-GCM")
            .replacingOccurrences(of: "remote sslvpn1.example.invalid 2400 tcp", with: "remote vpn.nuvem.example 1194 tcp")
            .replacingOccurrences(of: "remote sslvpn2.example.invalid 2400 tcp\n", with: "")
            .replacingOccurrences(of: "comp-lzo adaptive\n", with: "")
        let imported = try OpenVPNImporter.importText(ovpn, baseDirectory: root, suggestedName: "Nuvem Produção",
                                                      source: "~/Downloads/nuvem-producao.ovpn")
        let openVPN = Connection(name: "Nuvem Produção", kind: .openvpn, openVPN: imported.summary)
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
        try wireGuard("Casa", address: "10.8.0.3/32", endpoint: "198.51.100.24:51820", allowed: "0.0.0.0/0, ::/0", dns: "10.8.0.1")
        try wireGuard("Laboratório", address: "10.44.0.7/32", endpoint: "203.0.113.77:51820",
                      allowed: "10.44.0.0/16, 172.20.0.0/16", dns: "10.44.0.1")

        for connection in connections.values { observeDisconnect(connection) }
    }

    func started() {
        guard !didStart else { return }
        didStart = true
        // Two tunnels already up for a while, through the same connect path as the button.
        connect("Escritório São Paulo", fast: true, since: 4_325)
        connect("Casa", fast: true, since: 1_268)
        if let directory = ShowcaseApp.captureDirectory {
            Task { await ShowcaseTour(demo: self, directory: directory).run() }
        } else {
            showFailure("Homologação")
        }
    }

    func connection(_ name: String) -> Connection { connections[name]! }

    /// The interactive demo opens with one recent failure, as after an unreachable gateway.
    private func showFailure(_ name: String) {
        let session = model.manager.session(connection(name).id)
        session.begin()
        session.log("ERROR:  connect: Operation timed out")
        session.log("ERROR:  Could not connect to gateway (vpn-hml.acme.example:8443).")
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

    private static let openVPNOutput: [(TimeInterval, String, ConnectionState?)] = [
        (0.4, "OpenVPN 2.7.8 aarch64-apple-darwin [SSL (OpenSSL)] [LZO] [LZ4] [PKCS11] [MH/RECVDA] [AEAD]", nil),
        (0.4, "TCP/UDP: Preserving recently used remote address: [AF_INET]203.0.113.40:1194", nil),
        (0.4, "TCP connection established with [AF_INET]203.0.113.40:1194", nil),
        (0.5, "[vpn.nuvem.example] Peer Connection Initiated with [AF_INET]203.0.113.40:1194", nil),
        (0.4, "Data Channel: cipher 'AES-256-GCM', peer-id: 3", nil),
        (0.3, "net_iface_up: set utun7 up", nil),
        (0.2, "net_route_v4_add: 10.20.0.0/16 via 10.20.0.1 dev [NULL] table 0 metric -1", nil),
        (0.2, "dns-updown: DNS do túnel aplicado (nuvem.example → 10.20.0.2)", nil),
        (0.3, "Initialization Sequence Completed", nil)
    ]

    private static let wireGuardOutput: [(TimeInterval, String, ConnectionState?)] = [
        (0.3, "[+] Interface do WireGuard: utun6", nil),
        (0.3, "[#] ifconfig utun6 inet 10.8.0.3/32 10.8.0.3 alias", nil),
        (0.2, "[#] ifconfig utun6 mtu 1420", nil),
        (0.2, "[#] route -q -n add -inet 198.51.100.24 -gateway 192.168.1.1", nil),
        (0.2, "[#] route -q -n add -inet 0.0.0.0/1 -interface utun6", nil),
        (0.2, "[#] route -q -n add -inet 128.0.0.0/1 -interface utun6", nil),
        (0.2, "[+] DNS 10.8.0.1 no serviço Wi-Fi", nil),
        (0.2, "\(WireGuardMarkers.ready) em utun6.", nil),
        (0.6, "\(WireGuardMarkers.handshake) com 198.51.100.24:51820.", nil)
    ]

    private static func closing(_ connection: Connection) -> [String] {
        switch connection.kind {
        case .fortinet: return ["INFO:   Cancelling threads...", "INFO:   Setting ppp interface down.", "INFO:   Restoring routes...",
                                "INFO:   Removing VPN nameservers...", "INFO:   Logged out."]
        case .openvpn: return ["SIGTERM[hard,] received, process exiting"]
        case .wireguard: return ["[#] Rotas e DNS restaurados; interface removida."]
        }
    }

    private func cleanUp() {
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
        await pause(0.5)
        widenSidebar(window)
        await pause(0.5)

        for (appearance, suffix) in [(NSAppearance.Name.aqua, "light"), (.darkAqua, "dark")] {
            NSApp.appearance = NSAppearance(named: appearance)
            select("Escritório São Paulo")
            await pause(1.2)
            capture([window], "main-\(suffix)")
            select("Casa")
            await pause(1.0)
            capture([window], "wireguard-\(suffix)")

            let panel = menuBarPanel()
            await pause(1.0)
            fit(panel)
            await pause(0.5)
            capture([panel], "menubar-\(suffix)")
            panel.orderOut(nil)
            await pause(0.5)

            window.makeKeyAndOrderFront(nil)
            press("n", keyCode: 45, in: window)
            await pause(1.2)
            if let sheet = window.attachedSheet {
                capture([sheet, window], "new-connection-\(suffix)")
                press("\u{1b}", keyCode: 53, in: sheet, command: false)
                await pause(0.8)
                if let sheet = window.attachedSheet { window.endSheet(sheet) }
            }
            await pause(0.5)

            await captureOnboarding(over: window, suffix)
            await captureSettings(.backup, "backup-\(suffix)", height: 470)
            window.makeKeyAndOrderFront(nil)
            await pause(0.5)
        }
        NSApp.appearance = nil

        // Animated connect and disconnect of a Fortinet profile.
        NSApp.appearance = NSAppearance(named: .aqua)
        select("Homologação")
        await pause(1.2)
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
        demo.connect("Homologação")
        await pause(5.5)
        demo.model.manager.disconnect(demo.connection("Homologação").id)
        await pause(2.5)
        recorder.invalidate()

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
                                          .wireguard: .init(path: "/opt/homebrew/bin/wireguard-go", exists: false, version: nil, sourceChanged: false)],
                                  latest: [.openfortivpn: "1.24.1", .openvpn: "2.7.10", .wireguard: "0.0.20250522"])
        }
        fake()
        let guide = ServiceOnboardingSheet(model: model, versions: versions, forcedStep: .clients,
                                           chosen: [.openfortivpn, .openvpn, .wireguard]) { _ in }
        let controller = NSHostingController(rootView: guide)
        window.contentViewController?.presentAsSheet(controller)
        await pause(0.8)
        fake() // The guide reads this Mac's installations on appear.
        await pause(1.0)
        if let sheet = window.attachedSheet { capture([sheet, window], "onboarding-\(suffix)") }
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
        settings.makeKeyAndOrderFront(nil)
        await pause(1.5)
        capture([settings], name)
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

    /// The MenuBarExtra popover cannot be opened from code; the same view in a panel with
    /// the menu material stands in for it.
    private final class KeyPanel: NSPanel {
        override var canBecomeKey: Bool { true }
    }

    private func menuBarPanel() -> NSPanel {
        let host = NSHostingView(rootView: MenuBarView(menuBar: demo.menuBar))
        let size = NSSize(width: 360, height: 600)
        let panel = KeyPanel(contentRect: NSRect(origin: .zero, size: size), styleMask: [.borderless, .nonactivatingPanel],
                            backing: .buffered, defer: false)
        panel.isReleasedWhenClosed = false
        panel.backgroundColor = .clear
        panel.isOpaque = false
        panel.hasShadow = true
        let material = NSVisualEffectView(frame: NSRect(origin: .zero, size: size))
        material.material = .menu
        material.state = .active
        material.maskImage = NSImage(size: NSSize(width: 29, height: 29), flipped: false) { rect in
            NSBezierPath(roundedRect: rect, xRadius: 14, yRadius: 14).fill()
            return true
        }
        material.maskImage?.capInsets = NSEdgeInsets(top: 14, left: 14, bottom: 14, right: 14)
        host.frame = material.bounds
        host.autoresizingMask = [.width, .height]
        material.addSubview(host)
        panel.contentView = material
        if let screen = NSScreen.main?.visibleFrame {
            panel.setFrameTopLeftPoint(NSPoint(x: screen.maxX - size.width - 40, y: screen.maxY - 8))
        }
        panel.makeKeyAndOrderFront(nil)
        return panel
    }

    /// Shrinks the panel to the view's measured height, keeping its top edge.
    private func fit(_ panel: NSPanel) {
        guard let host = panel.contentView?.subviews.first else { return }
        let height = host.fittingSize.height
        var frame = panel.frame
        frame.origin.y += frame.height - height
        frame.size.height = height
        panel.setFrame(frame, display: true)
    }

    private func capture(_ windows: [NSWindow], _ name: String) {
        Self.write(windows, shadow: true, to: directory.appendingPathComponent("\(name).png"))
        print("Showcase: \(name).png")
    }

    /// Composites only the given windows of this app (no other app, no desktop).
    static func write(_ windows: [NSWindow], shadow: Bool, to url: URL) {
        let ids = windows.map { UnsafeRawPointer(bitPattern: UInt($0.windowNumber)) }
        let array = ids.withUnsafeBufferPointer { CFArrayCreate(nil, UnsafeMutablePointer(mutating: $0.baseAddress), $0.count, nil) }
        var options: CGWindowImageOption = [.bestResolution]
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
    static func windowListImage(_ windows: CFArray, options: CGWindowImageOption) -> CGImage? {
        CGImage(windowListFromArrayScreenBounds: .null, windowArray: windows, imageOption: options)
    }
}
