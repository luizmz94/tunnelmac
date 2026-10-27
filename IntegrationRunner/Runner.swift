import SwiftUI
import AppKit
@testable import VPNApp

@main
enum Launcher {
    /// `--showcase` opens the README demo (fictitious connections) instead of the checks.
    static func main() {
        if ShowcaseApp.requested { ShowcaseApp.main() } else { IntegrationApp.main() }
    }
}

struct IntegrationApp: App {
    init() {
        // The Homebrew sandbox check runs this executable in the app's maintenance mode.
        if CommandLine.arguments.contains(where: [Maintenance.argument, Maintenance.legacyMigrationArgument].contains) {
            exit(Maintenance.run())
        }
        signal(SIGPIPE, SIG_IGN)
        if CommandLine.arguments.contains("--self-test") { _ = NSApplication.shared; exit(SelfTests.run()) }
        if CommandLine.arguments.contains("--release-checks") { exit(ReleaseTests.run()) }
        // The checks order hundreds of windows in and out while the main thread is busy:
        // each open/close animation then holds a GCD worker thread, and once the pool
        // (64) is exhausted URLSession and XPC replies never arrive.
        UserDefaults.standard.register(defaults: ["NSAutomaticWindowAnimationsEnabled": false])
        LocalChecks.shared.start()
    }
    var body: some Scene { WindowGroup("TunnelMac Local Checks") { LocalTestsView(checks: .shared) } }
}

/// Starts when the app finishes launching, not with its window: a window never appears
/// while the display is off or the lid is closed (CI), and the checks then waited forever.
@MainActor
final class LocalChecks: ObservableObject {
    static let shared = LocalChecks()
    @Published private(set) var result: Int32?
    private var started = false

    func start() {
        NotificationCenter.default.addObserver(forName: NSApplication.didFinishLaunchingNotification, object: nil, queue: nil) { _ in
            MainActor.assumeIsolated { LocalChecks.shared.run() }
        }
    }

    private func run() {
        guard !started else { return }
        started = true
        // A run-loop block, not a main-queue block: the checks spin the run loop to
        // receive XPC replies, and GCD does not drain the main queue re-entrantly.
        RunLoop.main.perform(inModes: [.default]) {
            let report = Bundle.main.bundleURL.deletingLastPathComponent().appendingPathComponent("TestResults.txt")
            freopen(report.path, "w", stdout)
            freopen(report.path + ".stderr", "w", stderr)
            MainActor.assumeIsolated {
                let result = SelfTests.run()
                self.result = result
                fflush(stdout)
                fflush(stderr)
                // exit, not NSApp.terminate: terminate waits for AppKit's window state
                // restoration and hung forever on CI after the checks had finished.
                if CommandLine.arguments.contains("--headless") { exit(result) }
            }
        }
    }
}

struct LocalTestsView: View {
    @ObservedObject var checks: LocalChecks
    var body: some View {
        VStack(spacing: 16) {
            Text(checks.result == nil ? "Executando verificações locais…" : checks.result == 0 ? "Verificações locais concluídas: 0 falhas" : "As verificações locais encontraram falhas")
                .font(.headline)
            Text("Resultado em TestResults.txt, ao lado deste executor. Nenhuma VPN é acessada.")
            Button("Fechar") { NSApp.terminate(nil) }.disabled(checks.result == nil)
        }.padding(30).frame(width: 550)
    }
}
