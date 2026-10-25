import SwiftUI
import AppKit
@testable import VPNApp

@main
struct IntegrationApp: App {
    init() {
        // The Homebrew sandbox check runs this executable in the app's maintenance mode.
        if CommandLine.arguments.contains(where: [Maintenance.argument, Maintenance.legacyMigrationArgument].contains) {
            exit(Maintenance.run())
        }
        signal(SIGPIPE, SIG_IGN)
        if CommandLine.arguments.contains("--self-test") { _ = NSApplication.shared; exit(SelfTests.run()) }
        if CommandLine.arguments.contains("--release-checks") { exit(ReleaseTests.run()) }
    }
    var body: some Scene { WindowGroup("TunnelMac Local Checks") { LocalTestsView() } }
}

struct LocalTestsView: View {
    @State private var result: Int32?
    @State private var started = false
    var body: some View {
        VStack(spacing: 16) {
            Text(result == nil ? "Executando verificações locais…" : result == 0 ? "Verificações locais concluídas: 0 falhas" : "As verificações locais encontraram falhas")
                .font(.headline)
            Text("Resultado em TestResults.txt, ao lado deste executor. Nenhuma VPN é acessada.")
            Button("Fechar") { NSApp.terminate(nil) }.disabled(result == nil)
        }.padding(30).frame(width: 550)
            .onAppear {
                guard !started else { return }
                started = true
                // A run-loop block, not a main-queue block: the checks spin the run loop to
                // receive XPC replies, and GCD does not drain the main queue re-entrantly.
                RunLoop.main.perform(inModes: [.default]) {
                    let report = Bundle.main.bundleURL.deletingLastPathComponent().appendingPathComponent("TestResults.txt")
                    freopen(report.path, "w", stdout)
                    freopen(report.path + ".stderr", "w", stderr)
                    MainActor.assumeIsolated {
                        result = SelfTests.run()
                        fflush(stdout)
                        if CommandLine.arguments.contains("--headless") { NSApp.terminate(nil) }
                    }
                }
            }
    }
}
