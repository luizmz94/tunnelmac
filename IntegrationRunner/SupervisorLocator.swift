import Foundation

/// Supervisor next to the running executable. Used by the local checks only; the helper
/// executes its own protected, signature-checked copy.
enum SupervisorLocator {
    static var path: String {
        let executable = Bundle.main.executableURL ?? URL(fileURLWithPath: CommandLine.arguments[0])
        return executable.deletingLastPathComponent().appendingPathComponent("VPNSupervisor").path
    }
}

