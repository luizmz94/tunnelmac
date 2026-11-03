import AppKit
import Darwin
import ServiceManagement
import ProcessBridge
import VPNHelperShared

/// Fixed operations, run as the logged-in user. No shell, root execution, PID
/// arguments, custom paths or helper commands. XPC uses the production trust policy.
@MainActor
enum Maintenance {
    static let argument = "--prepare-for-maintenance"
    /// Used by the cask before it moves a legacy OpenFortiDesk.app or VPNGUI.app away. Read-only.
    static let legacyMigrationArgument = "--prepare-for-legacy-migration"
    /// Used by the cask right after Homebrew's own `quit`: waits until the app and its
    /// VPN cleanup are gone, so brew never replaces a bundle that is still running.
    static let waitForQuitArgument = "--wait-for-quit"
    static var arguments: [String] { [argument, legacyMigrationArgument, waitForQuitArgument] }

    static let quitAndRetry = "Quit TunnelMac with Sair (this disconnects its VPNs), then run brew again."
    static let removeLegacyService = """
        The service of the old app (OpenFortiDesk.app or VPNGUI.app) is still registered. Open it, \
        use Remover serviço in Configurações… > Serviço privilegiado (Gerenciar… in VPNGUI), quit it \
        with Sair, then run brew again.
        """

    static func run() -> Int32 {
        guard CommandLine.arguments.count == 2, getuid() != 0 else { return usage() }
        switch CommandLine.arguments[1] {
        case argument: return restrictedEnvironment() ? restrictedCheck() : fullMaintenance()
        case legacyMigrationArgument: return legacyMigrationCheck()
        case waitForQuitArgument: return waitForQuit()
        default: return usage()
        }
    }

    // MARK: Homebrew sandbox

    /// Homebrew 7 runs cask `run` steps under sandbox-exec, which denies the
    /// mach-lookup that SMAppService and XPC need: the registration then reads as
    /// `.notFound` although this bundle ships the daemon plist.
    static func restrictedEnvironment() -> Bool {
        let plist = Bundle.main.bundleURL.appendingPathComponent("Contents/Library/LaunchDaemons/" + HelperConstants.plistName)
        return vpn_is_sandboxed() == 1 && FileManager.default.fileExists(atPath: plist.path)
            && DaemonRegistrar().status == .notFound
    }

    /// Nothing is quit, unregistered or contacted. The registration is kept: on
    /// upgrade the new bundle lands at the same path with the same identifier and
    /// Team, so it stays valid. Before `brew uninstall`, Remover serviço removes it.
    static func restrictedCheck() -> Int32 {
        let running = runningProductProcesses()
        guard running.isEmpty else { return busy(running) }
        return 0
    }

    /// Homebrew asked the app to quit just before. With active VPNs the app shows
    /// "Desconectar e sair?" and cleans up (up to 30 s), which outlasts brew's 10 s
    /// wait; this waits for the user and the cleanup. Nothing is quit or signalled here.
    static func waitForQuit() -> Int32 {
        guard !runningProductProcesses().isEmpty else { return 0 }
        print("Waiting for TunnelMac to quit (confirm Desconectar e sair in the app)...")
        fflush(stdout) // brew reads a pipe: show the line before the wait, not after.
        _ = wait(120) { runningProductProcesses().isEmpty }
        let running = runningProductProcesses()
        return running.isEmpty ? 0 : busy(running)
    }

    /// The old bundle is moved away, so its registration would point at nothing.
    /// `launchctl print` works inside the sandbox and outside it.
    static func legacyMigrationCheck() -> Int32 {
        let running = runningProductProcesses()
        guard running.isEmpty else { return busy(running) }
        return serviceIsAbsent() ? 0 : fail(removeLegacyService)
    }

    /// Product executables, found through libproc (no mach-lookup, no signals):
    /// the app and its supervisor in TunnelMac.app or a legacy bundle name, and the
    /// supervisor copy and managed openfortivpn in the helper's state directory.
    static func runningProductProcesses(excluding own: pid_t = getpid()) -> [(pid: pid_t, path: String)] {
        runningProcesses(excluding: own, matching: isProductExecutable)
    }

    /// Root-side processes of the product: the helper, any supervisor and the managed
    /// clients (openfortivpn/openvpn/wireguard-go copies in the helper's state directory).
    static func runningPrivilegedProcesses() -> [(pid: pid_t, path: String)] {
        runningProcesses(excluding: getpid()) { path in
            path.hasPrefix(HelperConstants.stateDirectory + "/")
                || ["VPNHelper", "VPNSupervisor"].contains { path.hasSuffix(".app/Contents/MacOS/" + $0) }
        }
    }

    static func runningProcesses(excluding own: pid_t, matching: (String) -> Bool) -> [(pid: pid_t, path: String)] {
        let capacity = proc_listallpids(nil, 0)
        guard capacity > 0 else { return [] }
        var pids = [pid_t](repeating: 0, count: Int(capacity) + 64)
        let count = pids.withUnsafeMutableBytes { proc_listallpids($0.baseAddress, Int32($0.count)) }
        var found: [(pid: pid_t, path: String)] = []
        var buffer = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        for pid in pids.prefix(max(0, Int(count))) where pid > 0 && pid != own {
            // Unreadable entries are exiting processes or kernel tasks.
            guard proc_pidpath(pid, &buffer, UInt32(buffer.count)) > 0 else { continue }
            let path = String(cString: buffer)
            if matching(path) { found.append((pid, path)) }
        }
        return found
    }

    /// Earlier names of the same product (same identifiers, profiles and Keychain).
    static let legacyBundles = ["OpenFortiDesk.app", "VPNGUI.app"]

    static func isProductExecutable(_ path: String) -> Bool {
        if path.hasPrefix(HelperConstants.stateDirectory + "/") { return true }
        return (["TunnelMac.app"] + legacyBundles).contains { bundle in
            ["VPNGUI", "VPNSupervisor"].contains { path.hasSuffix("/" + bundle + "/Contents/MacOS/" + $0) }
        }
    }

    private static func busy(_ running: [(pid: pid_t, path: String)]) -> Int32 {
        let list = running.map { "  \($0.pid) \($0.path)" }.joined(separator: "\n")
        return fail("TunnelMac is still running:\n\(list)\n\(quitAndRetry) The bundle was preserved.")
    }

    // MARK: Full maintenance (outside the sandbox)

    static func fullMaintenance() -> Int32 {
        guard case .trusted(let team) = CodeTrust.localPolicy() else { return usage() }
        // Cocoa's normal quit request reaches applicationShouldTerminate: cancellation
        // and pending cleanup are respected. Never forceTerminate or signal a PID.
        let running = NSRunningApplication.runningApplications(withBundleIdentifier: HelperConstants.appIdentifier)
            .filter { $0.processIdentifier != getpid() }
        for app in running {
            guard app.terminate() else { return fail("Quit was refused. Use Sair in the installed app, then retry.") }
        }
        guard wait(125, { running.allSatisfy(\.isTerminated) }) else {
            return fail("Quit was cancelled or cleanup timed out. The bundle was preserved.")
        }
        let registrar = DaemonRegistrar()
        if registrar.status == .notRegistered {
            return serviceIsAbsent() ? 0 : fail("A service from another bundle is still registered. Remove it in the old app first.")
        }
        // Pending approval cannot have started a session. Unregister still must succeed.
        let client = HelperClient.production(team: team)
        if registrar.status == .enabled {
            var result: Bool?
            client.request(.prepareForMaintenance, timeout: 20) { reply in
                if case .success(.done) = reply { result = true } else { result = false }
            }
            guard wait(25, { result != nil }), result == true else {
                client.invalidate()
                return fail("Helper did not prove global idle. For a legacy installation, use Remover serviço in the old app first.")
            }
        } else if registrar.status != .requiresApproval || !serviceIsAbsent() {
            return fail("Service registration is unavailable or belongs to another bundle; bundle preserved.")
        }
        var finished = false
        var error: Error?
        registrar.unregister { error = $0; finished = true }
        guard wait(30, { finished }), error == nil, registrar.status == .notRegistered else {
            client.request(.cancelMaintenance) { _ in }
            _ = wait(1, { false })
            client.invalidate()
            return fail("Unregister failed or timed out; bundle preserved. Check Gerenciar serviço.")
        }
        client.invalidate()
        guard wait(10, { serviceIsAbsent() }) else {
            return fail("Launch service still exists after unregister; bundle preserved.")
        }
        return 0
    }

    /// Read-only, fixed system lookup. A registration attached to the old bundle
    /// must not be mistaken for a fresh install just because this bundle says absent.
    static func serviceIsAbsent() -> Bool {
        let process = Process()
        let errors = Pipe()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = ["print", "system/" + HelperConstants.helperIdentifier]
        process.environment = ["PATH": "/usr/bin:/bin", "LC_ALL": "C"]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = errors
        do { try process.run() } catch { return false }
        let output = errors.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return absentServiceReply(status: process.terminationStatus, stderr: String(decoding: output, as: UTF8.self))
    }
    static func absentServiceReply(status: Int32, stderr: String) -> Bool {
        status == 113 && stderr.contains("Could not find service \"" + HelperConstants.helperIdentifier + "\" in domain for system")
    }
    static func wait(_ seconds: TimeInterval, _ condition: () -> Bool) -> Bool {
        let deadline = Date().addingTimeInterval(seconds)
        while !condition(), Date() < deadline {
            RunLoop.current.run(until: Date().addingTimeInterval(0.05))
        }
        return condition()
    }
    private static func usage() -> Int32 {
        fail("Maintenance requires a signed app, a normal user and no extra arguments.")
    }
    private static func fail(_ message: String) -> Int32 { fputs(message + "\n", stderr); return 1 }
}
