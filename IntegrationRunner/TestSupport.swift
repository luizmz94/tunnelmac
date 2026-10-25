@testable import VPNApp
import Foundation
import Darwin
import CryptoKit
import ProcessBridge
import VPNHelperCore
import VPNHelperShared

/// Shared fixtures of the local checks. Unprivileged, loopback/file only, harmless children.
enum TestSupport {
    struct Failure: LocalizedError {
        let errorDescription: String?
        init(_ message: String) { errorDescription = message }
    }
    static func require(_ condition: @autoclosure () throws -> Bool, _ message: @autoclosure () -> String) throws {
        if try !condition() { throw Failure(message()) }
    }

    struct Run { let pid: pid_t; let fd: Int32 }

    /// Private 0700 directory for anonymous config files (the helper's work dir in production).
    static func workDirectory() throws -> String {
        let path = FileManager.default.temporaryDirectory.appendingPathComponent("VPNGUI-work-\(UUID().uuidString)").path
        guard mkdir(path, 0o700) == 0, let real = realpath(path, nil) else { throw Failure("Diretório de trabalho indisponível") }
        defer { free(real) }
        return String(cString: real)
    }

    /// Starts the real supervisor exactly like the helper does: fd 3 = anonymous config,
    /// fd 4 = cookie pipe (optional), fixed environment, own process group.
    static func spawn(configText: String = "host = vpn.invalid\nport = 443\n", configFD suppliedFD: Int32? = nil,
                      cookie: Data? = nil, cookieFD suppliedCookie: Int32? = nil, arguments: [String],
                      environment: [String] = ["PATH=/usr/bin:/bin:/usr/sbin:/sbin"]) throws -> Run {
        let work = try workDirectory()
        defer { rmdir(work) }
        let configFD = try suppliedFD ?? ProtectedDescriptor.anonymousFile(Data(configText.utf8), directory: work)
        var cookieFD: Int32 = -1
        if let suppliedCookie { cookieFD = suppliedCookie } else if let cookie { cookieFD = try ProtectedDescriptor.pipe(cookie) }
        defer { close(configFD); if cookieFD >= 0 { close(cookieFD) } }
        let argv = [SupervisorLocator.path] + arguments
        var a: [UnsafeMutablePointer<CChar>?] = argv.map { strdup($0) } + [nil]
        var e: [UnsafeMutablePointer<CChar>?] = environment.map { strdup($0) } + [nil]
        defer { a.forEach { free($0) }; e.forEach { free($0) } }
        var pid: pid_t = 0
        let fd = a.withUnsafeMutableBufferPointer { ap in
            e.withUnsafeMutableBufferPointer { ep in
                vpn_spawn_supervisor(SupervisorLocator.path, ap.baseAddress, ep.baseAddress, configFD, cookieFD, &pid)
            }
        }
        guard fd >= 0 else { throw Failure("Supervisor local não iniciou (\(String(cString: strerror(errno))))") }
        return Run(pid: pid, fd: fd)
    }

    static func transcript(_ run: Run, until marker: String = "__VPNGUI_EXIT__=", timeout: Int32 = 5000) throws -> String {
        var output = ""
        var buffer = [UInt8](repeating: 0, count: 4096)
        var descriptor = pollfd(fd: run.fd, events: Int16(POLLIN | POLLHUP), revents: 0)
        while !output.contains(marker) {
            guard poll(&descriptor, 1, timeout) > 0 else { throw Failure("Timeout aguardando \(marker): \(output.suffix(300))") }
            let count = Darwin.read(run.fd, &buffer, buffer.count)
            guard count > 0 else { break }
            output += String(decoding: buffer.prefix(count), as: UTF8.self)
        }
        return output
    }

    static func stop(_ run: Run) throws {
        let command = Array("STOP\n".utf8)
        let sent = command.withUnsafeBytes { Darwin.write(run.fd, $0.baseAddress, $0.count) }
        try require(sent == command.count, "STOP não enviado")
    }

    @discardableResult
    static func finish(_ run: Run) -> Int32 {
        close(run.fd)
        var status: Int32 = 0
        waitpid(run.pid, &status, 0)
        return status
    }

    /// Runs the main run loop (XPC replies and main-queue work) until `condition` or timeout.
    @MainActor
    static func spin(_ timeout: TimeInterval = 10, until condition: () -> Bool) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if condition() { return true }
            RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(0.02))
        }
        return condition()
    }

    static func md5(_ text: String) -> String {
        Insecure.MD5.hash(data: Data(text.utf8)).map { String(format: "%02x", $0) }.joined()
    }
}
