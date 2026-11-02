import XCTest
import Darwin
import ProcessBridge
@testable import VPNHelperCore

extension ReviewTests {
    func testSupervisorBoundsClientIgnoringSIGTERM() throws {
        let root = try temporary()
        let script = root.appendingPathComponent("stubborn-client")
        try Data("#!/bin/sh\ntrap '' TERM\necho READY\nwhile :; do /bin/sleep 0.1; done\n".utf8).write(to: script)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: script.path)
        let supervisor = URL(fileURLWithPath: FileManager.default.currentDirectoryPath).appendingPathComponent(".build/debug/VPNSupervisor").path
        XCTAssertTrue(FileManager.default.isExecutableFile(atPath: supervisor))
        let config = try ProtectedDescriptor.anonymousFile(Data("fixture\n".utf8), directory: root.path)
        defer { close(config) }
        let args = [supervisor, script.path]
        var argv = args.map { strdup($0) } + [nil]
        var env = [strdup("PATH=/usr/bin:/bin"), nil]
        defer { argv.forEach { free($0) }; env.forEach { free($0) } }
        var pid: pid_t = 0
        let control = argv.withUnsafeMutableBufferPointer { a in env.withUnsafeMutableBufferPointer { e in
            vpn_spawn_supervisor(supervisor, a.baseAddress, e.baseAddress, config, -1, &pid)
        } }
        XCTAssertGreaterThanOrEqual(control, 0)
        guard control >= 0 else { return }
        defer { close(control) }
        var output = "", bytes = [UInt8](repeating: 0, count: 4096)
        let startup = Date().addingTimeInterval(3)
        while !output.contains("READY"), Date() < startup {
            var descriptor = pollfd(fd: control, events: Int16(POLLIN), revents: 0)
            if poll(&descriptor, 1, 100) > 0 {
                let count = read(control, &bytes, bytes.count)
                if count <= 0 { break }
                output += String(decoding: bytes.prefix(count), as: UTF8.self)
            }
        }
        XCTAssertTrue(output.contains("READY"), output)
        let start = Date()
        _ = Array("STOP\n".utf8).withUnsafeBytes { write(control, $0.baseAddress, $0.count) }
        var status: Int32 = 0, result: pid_t = 0
        repeat {
            result = waitpid(pid, &status, WNOHANG)
            if result == 0 { usleep(50_000) }
        } while result == 0 && Date().timeIntervalSince(start) < 14
        XCTAssertEqual(result, pid, "Supervisor did not complete bounded shutdown")
        XCTAssertLessThan(Date().timeIntervalSince(start), 13)
        XCTAssertEqual((status >> 8) & 0xff, 137)
    }
}

extension ReviewTests {
    /// --openconnect: the client gets the protected config, --passwd-on-stdin and the server,
    /// and reads the credential (plus one newline) on stdin; nothing else reaches argv.
    func testSupervisorOpenConnectModePassesCredentialOnStdinOnly() throws {
        let root = try temporary()
        let script = root.appendingPathComponent("openconnect")
        try Data("#!/bin/sh\necho \"ARGS:$*\"\nIFS= read -r line\necho \"STDIN:$line\"\nread -r more && echo EXTRA || echo EOF\n".utf8).write(to: script)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: script.path)
        let supervisor = URL(fileURLWithPath: FileManager.default.currentDirectoryPath).appendingPathComponent(".build/debug/VPNSupervisor").path
        func run(_ arguments: [String], secret: String) throws -> String {
            let config = try ProtectedDescriptor.anonymousFile(Data("protocol=gp\n".utf8), directory: root.path)
            defer { close(config) }
            let channel = try ProtectedDescriptor.pipe(Data(secret.utf8))
            defer { close(channel) }
            var argv = ([supervisor] + arguments).map { strdup($0) } + [nil]
            var env = [strdup("PATH=/usr/bin:/bin"), nil]
            defer { argv.forEach { free($0) }; env.forEach { free($0) } }
            var pid: pid_t = 0
            let control = argv.withUnsafeMutableBufferPointer { a in env.withUnsafeMutableBufferPointer { e in
                vpn_spawn_supervisor(supervisor, a.baseAddress, e.baseAddress, config, channel, &pid)
            } }
            guard control >= 0 else { return "" }
            defer { close(control) }
            var output = "", bytes = [UInt8](repeating: 0, count: 4096)
            let deadline = Date().addingTimeInterval(5)
            while !output.contains("__VPNGUI_EXIT__"), Date() < deadline {
                var descriptor = pollfd(fd: control, events: Int16(POLLIN), revents: 0)
                if poll(&descriptor, 1, 100) > 0 {
                    let count = read(control, &bytes, bytes.count)
                    if count <= 0 { break }
                    output += String(decoding: bytes.prefix(count), as: UTF8.self)
                }
            }
            var status: Int32 = 0
            waitpid(pid, &status, 0)
            return output
        }
        let output = try run(["--openconnect", script.path, "vpn.example.invalid"], secret: "COOKIE+/=")
        XCTAssertTrue(output.contains("ARGS:--config=/dev/fd/3 --passwd-on-stdin vpn.example.invalid"), output)
        XCTAssertTrue(output.contains("STDIN:COOKIE+/="), output)
        XCTAssertTrue(output.contains("EOF"), output)
        XCTAssertTrue(try run(["--openconnect", script.path, "--script=/tmp/x"], secret: "x").contains("argumentos inválidos"))
        XCTAssertTrue(try run(["--openconnect", script.path, "vpn.example.invalid"], secret: "a\nb").contains("credencial em formato inesperado"))
    }
}
