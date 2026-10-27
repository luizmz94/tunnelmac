import Foundation
import Darwin
import CryptoKit
import VPNHelperShared

/// Descriptor-based reads stay bounded even when the selected file grows concurrently.
enum BoundedFile {
    static func read(_ url: URL, limit: Int) throws -> Data {
        let fd = open(url.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
        guard fd >= 0 else { throw AppFailure(String(localized: "Não foi possível abrir \(url.lastPathComponent).")) }
        defer { close(fd) }
        return try read(fd: fd, limit: limit)
    }
    static func read(fd: Int32, limit: Int) throws -> Data {
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
              info.st_size >= 0, info.st_size <= limit else { throw AppFailure(String(localized: "Arquivo inválido ou acima do limite de \(limit) bytes.")) }
        var data = Data()
        var bytes = [UInt8](repeating: 0, count: 16384)
        while true {
            let count = Darwin.read(fd, &bytes, min(bytes.count, limit - data.count + 1))
            if count < 0 && errno == EINTR { continue }
            guard count >= 0 else { throw AppFailure(String(localized: "Falha ao ler arquivo.")) }
            if count == 0 { return data }
            guard count <= limit - data.count else { throw AppFailure(String(localized: "Arquivo acima do limite de \(limit) bytes.")) }
            data.append(contentsOf: bytes.prefix(count))
        }
    }
    /// Final permissions and durable contents are established before replacement.
    static func replace(_ url: URL, data: Data) throws {
        let temporary = url.deletingLastPathComponent().appendingPathComponent(".txn-\(UUID())")
        let fd = open(temporary.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw AppFailure(String(localized: "Falha ao preparar gravação privada.")) }
        defer { close(fd); unlink(temporary.path) }
        try data.withUnsafeBytes { buffer in
            var offset = 0
            while offset < buffer.count {
                let count = Darwin.write(fd, buffer.baseAddress! + offset, buffer.count - offset)
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw AppFailure(String(localized: "Gravação incompleta.")) }
                offset += count
            }
        }
        guard fsync(fd) == 0, rename(temporary.path, url.path) == 0 else { throw AppFailure(String(localized: "Falha ao persistir arquivo.")) }
    }
}

enum RuntimeSourceCheck {
    static func changed(_ runtime: RuntimeSummary) -> Bool {
        let sources = runtime.sources ?? []
        let entries = sources.isEmpty ? [(runtime.sourcePath, runtime.sourceSHA256)] : sources.map { ($0.sourcePath, $0.sha256) }
        return entries.contains { path, digest in
            guard let handle = FileHandle(forReadingAtPath: path) else { return true }
            defer { try? handle.close() }
            var hash = SHA256()
            var total = 0
            do {
                while let data = try handle.read(upToCount: 256 * 1024), !data.isEmpty {
                    total += data.count
                    guard total <= 256 * 1024 * 1024 else { return true }
                    hash.update(data: data)
                }
            } catch { return true }
            return hash.finalize().map { String(format: "%02x", $0) }.joined() != digest
        }
    }
}
