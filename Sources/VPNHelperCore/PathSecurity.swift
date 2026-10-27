import Foundation
import CryptoKit
import Darwin
import VPNHelperShared

func failure(_ code: HelperFailure.Code, _ message: String) -> HelperFailure { HelperFailure(code, message) }

enum Digest {
    static func sha256(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
}

/// Ownership rules for everything the helper executes or trusts as root.
public struct TrustedOwnership: Sendable {
    /// Owners allowed for protected files and directories (production: root only).
    public var owners: Set<uid_t>
    /// Directories above this anchor are checked with the stricter system rule
    /// (root-owned, not group/other writable). Production: "/".
    public var anchor: String
    public init(owners: Set<uid_t>, anchor: String) { self.owners = owners; self.anchor = anchor }
    public static let production = TrustedOwnership(owners: [0], anchor: "/")

    /// Every component from "/" to `path` must be a real directory/file (no symlink),
    /// owned by a trusted owner, and not writable by group or others. This is what
    /// makes "verify, then execute" race-free: nobody but a trusted owner can swap it.
    public func verifyChain(_ path: String) throws {
        guard path.hasPrefix("/"), !path.contains("/../"), !path.hasSuffix("/.."), !path.contains("//") else {
            throw failure(.runtimeRejected, ServiceLanguage.text("Caminho protegido inválido: \(path)"))
        }
        var current = ""
        let parts = path.split(separator: "/").map(String.init)
        var components = ["/"]
        for part in parts { current += "/" + part; components.append(current) }
        for component in components {
            // Production uses anchor "/" (everything checked). Local checks anchor a
            // temporary directory; its user-owned ancestors are outside the test's scope.
            let inside = anchor == "/" || component == anchor || component.hasPrefix(anchor + "/")
            if !inside { continue }
            var info = stat()
            guard lstat(component, &info) == 0 else { throw failure(.runtimeUnavailable, ServiceLanguage.text("Item protegido ausente: \(component)")) }
            guard (info.st_mode & S_IFMT) != S_IFLNK else { throw failure(.runtimeRejected, ServiceLanguage.text("Link simbólico em caminho protegido: \(component)")) }
            guard owners.contains(info.st_uid) else {
                throw failure(.runtimeRejected, ServiceLanguage.text("Dono inesperado (uid \(info.st_uid)) em caminho protegido: \(component)"))
            }
            guard info.st_mode & (S_IWGRP | S_IWOTH) == 0 else {
                throw failure(.runtimeRejected, ServiceLanguage.text("Permissão de escrita para grupo/outros em caminho protegido: \(component)"))
            }
        }
    }
}

enum SecureFile {
    /// Reads a regular file without following a final symlink, from one descriptor:
    /// the bytes returned and the metadata are from the same inode.
    static func read(_ path: String, limit: Int) throws -> (data: Data, info: stat) {
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw failure(.runtimeRejected, ServiceLanguage.text("Não foi possível abrir \(path) (\(String(cString: strerror(errno))))")) }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG else {
            throw failure(.runtimeRejected, ServiceLanguage.text("Não é um arquivo regular: \(path)"))
        }
        guard info.st_size >= 0, Int(info.st_size) <= limit else { throw failure(.runtimeRejected, ServiceLanguage.text("Arquivo acima do limite: \(path)")) }
        var data = Data(count: Int(info.st_size))
        var offset = 0
        let total = data.count
        try data.withUnsafeMutableBytes { buffer in
            while offset < total {
                let count = Darwin.read(fd, buffer.baseAddress! + offset, total - offset)
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw failure(.runtimeRejected, ServiceLanguage.text("Leitura incompleta: \(path)")) }
                offset += count
            }
        }
        return (data, info)
    }

    /// Creates a new file (never replacing anything) and writes all bytes.
    static func create(_ path: String, data: Data, mode: mode_t) throws {
        let fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode)
        guard fd >= 0 else { throw failure(.internalError, ServiceLanguage.text("Não foi possível criar \(path) (\(String(cString: strerror(errno))))")) }
        defer { close(fd) }
        try writeAll(fd, data, path: path)
        guard fsync(fd) == 0 else { throw failure(.internalError, ServiceLanguage.text("Não foi possível persistir \(path)")) }
        guard fchmod(fd, mode) == 0 else { throw failure(.internalError, ServiceLanguage.text("Não foi possível ajustar permissões de \(path)")) }
    }

    static func writeAll(_ fd: Int32, _ data: Data, path: String) throws {
        try data.withUnsafeBytes { buffer in
            var offset = 0
            while offset < buffer.count {
                let count = Darwin.write(fd, buffer.baseAddress! + offset, buffer.count - offset)
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw failure(.internalError, ServiceLanguage.text("Escrita incompleta: \(path)")) }
                offset += count
            }
        }
    }

    /// Atomic replacement inside a directory only the helper can write.
    static func replace(_ path: String, data: Data, mode: mode_t) throws {
        let temporary = path + ".new-\(UUID().uuidString)"
        try create(temporary, data: data, mode: mode)
        guard rename(temporary, path) == 0 else {
            unlink(temporary)
            throw failure(.internalError, ServiceLanguage.text("Não foi possível substituir \(path)"))
        }
    }

    static func makeDirectory(_ path: String, mode: mode_t) throws {
        if mkdir(path, mode) != 0 && errno != EEXIST {
            throw failure(.internalError, ServiceLanguage.text("Não foi possível criar \(path) (\(String(cString: strerror(errno))))"))
        }
        var info = stat()
        guard lstat(path, &info) == 0, (info.st_mode & S_IFMT) == S_IFDIR, info.st_uid == geteuid() else {
            throw failure(.runtimeRejected, ServiceLanguage.text("Diretório protegido inesperado: \(path)"))
        }
        guard chmod(path, mode) == 0 else { throw failure(.internalError, ServiceLanguage.text("Não foi possível ajustar \(path)")) }
    }

    /// Removes a tree the helper created, without following links out of it.
    static func removeTree(_ path: String) {
        var info = stat()
        guard lstat(path, &info) == 0 else { return }
        if (info.st_mode & S_IFMT) == S_IFDIR {
            chmod(path, 0o700)
            if let entries = try? FileManager.default.contentsOfDirectory(atPath: path) {
                for entry in entries { removeTree(path + "/" + entry) }
            }
            rmdir(path)
        } else {
            unlink(path)
        }
    }

    /// True when the file or any ancestor directory can be changed by a non-root user.
    static func mutableLocation(_ path: String) -> Bool {
        var current = path
        while true {
            var info = stat()
            if lstat(current, &info) != 0 { return true }
            if info.st_uid != 0 || info.st_mode & (S_IWGRP | S_IWOTH) != 0 {
                // Sticky, root-owned world-writable dirs (like /tmp) still allow others to add entries.
                return true
            }
            if current == "/" { return false }
            current = (current as NSString).deletingLastPathComponent
            if current.isEmpty { current = "/" }
        }
    }

    static func realPath(_ path: String) throws -> String {
        guard let resolved = realpath(path, nil) else {
            throw failure(.runtimeRejected, ServiceLanguage.text("Caminho inexistente: \(path)"))
        }
        defer { free(resolved) }
        return String(cString: resolved)
    }
}

/// Private, unlinked descriptors for the configuration and the SAML cookie.
public enum ProtectedDescriptor {
    /// Writes `content` to a new 0600 file inside the helper's 0700 work directory,
    /// unlinks it immediately and returns a read descriptor positioned at 0.
    /// The returned descriptor is close-on-exec; the supervisor receives it as fd 3.
    public static func anonymousFile(_ content: Data, directory: String) throws -> Int32 {
        let path = directory + "/cfg." + UUID().uuidString
        let fd = open(path, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw failure(.internalError, ServiceLanguage.text("Não foi possível criar a configuração protegida.")) }
        let removed = unlink(path)
        do {
            guard removed == 0 else { throw failure(.internalError, ServiceLanguage.text("Não foi possível remover a configuração temporária.")) }
            try SecureFile.writeAll(fd, content, path: ServiceLanguage.text("configuração"))
            guard lseek(fd, 0, SEEK_SET) == 0 else { throw failure(.internalError, ServiceLanguage.text("Configuração protegida inválida.")) }
        } catch { close(fd); throw error }
        return fd
    }

    /// A pipe holding exactly `content` followed by EOF (no newline is added).
    public static func pipe(_ content: Data) throws -> Int32 {
        guard content.count <= 4096 else { throw failure(.invalidRequest, ServiceLanguage.text("Sessão SAML acima do limite.")) }
        var ends: [Int32] = [0, 0]
        guard Darwin.pipe(&ends) == 0 else { throw failure(.internalError, ServiceLanguage.text("Não foi possível criar o canal da sessão SAML.")) }
        _ = fcntl(ends[0], F_SETFD, FD_CLOEXEC)
        _ = fcntl(ends[1], F_SETFD, FD_CLOEXEC)
        defer { close(ends[1]) }
        do { try SecureFile.writeAll(ends[1], content, path: ServiceLanguage.text("sessão SAML")) }
        catch { close(ends[0]); throw error }
        return ends[0]
    }
}
