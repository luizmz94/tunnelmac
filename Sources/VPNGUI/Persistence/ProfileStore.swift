import Foundation
import Security
import Darwin
import VPNHelperShared

/// Imported profiles (OpenVPN: normalized, inline material only; WireGuard: normalized,
/// with the private key), one 0600 file per connection inside a 0700 directory of the
/// app's own data folder.
struct ProfileStore {
    let directory: URL
    let fileExtension: String
    let label: String
    let maximumSize: Int
    init(directory: URL, fileExtension: String = "ovpn", label: String = "OpenVPN", maximumSize: Int = OpenVPNProfile.maximumNormalizedSize) {
        self.directory = directory; self.fileExtension = fileExtension; self.label = label; self.maximumSize = maximumSize
    }
    static func openVPN(_ store: JSONStore) -> ProfileStore {
        ProfileStore(directory: store.directory.appendingPathComponent("OpenVPN", isDirectory: true))
    }
    static func wireGuard(_ store: JSONStore) -> ProfileStore {
        ProfileStore(directory: store.directory.appendingPathComponent("WireGuard", isDirectory: true), fileExtension: "conf",
                     label: "WireGuard", maximumSize: WireGuardProfile.maximumSize)
    }
    func file(_ id: UUID) -> URL { directory.appendingPathComponent(id.uuidString + "." + fileExtension) }
    func read(_ id: UUID) throws -> String {
        let url = file(id)
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw AppFailure("O perfil \(label) desta conexão não foi encontrado. Importe-o novamente.")
        }
        let data = try BoundedFile.read(url, limit: maximumSize)
        guard data.count <= maximumSize, let text = String(data: data, encoding: .utf8) else {
            throw AppFailure("Perfil \(label) salvo ilegível.")
        }
        return text
    }
    func write(_ text: String, id: UUID) throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
        let url = file(id)
        let temporary = directory.appendingPathComponent(".\(id.uuidString).\(UUID().uuidString).tmp")
        // Created 0600 before any byte is written; then atomically renamed into place.
        guard FileManager.default.createFile(atPath: temporary.path, contents: nil, attributes: [.posixPermissions: 0o600]) else {
            throw AppFailure("Não foi possível gravar o perfil \(label).")
        }
        do {
            let handle = try FileHandle(forWritingTo: temporary)
            try handle.write(contentsOf: Data(text.utf8))
            try handle.synchronize()
            try handle.close()
            guard rename(temporary.path, url.path) == 0 else { throw AppFailure("Não foi possível gravar o perfil \(label).") }
        } catch {
            try? FileManager.default.removeItem(at: temporary)
            throw error
        }
    }
    func delete(_ id: UUID) throws {
        let url = file(id)
        if FileManager.default.fileExists(atPath: url.path) { try FileManager.default.removeItem(at: url) }
    }
}

