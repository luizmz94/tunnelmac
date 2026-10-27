import Foundation
import Security
import Darwin
import VPNHelperShared

struct JSONStore {
    static let maximumSize = 4 * 1024 * 1024
    let directory: URL
    init(directory: URL? = nil) throws {
        self.directory = try directory ?? FileManager.default.url(for: .applicationSupportDirectory,
            in: .userDomainMask, appropriateFor: nil, create: true).appendingPathComponent("VPNGUI", isDirectory: true)
        try FileManager.default.createDirectory(at: self.directory, withIntermediateDirectories: true,
                                               attributes: [.posixPermissions: 0o700])
    }
    var file: URL { directory.appendingPathComponent("connections.json") }
    func load() throws -> SavedData {
        guard FileManager.default.fileExists(atPath: file.path) else { return SavedData() }
        let saved = try JSONDecoder().decode(SavedData.self, from: BoundedFile.read(file, limit: Self.maximumSize))
        guard Set(saved.connections.map(\.id)).count == saved.connections.count else {
            throw AppFailure(String(localized: "O arquivo de conexões contém identificadores duplicados."))
        }
        return saved
    }
    func encoded(_ data: SavedData) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let bytes = try encoder.encode(data)
        guard bytes.count <= Self.maximumSize else { throw AppFailure(String(localized: "Arquivo de conexões acima do limite de 4 MiB; reduza os cadastros antes de salvar.")) }
        return bytes
    }
    func save(_ data: SavedData) throws { try BoundedFile.replace(file, data: encoded(data)) }
}

