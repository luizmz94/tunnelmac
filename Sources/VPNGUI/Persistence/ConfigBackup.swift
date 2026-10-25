import Foundation
import VPNHelperShared

/// Everything needed to rebuild the app on another Mac, encrypted with BackupCipher.
/// SAML sessions are left out (temporary and bound to this Mac); client certificates
/// travel only as a reference: the identity itself must already be in the other Keychain.
struct BackupPayload: Codable {
    static let format = "tunnelmac-backup"
    struct Entry: Codable {
        var connection: Connection
        var password: String?
        var openVPNProfile: String?
        var wireGuardProfile: String?
    }
    var format = BackupPayload.format
    var version = 1
    var createdAt = Date()
    var appVersion = HelperConstants.releaseVersion
    var connections: [Entry]
    var preferences: BackupPreferences?
}

/// The user's choices in Configurações; update bookkeeping and the login item stay per Mac.
struct BackupPreferences: Codable, Equatable {
    var showMenuBarIcon: Bool
    var hideDockOnClose: Bool
    var checkForUpdates: Bool
    var includePrereleases: Bool
    var internetDNSSelection: String
    var customInternetDNS: [InternetDNSOption]
}

extension AppPreferences {
    var backup: BackupPreferences {
        BackupPreferences(showMenuBarIcon: showMenuBarIcon, hideDockOnClose: hideDockOnClose, checkForUpdates: checkForUpdates,
                          includePrereleases: includePrereleases, internetDNSSelection: internetDNSSelection,
                          customInternetDNS: customInternetDNS)
    }
    /// Custom DNS entries are checked with the same rules as typed ones; invalid ones are dropped.
    func restore(_ saved: BackupPreferences) {
        showMenuBarIcon = saved.showMenuBarIcon
        hideDockOnClose = saved.hideDockOnClose
        checkForUpdates = saved.checkForUpdates
        includePrereleases = saved.includePrereleases
        var custom: [InternetDNSOption] = []
        for option in saved.customInternetDNS where !custom.contains(where: { $0.id == option.id })
            && !InternetDNSOption.presets.contains(where: { $0.id == option.id }) && option.id != InternetDNSOption.offID {
            if let valid = try? InternetDNSOption.custom(name: option.name, servers: option.servers.joined(separator: ",")) {
                custom.append(InternetDNSOption(id: option.id, name: valid.name, servers: valid.servers))
            }
        }
        customInternetDNS = custom
        let selection = saved.internetDNSSelection
        internetDNSSelection = selection == InternetDNSOption.offID || internetDNSOptions.contains { $0.id == selection }
            ? selection : InternetDNSOption.defaultID
    }
}

/// A decrypted, fully validated backup and what importing it would change.
struct BackupImportPlan {
    var payload: BackupPayload
    /// Names of the connections that already exist here (same identifier) and would be replaced.
    var replacing: [String]
    var adding: [String]
    /// Connections whose password is not in the backup (never saved on the other Mac).
    var missingPasswords: [String]
    /// Connections whose client certificate is not in this Mac's Keychain.
    var missingCertificates: [String]
    var hasPreferences: Bool { payload.preferences != nil }
}

enum ConfigBackup {
    static let fileExtension = "tunnelmacbackup"

    /// Reads every secret of the saved connections. Runs on the persistence queue.
    static func export(_ data: SavedData, store: JSONStore, passwords: PasswordStore,
                       preferences: BackupPreferences?, password: String,
                       iterations: UInt32 = BackupCipher.defaultIterations) throws -> Data {
        try BackupCipher.checkPassword(password)
        let entries = try data.connections.map { connection -> BackupPayload.Entry in
            var entry = BackupPayload.Entry(connection: connection)
            if connection.usesPassword { entry.password = try passwords.read(connection.id) }
            if connection.isOpenVPN { entry.openVPNProfile = try ProfileStore.openVPN(store).read(connection.id) }
            if connection.isWireGuard { entry.wireGuardProfile = try ProfileStore.wireGuard(store).read(connection.id) }
            return entry
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let plaintext = try encoder.encode(BackupPayload(connections: entries, preferences: preferences))
        return try BackupCipher.seal(plaintext, password: password, iterations: iterations)
    }

    /// Decrypts and checks everything with the same rules as a manual save, before anything is written.
    static func open(_ file: Data, password: String) throws -> BackupPayload {
        let plaintext = try BackupCipher.open(file, password: password)
        guard let payload = try? JSONDecoder().decode(BackupPayload.self, from: plaintext), payload.format == BackupPayload.format else {
            throw AppFailure("Conteúdo do backup ilegível.")
        }
        guard payload.version == 1 else {
            throw AppFailure("Backup criado por uma versão mais nova do TunnelMac; atualize o app para importá-lo.")
        }
        guard Set(payload.connections.map(\.connection.id)).count == payload.connections.count else {
            throw AppFailure("O backup contém identificadores de conexão duplicados.")
        }
        for entry in payload.connections {
            let name = entry.connection.name
            func failure(_ message: String) -> AppFailure { AppFailure("Conexão \u{201C}\(name)\u{201D} do backup: \(message)") }
            do {
                let connection = try entry.connection.validated()
                if connection.isOpenVPN {
                    guard let text = entry.openVPNProfile else { throw AppFailure("perfil OpenVPN ausente.") }
                    _ = try OpenVPNProfile.validated(text)
                }
                if connection.isWireGuard {
                    guard let text = entry.wireGuardProfile else { throw AppFailure("perfil WireGuard ausente.") }
                    _ = try WireGuardProfile.validated(text)
                }
                if connection.usesPassword, let password = entry.password, !password.isEmpty {
                    if connection.isOpenVPN { try OpenVPNRules.checkCredential(password, label: "Senha") }
                    else { try Connection.checkConfigValue(password, label: "Senha") }
                }
            } catch let violation as RuleViolation { throw failure(violation.message) }
            catch { throw failure(error.localizedDescription) }
        }
        return payload
    }

    static func plan(_ payload: BackupPayload, current: SavedData, certificates: Set<String>) -> BackupImportPlan {
        let existing = Set(current.connections.map(\.id))
        let connections = payload.connections.map(\.connection)
        return BackupImportPlan(
            payload: payload,
            replacing: connections.filter { existing.contains($0.id) }.map(\.name),
            adding: connections.filter { !existing.contains($0.id) }.map(\.name),
            missingPasswords: payload.connections.filter { $0.connection.usesPassword && ($0.password ?? "").isEmpty }.map(\.connection.name),
            missingCertificates: connections.compactMap { connection in
                guard let reference = connection.clientCertificate, !connection.usesProfile,
                      !certificates.contains(reference.sha1.lowercased()) else { return nil }
                return "\(connection.name) (\(reference.name))"
            })
    }

    /// One transaction per connection, in backup order; connections not in the backup stay.
    /// Stops at the first failure: what was already imported is kept and reported.
    static func apply(_ payload: BackupPayload, current: SavedData, store: JSONStore,
                      passwords: PasswordStore, cookies: SAMLCookieStore) throws -> SavedData {
        var updated = current
        let save = ConnectionSave(store: store, passwords: passwords, cookies: cookies)
        for (index, entry) in payload.connections.enumerated() {
            do {
                updated = try save.run(current: updated, connection: entry.connection, password: entry.password ?? "",
                                       openVPNProfile: entry.connection.isOpenVPN ? entry.openVPNProfile : nil,
                                       wireGuardProfile: entry.connection.isWireGuard ? entry.wireGuardProfile : nil,
                                       requirePassword: false)
            } catch {
                throw BackupImportFailure(saved: updated, imported: index, message:
                    "Importação interrompida em \u{201C}\(entry.connection.name)\u{201D} (\(index) de \(payload.connections.count) importadas): \(error.localizedDescription)")
            }
        }
        return updated
    }
}

/// A partial import: the connections already saved are real and must reach the interface.
struct BackupImportFailure: LocalizedError {
    let saved: SavedData
    let imported: Int
    let message: String
    var errorDescription: String? { message }
}
