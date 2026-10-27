import Foundation
import VPNHelperShared

struct ConnectionSave {
    let store: JSONStore
    let passwords: PasswordStore
    let cookies: SAMLCookieStore
    /// `requirePassword: false` (backup import) saves a cadastro whose password was not in the
    /// backup; connecting then asks the user to edit it and type the password again.
    func run(current: SavedData, connection: Connection, password: String, openVPNProfile: String?, wireGuardProfile: String?,
             requirePassword: Bool = true) throws -> SavedData {
        let c = try connection.validated()
        let storesPassword = c.usesPassword && (requirePassword || !password.isEmpty)
        if storesPassword {
            guard !password.isEmpty else { throw AppFailure(String(localized: "Informe a senha da VPN.")) }
            if c.isOpenVPN {
                do { try OpenVPNRules.checkCredential(password, label: String(localized: "Senha")) }
                catch let violation as RuleViolation { throw AppFailure(violation.message) }
            } else { try Connection.checkConfigValue(password, label: String(localized: "Senha")) }
        }
        if c.isOpenVPN {
            let profiles = ProfileStore.openVPN(store)
            if let openVPNProfile {
                // The helper applies exactly this check again before root reads it.
                do { _ = try OpenVPNProfile.validated(openVPNProfile) }
                catch let violation as RuleViolation { throw AppFailure(violation.message) }
            } else { _ = try profiles.read(c.id) }
        }
        if c.isWireGuard {
            let wireGuardProfiles = ProfileStore.wireGuard(store)
            if let wireGuardProfile {
                do { _ = try WireGuardProfile.validated(wireGuardProfile) }
                catch let violation as RuleViolation { throw AppFailure(violation.message) }
            } else { _ = try wireGuardProfiles.read(c.id) }
        }
        var updated = current
        if let index = updated.connections.firstIndex(where: { $0.id == c.id }) { updated.connections[index] = c }
        else { updated.connections.append(c) }
        try ConnectionTransaction(store: store, passwords: passwords, cookies: cookies).save(
            connection: c, updated: updated, password: storesPassword ? password : nil,
            openVPN: openVPNProfile, wireGuard: wireGuardProfile)
        return updated
    }
}
