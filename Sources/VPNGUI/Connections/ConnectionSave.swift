import Foundation
import VPNHelperShared

struct ConnectionSave {
    let store: JSONStore
    let passwords: PasswordStore
    let cookies: SAMLCookieStore
    func run(current: SavedData, connection: Connection, password: String, openVPNProfile: String?, wireGuardProfile: String?) throws -> SavedData {
        let c = try connection.validated()
        if c.usesPassword {
            guard !password.isEmpty else { throw AppFailure("Informe a senha da VPN.") }
            if c.isOpenVPN {
                do { try OpenVPNRules.checkCredential(password, label: "Senha") }
                catch let violation as RuleViolation { throw AppFailure(violation.message) }
            } else { try Connection.checkConfigValue(password, label: "Senha") }
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
            connection: c, updated: updated, password: c.usesPassword ? password : nil,
            openVPN: openVPNProfile, wireGuard: wireGuardProfile)
        return updated
    }
}
