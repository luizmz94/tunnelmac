import Foundation
import Security
import CryptoKit
import VPNHelperShared

// SAML session cache in the user's Keychain. Capture rules, the output filter and the
// launch plan live in VPNHelperShared (the helper filters output before it reaches the app).

/// Everything that makes a cached cookie belong to exactly one gateway session.
/// The profile name is excluded, so renaming keeps the cache.
struct SAMLCookieIdentity: Equatable {
    let digest: String
    init(_ connection: Connection) {
        let host = connection.server.trimmingCharacters(in: .whitespacesAndNewlines)
            .trimmingCharacters(in: CharacterSet(charactersIn: "[]")).lowercased()
        var parts = ["v2", connection.clientCertificate?.sha1.lowercased() ?? "", connection.id.uuidString, host, String(connection.port), connection.username,
                     connection.authentication.rawValue,
                     connection.trustedCertificate.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()]
        // Only when set, so sessions saved before realms existed keep their identity.
        if !connection.realm.isEmpty { parts.append("realm=" + connection.realm) }
        let bytes = Data(parts.joined(separator: "\u{1f}").utf8)
        digest = SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
    }
}

struct SAMLCookieRecord: Codable {
    var version = 1
    var cookie: String
    var identity: String
    var capturedAt: Date
    var expiresAt: Date
}

enum SAMLCookieLookup {
    case none
    case cookie(String)
    case failure(String)
}

/// Keychain cache, in a service separate from passwords. Never written to JSON or UserDefaults.
struct SAMLCookieStore {
    let service: String
    init(service: String = "com.luiz.vpngui.saml-cookie") { self.service = service }
    private func query(_ id: UUID) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
         kSecAttrAccount as String: id.uuidString]
    }
    /// Returns an eligible cookie or nothing. Expired or foreign entries are deleted.
    /// Reading never extends the lifetime.
    func lookup(_ connection: Connection, now: Date = Date()) -> SAMLCookieLookup {
        guard connection.authentication == .saml else { return .none }
        do {
            guard let record = try read(connection.id) else { return .none }
            let identity = SAMLCookieIdentity(connection).digest
            // Allow small clock corrections but never a capture time from the future.
            guard record.version == 1, record.identity == identity, SAMLCookieRules.isValid(record.cookie),
                  record.capturedAt <= now.addingTimeInterval(60),
                  now < record.expiresAt,
                  record.expiresAt <= record.capturedAt.addingTimeInterval(SAMLCookieRules.maximumAge) else {
                try? delete(connection.id)
                return .none
            }
            return .cookie(record.cookie)
        } catch {
            return .failure(error.localizedDescription)
        }
    }
    func save(_ cookie: String, for connection: Connection, capturedAt: Date = Date(), knownExpiry: Date? = nil) throws {
        guard connection.authentication == .saml, SAMLCookieRules.isValid(cookie) else {
            throw AppFailure("Sessão SAML em formato inesperado; não foi armazenada.")
        }
        var expiresAt = capturedAt.addingTimeInterval(SAMLCookieRules.maximumAge)
        if let knownExpiry, knownExpiry < expiresAt { expiresAt = knownExpiry }
        let record = SAMLCookieRecord(cookie: cookie, identity: SAMLCookieIdentity(connection).digest,
                                      capturedAt: capturedAt, expiresAt: expiresAt)
        let data = try JSONEncoder().encode(record)
        let q = query(connection.id)
        let values: [String: Any] = [kSecValueData as String: data,
                                     kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                     kSecAttrLabel as String: "TunnelMac – sessão SAML temporária"]
        let status = SecItemUpdate(q as CFDictionary, values as CFDictionary)
        if status == errSecItemNotFound {
            try check(SecItemAdd(q.merging(values) { _, new in new } as CFDictionary, nil))
        } else { try check(status) }
    }
    func read(_ id: UUID) throws -> SAMLCookieRecord? {
        var q = query(id)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        try check(status)
        guard let data = result as? Data, let record = try? JSONDecoder().decode(SAMLCookieRecord.self, from: data) else {
            try? delete(id)
            return nil
        }
        return record
    }
    func delete(_ id: UUID) throws {
        let status = SecItemDelete(query(id) as CFDictionary)
        if status != errSecItemNotFound { try check(status) }
    }
    private func check(_ status: OSStatus) throws {
        guard status == errSecSuccess else {
            throw AppFailure("Keychain da sessão SAML (\(status)): \(SecCopyErrorMessageString(status, nil) as String? ?? String(status))")
        }
    }
}
