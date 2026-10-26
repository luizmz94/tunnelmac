import Foundation
import Security
import Darwin
import VPNHelperShared

struct PasswordStore {
    let service: String
    init(service: String = "com.luiz.vpngui.password") { self.service = service }
    private func query(_ id: UUID) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
         kSecAttrAccount as String: id.uuidString]
    }
    func read(_ id: UUID) throws -> String? {
        var q = query(id)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        try check(status)
        if (result as? Data)?.isEmpty == true { return nil } // Scrubbed by KeychainItem.delete.
        guard let data = result as? Data, let text = String(data: data, encoding: .utf8) else {
            throw AppFailure("Senha inválida no Keychain.")
        }
        return text
    }
    func write(_ password: String, id: UUID) throws {
        let q = query(id)
        let values = [kSecValueData as String: Data(password.utf8)]
        let status = SecItemUpdate(q as CFDictionary, values as CFDictionary)
        if status == errSecItemNotFound {
            let item = q.merging(values) { _, new in new }
            try check(SecItemAdd(item as CFDictionary, nil))
        } else { try check(status) }
    }
    func delete(_ id: UUID) throws {
        let status = KeychainItem.delete(query(id))
        if status != errSecItemNotFound { try check(status) }
    }
    private func check(_ status: OSStatus) throws {
        guard status == errSecSuccess else {
            throw AppFailure("Keychain (\(status)): \(SecCopyErrorMessageString(status, nil) as String? ?? String(status))")
        }
    }
}

enum KeychainItem {
    /// Items created by an earlier build (another path or signature) carry an owner ACL that
    /// refuses deletion with errSecInvalidOwnerEdit, although their value can still be updated.
    /// The secret is then overwritten with nothing, so a pending deletion can finish.
    static func delete(_ query: [String: Any]) -> OSStatus {
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecInvalidOwnerEdit else { return status }
        return SecItemUpdate(query as CFDictionary, [kSecValueData as String: Data()] as CFDictionary)
    }
}
