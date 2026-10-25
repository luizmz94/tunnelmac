import Foundation
import Security
import CryptoKit
import VPNHelperShared

/// Client certificate chosen for a Fortinet connection: only a reference to a Keychain
/// identity (certificate + private key). The key never leaves the Keychain except for the
/// encrypted copy exported for each connection attempt.
struct ClientCertificateReference: Codable, Equatable {
    /// SHA-1 of the certificate (DER), as Keychain Access and `security find-identity` show it.
    var sha1: String
    var name: String

    static func isValidHash(_ value: String) -> Bool {
        value.count == 40 && value.allSatisfy { $0.isASCII && $0.isHexDigit }
    }
}

/// A certificate with a private key in the user's keychains, usable for TLS client auth.
struct ClientIdentity: Identifiable, Equatable {
    var sha1: String
    var name: String
    var issuer: String
    var expires: Date?
    var id: String { sha1 }
    var expired: Bool { expires.map { $0 < Date() } ?? false }
    var reference: ClientCertificateReference { ClientCertificateReference(sha1: sha1, name: name) }
}

enum ClientIdentities {
    /// Keychains to search; nil = the user's search list (tests pass a throwaway keychain).
    static var searchList: [SecKeychain]?

    static func list() -> [ClientIdentity] {
        identities().map(\.info).sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
    }

    /// Exports the identity for one connection attempt. The private key leaves the Keychain
    /// only as encrypted PKCS#8, under a random passphrase that exists only in this request.
    /// macOS may ask the user to allow TunnelMac to use the key ("Sempre permitir").
    static func export(_ reference: ClientCertificateReference) throws -> ClientCertificate {
        guard let match = identities().first(where: { $0.info.sha1 == reference.sha1.lowercased() }) else {
            throw AppFailure("O certificado do cliente \"\(reference.name)\" não foi encontrado no Keychain. Edite a conexão e escolha-o de novo.")
        }
        var key: SecKey?
        var status = SecIdentityCopyPrivateKey(match.identity, &key)
        guard status == errSecSuccess, let key else { throw failure(status, "Não foi possível ler a chave do certificado") }
        var bytes = [UInt8](repeating: 0, count: ClientCertificate.passphraseBytes)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            throw AppFailure("Não foi possível gerar a senha temporária da chave.")
        }
        let passphrase = bytes.map { String(format: "%02x", $0) }.joined()
        var parameters = SecItemImportExportKeyParameters()
        parameters.version = UInt32(SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION)
        parameters.passphrase = Unmanaged.passUnretained(passphrase as CFString)
        var exported: CFData?
        status = withExtendedLifetime(passphrase) {
            SecItemExport(key, .formatWrappedPKCS8, .pemArmour, &parameters, &exported)
        }
        guard status == errSecSuccess, let exported, let pem = String(data: exported as Data, encoding: .utf8) else {
            throw failure(status, "Não foi possível usar a chave do certificado \"\(reference.name)\"")
        }
        let certificate = try certificateChain(match.certificate).map {
            PEM.encode(SecCertificateCopyData($0) as Data, label: "CERTIFICATE")
        }.joined()
        do { return try ClientCertificate(certificate: certificate, key: pem, passphrase: passphrase).validated() }
        catch let violation as RuleViolation { throw AppFailure(violation.message) }
    }

    /// Imports a .p12/.pfx into the login keychain (the password is used only here) and
    /// returns the identity it contains.
    static func importPKCS12(_ data: Data, password: String) throws -> ClientIdentity {
        var options: [String: Any] = [kSecImportExportPassphrase as String: password]
        if let keychain = searchList?.first { options[kSecImportExportKeychain as String] = keychain }
        var items: CFArray?
        let status = SecPKCS12Import(data as CFData, options as CFDictionary, &items)
        switch status {
        case errSecSuccess: break
        case errSecAuthFailed, errSecPkcs12VerifyFailure, errSecPassphraseRequired:
            throw AppFailure("Senha do certificado incorreta.")
        case errSecDuplicateItem:
            throw AppFailure("Este certificado já está no Keychain. Escolha-o na lista \"Certificado do cliente\".")
        default:
            throw failure(status, "Não foi possível importar o arquivo")
        }
        // Preserve intermediate certificates from PKCS#12 for later offline chain export.
        for item in items as? [[String: Any]] ?? [] {
            for certificate in item[kSecImportItemCertChain as String] as? [SecCertificate] ?? [] {
                if let subject = SecCertificateCopyNormalizedSubjectSequence(certificate),
                   let issuer = SecCertificateCopyNormalizedIssuerSequence(certificate), subject == issuer { continue }
                var query: [String: Any] = [kSecClass as String: kSecClassCertificate, kSecValueRef as String: certificate]
                if let keychain = searchList?.first { query[kSecUseKeychain as String] = keychain }
                let result = SecItemAdd(query as CFDictionary, nil)
                guard result == errSecSuccess || result == errSecDuplicateItem else {
                    throw failure(result, "A identidade foi importada, mas não foi possível preservar um certificado intermediário")
                }
            }
        }
        let identities = (items as? [[String: Any]] ?? []).compactMap { $0[kSecImportItemIdentity as String] }
        guard let first = identities.first else { throw AppFailure("O arquivo não contém certificado com chave privada.") }
        let identity = first as! SecIdentity
        var certificate: SecCertificate?
        guard SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess, let certificate else {
            throw AppFailure("O arquivo não contém certificado com chave privada.")
        }
        return info(certificate)
    }

    /// Build from locally available certificates only; never fetch AIA URLs during export.
    static func certificateChain(_ leaf: SecCertificate) throws -> [SecCertificate] {
        var trust: SecTrust?
        guard SecTrustCreateWithCertificates(leaf, SecPolicyCreateBasicX509(), &trust) == errSecSuccess,
              let trust else { throw AppFailure("Não foi possível construir a cadeia do certificado.") }
        SecTrustSetNetworkFetchAllowed(trust, false)
        if let searchList { SecTrustSetKeychains(trust, searchList as CFArray) }
        _ = SecTrustEvaluateWithError(trust, nil)
        let chain = (SecTrustCopyCertificateChain(trust) as? [SecCertificate]) ?? [leaf]
        return chain.enumerated().compactMap { index, certificate in
            if index > 0, let subject = SecCertificateCopyNormalizedSubjectSequence(certificate),
               let issuer = SecCertificateCopyNormalizedIssuerSequence(certificate), subject == issuer { return nil }
            return certificate
        }
    }

    // MARK: Internals

    private static func identities() -> [(identity: SecIdentity, certificate: SecCertificate, info: ClientIdentity)] {
        var query: [String: Any] = [kSecClass as String: kSecClassIdentity, kSecMatchLimit as String: kSecMatchLimitAll,
                                    kSecReturnRef as String: true]
        if let searchList { query[kSecMatchSearchList as String] = searchList }
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let found = result as? [SecIdentity] else { return [] }
        var seen: Set<String> = []
        var list: [(SecIdentity, SecCertificate, ClientIdentity)] = []
        for identity in found {
            var certificate: SecCertificate?
            guard SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess, let certificate,
                  allowsClientAuthentication(certificate) else { continue }
            let info = info(certificate)
            if seen.insert(info.sha1).inserted { list.append((identity, certificate, info)) }
        }
        return list
    }

    static func info(_ certificate: SecCertificate) -> ClientIdentity {
        let der = SecCertificateCopyData(certificate) as Data
        let sha1 = Insecure.SHA1.hash(data: der).map { String(format: "%02x", $0) }.joined()
        let name = (SecCertificateCopySubjectSummary(certificate) as String?) ?? "Certificado sem nome"
        let values = SecCertificateCopyValues(certificate, [kSecOIDX509V1IssuerName, kSecOIDX509V1ValidityNotAfter] as CFArray, nil)
            as? [String: [String: Any]] ?? [:]
        var issuer = ""
        if let parts = values[kSecOIDX509V1IssuerName as String]?[kSecPropertyKeyValue as String] as? [[String: Any]] {
            let common = parts.first { ($0[kSecPropertyKeyLabel as String] as? String) == (kSecOIDCommonName as String) }
            issuer = (common?[kSecPropertyKeyValue as String] as? String) ?? ""
        }
        var expires: Date?
        if let seconds = values[kSecOIDX509V1ValidityNotAfter as String]?[kSecPropertyKeyValue as String] as? NSNumber {
            expires = Date(timeIntervalSinceReferenceDate: seconds.doubleValue)
        }
        return ClientIdentity(sha1: sha1, name: name, issuer: issuer, expires: expires)
    }

    /// No Extended Key Usage, or one that includes TLS client auth (1.3.6.1.5.5.7.3.2) or any
    /// purpose (2.5.29.37.0). Leaves out code signing identities such as Developer ID.
    private static func allowsClientAuthentication(_ certificate: SecCertificate) -> Bool {
        let values = SecCertificateCopyValues(certificate, [kSecOIDExtendedKeyUsage] as CFArray, nil) as? [String: [String: Any]]
        guard let usages = values?[kSecOIDExtendedKeyUsage as String]?[kSecPropertyKeyValue as String] as? [Data] else { return true }
        let clientAuth = Data([0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02]), any = Data([0x55, 0x1D, 0x25, 0x00])
        return usages.contains { $0.suffix(clientAuth.count) == clientAuth || $0.suffix(any.count) == any }
    }

    private static func failure(_ status: OSStatus, _ message: String) -> AppFailure {
        if status == errSecUserCanceled || status == errSecAuthFailed {
            return AppFailure("\(message): acesso à chave negado no Keychain.")
        }
        let detail = (SecCopyErrorMessageString(status, nil) as String?) ?? "erro \(status)"
        return AppFailure("\(message) (\(detail)).")
    }
}
