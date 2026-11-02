import Foundation
import Security
import VPNHelperShared

/// "Consultar gateway" of a Check Point connection. Gateways usually present a certificate
/// issued by their own internal CA (ICA), valid for one address only. The app reads the chain
/// of https://<host>:<port>/ (one ephemeral handshake, nothing sent to an untrusted server),
/// shows the ICA for the user to trust explicitly and points out an address the certificate
/// does not cover. The login types come from `snx-rs -m info`, run by the helper.
enum CheckPointGateway {
    enum Certificate: Equatable {
        /// macOS validates the gateway on its own.
        case system
        /// Issued by this authority (sent by the gateway), valid for the address.
        case authority(CheckPointAuthority)
        /// The certificate chains to the authority but names other addresses.
        case mismatch(names: [String], authority: CheckPointAuthority)
        case untrusted(String)
    }

    /// A gateway typed or pasted far enough to query on its own: a full IPv4 or bracketed IPv6
    /// address, or a host name with a top-level domain (optionally with a port). Anything else
    /// waits for the field to lose focus.
    static func isCompleteAddress(_ text: String) -> Bool {
        guard let gateway = try? GatewayAddress.parse(text), gateway.realm.isEmpty else { return false }
        let host = gateway.host
        if host.hasPrefix("[") { return true }
        let labels = host.split(separator: ".", omittingEmptySubsequences: false)
        if labels.allSatisfy({ !$0.isEmpty && $0.allSatisfy(\.isNumber) }) {
            return labels.count == 4 && labels.allSatisfy { Int($0).map { (0...255).contains($0) } ?? false }
        }
        guard labels.count >= 2, let top = labels.last else { return false }
        return top.count >= 2 && top.allSatisfy(\.isLetter)
    }

    static func inspect(host: String, port: Int) async -> Certificate {
        var components = URLComponents()
        components.scheme = "https"
        components.host = host.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        if port != 443 { components.port = port }
        components.path = "/"
        guard let url = components.url else { return .untrusted(String(localized: "Servidor inválido.")) }
        let (trusted, chain, error) = await NetworkCertificates.handshake(url)
        guard let leaf = chain.first else {
            return .untrusted(String(localized: "Não foi possível conectar ao gateway: \(error ?? String(localized: "sem resposta"))"))
        }
        if trusted == true { return .system }
        return evaluate(chain: chain, leaf: leaf, host: components.host ?? host)
    }

    /// The ICA is the last self-signed certificate of the chain. Valid for `host` with only that
    /// anchor → `authority`; valid without the host check → `mismatch` with the names it covers.
    static func evaluate(chain: [SecCertificate], leaf: SecCertificate, host: String) -> Certificate {
        guard let root = chain.last(where: NetworkCertificates.selfSigned), root != leaf || chain.count == 1 else {
            return .untrusted(String(localized: "O gateway não enviou a autoridade que assinou o certificado dele; peça o certificado ao administrador da VPN."))
        }
        let authority = describe(root)
        if verify(chain, anchor: root, policy: SecPolicyCreateSSL(true, host as CFString)) { return .authority(authority) }
        if verify(chain, anchor: root, policy: SecPolicyCreateBasicX509()) {
            return .mismatch(names: names(leaf), authority: authority)
        }
        return .untrusted(String(localized: "O certificado do gateway não é válido nem com a autoridade que ele apresenta (vencido ou incompleto)."))
    }

    static func verify(_ chain: [SecCertificate], anchor: SecCertificate, policy: SecPolicy) -> Bool {
        var trust: SecTrust?
        guard SecTrustCreateWithCertificates(chain as CFArray, policy, &trust) == errSecSuccess, let trust else { return false }
        SecTrustSetAnchorCertificates(trust, [anchor] as CFArray)
        SecTrustSetAnchorCertificatesOnly(trust, true)
        return SecTrustEvaluateWithError(trust, nil)
    }

    static func describe(_ certificate: SecCertificate) -> CheckPointAuthority {
        let der = SecCertificateCopyData(certificate) as Data
        return CheckPointAuthority(der: der, sha256: CheckPointAuthority.digest(der), subject: subject(certificate),
                                   notAfter: NetworkCertificates.notAfter(certificate), fingerprintWords: nil)
    }

    /// "O=…, CN=…" from the subject; the system summary when the fields are unknown.
    static func subject(_ certificate: SecCertificate) -> String {
        let labels: [String: String] = [kSecOIDCommonName as String: "CN", kSecOIDOrganizationName as String: "O",
                                        kSecOIDOrganizationalUnitName as String: "OU", kSecOIDCountryName as String: "C"]
        let keys = [kSecOIDX509V1SubjectName] as CFArray
        if let values = SecCertificateCopyValues(certificate, keys, nil) as? [String: Any],
           let subject = values[kSecOIDX509V1SubjectName as String] as? [String: Any],
           let entries = subject[kSecPropertyKeyValue as String] as? [[String: Any]] {
            let parts = entries.compactMap { entry -> String? in
                guard let label = entry[kSecPropertyKeyLabel as String] as? String, let short = labels[label],
                      let value = entry[kSecPropertyKeyValue as String] as? String else { return nil }
                return "\(short)=\(value)"
            }
            if !parts.isEmpty { return parts.joined(separator: ", ") }
        }
        return SecCertificateCopySubjectSummary(certificate) as String? ?? "?"
    }

    /// DNS names and IP addresses of the subject alternative names, then the common name.
    static func names(_ certificate: SecCertificate) -> [String] {
        var result: [String] = []
        let keys = [kSecOIDSubjectAltName] as CFArray
        if let values = SecCertificateCopyValues(certificate, keys, nil) as? [String: Any],
           let alternative = values[kSecOIDSubjectAltName as String] as? [String: Any],
           let entries = alternative[kSecPropertyKeyValue as String] as? [[String: Any]] {
            for entry in entries {
                guard let value = entry[kSecPropertyKeyValue as String] as? String else { continue }
                result.append(value)
            }
        }
        var common: CFString?
        if SecCertificateCopyCommonName(certificate, &common) == errSecSuccess, let common = common as String? { result.append(common) }
        var seen = Set<String>()
        // Only values that can be typed as a gateway address.
        return result.filter { value in
            (try? ConnectionRules.normalizedHost(value)) != nil && !value.contains("*") && seen.insert(value.lowercased()).inserted
        }.prefix(8).map { $0 }
    }

    /// Why a login type cannot be used by this version, shown next to it.
    static func unsupportedReason(_ option: CheckPointLoginOption) -> String? {
        guard !CheckPointRules.isSupported(option) else { return nil }
        if option.factors.contains("identity_provider") { return String(localized: "exige navegador") }
        if option.factors.contains("certificate") { return String(localized: "exige certificado") }
        if option.factors.count > 1 { return String(localized: "exige MFA") }
        return String(localized: "não suportado")
    }
}
