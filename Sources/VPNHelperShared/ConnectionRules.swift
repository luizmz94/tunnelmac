import Foundation
import Darwin

public struct RuleViolation: LocalizedError, Equatable {
    public let message: String
    public init(_ message: String) { self.message = message }
    public var errorDescription: String? { message }
}

public enum Authentication: String, Codable, CaseIterable, Identifiable, Sendable {
    case password, saml
    public var id: String { rawValue }
}

/// Field rules shared by the app (form validation) and the helper (request validation).
/// The helper never trusts the app's validation: it runs the same rules again.
public enum ConnectionRules {
    public static let maximumHost = 253 + 2
    public static let maximumField = 512

    public static func normalizedHost(_ server: String) throws -> String {
        let value = server.trimmingCharacters(in: .whitespacesAndNewlines)
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-:[]")
        guard !value.isEmpty, value.count <= maximumHost, value.unicodeScalars.allSatisfy(allowed.contains),
              !value.hasPrefix("-"), !value.contains("/") else {
            throw RuleViolation(ServiceLanguage.text("Informe somente o hostname ou IP do servidor, sem protocolo ou porta."))
        }
        return value
    }

    public static func checkPort(_ port: Int) throws {
        guard (1...65535).contains(port) else { throw RuleViolation(ServiceLanguage.text("A porta deve estar entre 1 e 65535.")) }
    }

    /// openfortivpn's config is line based and trims surrounding whitespace.
    public static func checkConfigValue(_ text: String, label: String) throws {
        guard text.utf8.count <= maximumField,
              !text.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }),
              text == text.trimmingCharacters(in: .whitespacesAndNewlines) else {
            throw RuleViolation(ServiceLanguage.text("\(label): caracteres de controle ou espaços nas extremidades não são suportados."))
        }
    }

    /// FortiGate realm (the "/realm" of a FortiClient gateway address).
    public static func checkRealm(_ realm: String) throws {
        guard realm.isEmpty || (realm.count <= 64 && !realm.hasPrefix("-")
              && realm.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || "._-".contains($0)) })) else {
            throw RuleViolation(ServiceLanguage.text("Realm: use somente letras, números, ponto, hífen ou sublinhado."))
        }
    }

    /// "DNS da internet": 1 to 4 literal IPv4/IPv6 addresses, canonical and without repeats.
    public static func internetDNS(_ servers: [String]) throws -> [String] {
        var result: [String] = []
        for raw in servers {
            let value = raw.trimmingCharacters(in: .whitespaces)
            var v4 = in_addr(), v6 = in6_addr()
            var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            if inet_pton(AF_INET, value, &v4) == 1, v4.s_addr != 0 {
                inet_ntop(AF_INET, &v4, &buffer, socklen_t(buffer.count))
            } else if inet_pton(AF_INET6, value, &v6) == 1 {
                inet_ntop(AF_INET6, &v6, &buffer, socklen_t(buffer.count))
            } else {
                throw RuleViolation(ServiceLanguage.text("DNS da internet: \"\(value)\" não é um endereço IP."))
            }
            let canonical = String(cString: buffer)
            if !result.contains(canonical) { result.append(canonical) }
        }
        guard (1...4).contains(result.count) else { throw RuleViolation(ServiceLanguage.text("DNS da internet: informe de 1 a 4 servidores.")) }
        return result
    }

    public static func normalizedCertificate(_ value: String) throws -> String {
        let digest = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard digest.isEmpty || (digest.count == 64 && digest.allSatisfy({ $0.isHexDigit && $0.isASCII })) else {
            throw RuleViolation(ServiceLanguage.text("O certificado confiável deve ter exatamente 64 caracteres hexadecimais (SHA-256)."))
        }
        return digest
    }
}

/// openfortivpn configuration rendered by the helper from validated fields only.
/// Options such as pppd-plugin, pppd-call, log paths or set-routes are never produced:
/// the client cannot add lines because every value is line-safe. user-cert/user-key only
/// point at files the helper itself wrote for this session.
public enum ConfigRenderer {
    public static func render(host: String, port: Int, username: String, password: String?,
                              trustedCertificate: String, realm: String = "",
                              clientCertificate: ClientCertificateFiles? = nil) throws -> String {
        let host = try ConnectionRules.normalizedHost(host)
        try ConnectionRules.checkPort(port)
        try ConnectionRules.checkConfigValue(username, label: ServiceLanguage.text("Usuário"))
        let certificate = try ConnectionRules.normalizedCertificate(trustedCertificate)
        var content = "host = \(host)\nport = \(port)\n"
        try ConnectionRules.checkRealm(realm)
        if !realm.isEmpty { content += "realm = \(realm)\n" }
        if !username.isEmpty { content += "username = \(username)\n" }
        if let password {
            try ConnectionRules.checkConfigValue(password, label: ServiceLanguage.text("Senha"))
            content += "password = \(password)\n"
        }
        if !certificate.isEmpty { content += "trusted-cert = \(certificate)\n" }
        if let files = clientCertificate {
            for (value, label) in [(files.certificatePath, ServiceLanguage.text("Certificado")), (files.keyPath, ServiceLanguage.text("Chave")), (files.passphrase, ServiceLanguage.text("Senha da chave"))] {
                try ConnectionRules.checkConfigValue(value, label: label)
            }
            guard files.certificatePath.hasPrefix("/"), files.keyPath.hasPrefix("/"), !files.passphrase.isEmpty else {
                throw RuleViolation(ServiceLanguage.text("Arquivos do certificado do cliente inválidos."))
            }
            content += "user-cert = \(files.certificatePath)\nuser-key = \(files.keyPath)\npem-passphrase = \(files.passphrase)\n"
        }
        return content
    }
}
