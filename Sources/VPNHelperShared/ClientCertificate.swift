import Foundation
import Security

/// Client certificate of a Fortinet session, exported by the app from the user's Keychain
/// for this one connection: the certificate chain in PEM and the private key as an encrypted
/// PKCS#8 PEM, protected by a random passphrase made for this export. The helper writes the
/// two PEM files into its own root-only directory and gives openfortivpn the passphrase
/// through the protected configuration only.
public struct ClientCertificate: Codable, Equatable, Sendable {
    public var certificate: String
    public var key: String
    public var passphrase: String
    public init(certificate: String, key: String, passphrase: String) {
        self.certificate = certificate; self.key = key; self.passphrase = passphrase
    }

    public static let maximumPEM = 24 * 1024
    public static let maximumChain = 8
    /// openfortivpn keeps at most 31 characters of pem-passphrase (PEM_PASSPHRASE_SIZE) and
    /// silently truncates longer values, so the key would no longer open: 15 random bytes in hex.
    public static let passphraseBytes = 15
    public static var passphraseLength: Int { passphraseBytes * 2 }

    /// Same rules in the app and in the helper. Returns canonical PEM (base64 re-wrapped from
    /// decoded DER), so nothing but the validated blocks ever reaches a file.
    public func validated() throws -> ClientCertificate {
        guard certificate.utf8.count <= Self.maximumPEM, key.utf8.count <= Self.maximumPEM else {
            throw RuleViolation(ServiceLanguage.text("Certificado do cliente acima do tamanho suportado."))
        }
        let certificates = try PEM.blocks(certificate, label: "CERTIFICATE")
        guard !certificates.isEmpty, certificates.count <= Self.maximumChain else {
            throw RuleViolation(ServiceLanguage.text("Certificado do cliente em formato inesperado."))
        }
        for der in certificates where SecCertificateCreateWithData(nil, der as CFData) == nil {
            throw RuleViolation(ServiceLanguage.text("Certificado do cliente inválido."))
        }
        let keys = try PEM.blocks(key, label: "ENCRYPTED PRIVATE KEY")
        guard keys.count == 1 else { throw RuleViolation(ServiceLanguage.text("Chave do certificado do cliente em formato inesperado.")) }
        guard passphrase.count == Self.passphraseLength, passphrase.allSatisfy({ $0.isASCII && $0.isHexDigit }) else {
            throw RuleViolation(ServiceLanguage.text("Senha temporária da chave em formato inesperado."))
        }
        return ClientCertificate(certificate: certificates.map { PEM.encode($0, label: "CERTIFICATE") }.joined(),
                                 key: PEM.encode(keys[0], label: "ENCRYPTED PRIVATE KEY"), passphrase: passphrase)
    }
}

/// Paths chosen by the helper for one session's certificate files.
public struct ClientCertificateFiles: Equatable, Sendable {
    public var certificatePath: String
    public var keyPath: String
    public var passphrase: String
    public init(certificatePath: String, keyPath: String, passphrase: String) {
        self.certificatePath = certificatePath; self.keyPath = keyPath; self.passphrase = passphrase
    }
}

public enum PEM {
    /// Every "-----BEGIN <label>-----" block, decoded. Text outside blocks must be blank;
    /// blocks of another label are refused.
    public static func blocks(_ text: String, label: String) throws -> [Data] {
        let begin = "-----BEGIN \(label)-----", end = "-----END \(label)-----"
        var result: [Data] = []
        var body: [String]?
        for raw in text.split(omittingEmptySubsequences: false, whereSeparator: \.isNewline) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if var current = body {
                if line == end {
                    guard let data = Data(base64Encoded: current.joined()), !data.isEmpty else {
                        throw RuleViolation(ServiceLanguage.text("Bloco PEM inválido."))
                    }
                    result.append(data); body = nil
                } else {
                    guard line.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || "+/=".contains($0)) }) else {
                        throw RuleViolation(ServiceLanguage.text("Bloco PEM inválido."))
                    }
                    current.append(line); body = current
                }
            } else if line == begin {
                body = []
            } else if !line.isEmpty {
                throw RuleViolation(ServiceLanguage.text("Conteúdo inesperado no PEM."))
            }
        }
        guard body == nil else { throw RuleViolation(ServiceLanguage.text("Bloco PEM incompleto.")) }
        return result
    }

    public static func encode(_ der: Data, label: String) -> String {
        let base64 = der.base64EncodedString()
        var lines: [Substring] = []
        var index = base64.startIndex
        while index < base64.endIndex {
            let next = base64.index(index, offsetBy: 64, limitedBy: base64.endIndex) ?? base64.endIndex
            lines.append(base64[index..<next]); index = next
        }
        return "-----BEGIN \(label)-----\n" + lines.joined(separator: "\n") + "\n-----END \(label)-----\n"
    }
}
