import Foundation
import CryptoKit
import CommonCrypto
import Security

/// Password-protected container of a TunnelMac backup:
/// "TMBACKUP" · version (1 byte) · PBKDF2 iterations (UInt32, big endian) · salt (16) · nonce (12)
/// followed by AES-256-GCM ciphertext and tag. The whole header is authenticated as AAD,
/// so a changed iteration count, salt or version fails exactly like a wrong password.
enum BackupCipher {
    static let magic = Data("TMBACKUP".utf8)
    static let version: UInt8 = 1
    /// PBKDF2-HMAC-SHA256, OWASP 2023 recommendation.
    static let defaultIterations: UInt32 = 600_000
    /// Accepted on import: never weaker than the minimum, never a header that stalls the app.
    static let acceptedIterations: ClosedRange<UInt32> = 100_000...10_000_000
    static let saltSize = 16
    static let nonceSize = 12
    static let tagSize = 16
    static var headerSize: Int { magic.count + 1 + 4 + saltSize + nonceSize }
    static let minimumPassword = 8
    static let maximumSize = 32 * 1024 * 1024

    static func checkPassword(_ password: String) throws {
        guard password.count >= minimumPassword else {
            throw AppFailure("Use uma senha de pelo menos \(minimumPassword) caracteres.")
        }
    }

    static func seal(_ plaintext: Data, password: String, iterations: UInt32 = defaultIterations) throws -> Data {
        try checkPassword(password)
        let salt = try random(saltSize), nonce = try random(nonceSize)
        var header = magic
        header.append(version)
        withUnsafeBytes(of: iterations.bigEndian) { header.append(contentsOf: $0) }
        header.append(salt)
        header.append(nonce)
        let key = try derive(password, salt: salt, iterations: iterations)
        let box = try AES.GCM.seal(plaintext, using: key, nonce: AES.GCM.Nonce(data: nonce), authenticating: header)
        let sealed = header + box.ciphertext + box.tag
        guard sealed.count <= maximumSize else { throw AppFailure("Backup acima do limite de 32 MiB.") }
        return sealed
    }

    static func open(_ file: Data, password: String) throws -> Data {
        let file = Data(file) // Zero-based indices.
        guard file.count >= headerSize + tagSize, file.count <= maximumSize, file.prefix(magic.count) == magic else {
            throw AppFailure("O arquivo escolhido não é um backup do TunnelMac.")
        }
        guard file[magic.count] == version else {
            throw AppFailure("Backup criado por uma versão mais nova do TunnelMac; atualize o app para importá-lo.")
        }
        let iterations = file[(magic.count + 1)..<(magic.count + 5)].reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
        guard acceptedIterations.contains(iterations) else { throw AppFailure("Backup com parâmetros de proteção inválidos.") }
        let saltStart = magic.count + 5
        let salt = file[saltStart..<(saltStart + saltSize)]
        let nonce = file[(saltStart + saltSize)..<headerSize]
        let header = file.prefix(headerSize)
        let body = file.dropFirst(headerSize)
        do {
            let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: nonce), ciphertext: body.dropLast(tagSize), tag: body.suffix(tagSize))
            return try AES.GCM.open(box, using: derive(password, salt: Data(salt), iterations: iterations), authenticating: header)
        } catch {
            throw AppFailure("Senha incorreta ou arquivo de backup danificado.")
        }
    }

    /// NFC first, so the same password typed with a different keyboard layout still opens the file.
    static func derive(_ password: String, salt: Data, iterations: UInt32) throws -> SymmetricKey {
        let secret = password.precomposedStringWithCanonicalMapping
        guard !secret.isEmpty, !salt.isEmpty else { throw AppFailure("Senha incorreta ou arquivo de backup danificado.") }
        var key = [UInt8](repeating: 0, count: 32)
        let status = salt.withUnsafeBytes { saltBytes in
            CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), secret, secret.utf8.count,
                                 saltBytes.bindMemory(to: UInt8.self).baseAddress, salt.count,
                                 CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), iterations, &key, key.count)
        }
        guard status == kCCSuccess else { throw AppFailure("Não foi possível derivar a chave do backup.") }
        defer { key.withUnsafeMutableBytes { _ = memset_s($0.baseAddress, $0.count, 0, $0.count) } }
        return SymmetricKey(data: key)
    }

    private static func random(_ count: Int) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        guard SecRandomCopyBytes(kSecRandomDefault, count, &bytes) == errSecSuccess else {
            throw AppFailure("Não foi possível gerar dados aleatórios para o backup.")
        }
        return Data(bytes)
    }
}
