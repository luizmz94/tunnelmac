import XCTest
import VPNHelperShared
@testable import VPNApp

/// Backup container and payload rules; no Keychain (the round trip through it is in the local checks).
final class BackupTests: XCTestCase {
    /// Lowest accepted cost keeps the suite fast; the format is the same.
    let iterations = BackupCipher.acceptedIterations.lowerBound
    static let wireGuard = """
    [Interface]
    PrivateKey = dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=
    Address = 10.8.0.3/32

    [Peer]
    PublicKey = 3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08=
    AllowedIPs = 10.0.0.0/8
    Endpoint = 203.0.113.10:51820
    """

    func payload(_ entries: [BackupPayload.Entry]) throws -> Data {
        try BackupCipher.seal(JSONEncoder().encode(BackupPayload(connections: entries)), password: "correct horse", iterations: iterations)
    }

    func testRoundTripAndWrongPassword() throws {
        let plaintext = Data("segredo".utf8)
        let sealed = try BackupCipher.seal(plaintext, password: "correct horse", iterations: iterations)
        XCTAssertEqual(sealed.prefix(8), Data("TMBACKUP".utf8))
        XCTAssertNil(sealed.range(of: plaintext), "Conteúdo em claro no arquivo")
        XCTAssertEqual(try BackupCipher.open(sealed, password: "correct horse"), plaintext)
        XCTAssertThrowsError(try BackupCipher.open(sealed, password: "correct horsf"))
        XCTAssertThrowsError(try BackupCipher.open(sealed, password: ""))
        let again = try BackupCipher.seal(plaintext, password: "correct horse", iterations: iterations)
        XCTAssertNotEqual(sealed, again, "Sal ou nonce repetidos")
    }

    func testPasswordIsNormalized() throws {
        let composed = "senha-çãé-123", decomposed = composed.decomposedStringWithCanonicalMapping
        XCTAssertNotEqual(Array(composed.utf8), Array(decomposed.utf8))
        let sealed = try BackupCipher.seal(Data("x".utf8), password: composed, iterations: iterations)
        XCTAssertEqual(try BackupCipher.open(sealed, password: decomposed), Data("x".utf8))
    }

    func testShortPasswordRejected() {
        XCTAssertThrowsError(try BackupCipher.seal(Data(), password: "1234567", iterations: iterations))
    }

    func testEveryTamperedByteIsRejected() throws {
        let sealed = try BackupCipher.seal(Data("conteúdo".utf8), password: "correct horse", iterations: iterations)
        // Header (version, iterations, salt, nonce) is authenticated just like the body and tag.
        for index in 0..<sealed.count {
            var changed = sealed
            changed[index] ^= 0x01
            XCTAssertThrowsError(try BackupCipher.open(changed, password: "correct horse"), "Byte \(index) alterado foi aceito")
        }
        XCTAssertThrowsError(try BackupCipher.open(sealed.dropLast(), password: "correct horse"))
        XCTAssertThrowsError(try BackupCipher.open(Data("not a backup".utf8), password: "correct horse"))
    }

    func testHeaderParametersAreBounded() throws {
        var sealed = try BackupCipher.seal(Data("x".utf8), password: "correct horse", iterations: iterations)
        sealed.replaceSubrange(9..<13, with: [0xff, 0xff, 0xff, 0xff]) // ~4 billion iterations would stall the app.
        XCTAssertThrowsError(try BackupCipher.open(sealed, password: "correct horse")) {
            XCTAssertEqual($0.localizedDescription, "Backup com parâmetros de proteção inválidos.")
        }
        sealed[8] = 2
        XCTAssertThrowsError(try BackupCipher.open(sealed, password: "correct horse")) {
            XCTAssertTrue($0.localizedDescription.contains("versão mais nova"))
        }
    }

    func testPayloadIsValidatedBeforeImport() throws {
        let fortinet = Connection(name: "Escritório", server: "vpn.example.invalid", port: 443, username: "ana")
        let opened = try ConfigBackup.open(payload([.init(connection: fortinet, password: "senha")]), password: "correct horse")
        XCTAssertEqual(opened.connections.map(\.connection), [fortinet])
        XCTAssertEqual(opened.connections.first?.password, "senha")

        let wireGuard = Connection(name: "Casa", kind: .wireguard,
                                   wireGuard: WireGuardSummary(endpoints: [], addresses: [], dns: [], allowedIPs: [], fullTunnel: false, publicKey: ""))
        XCTAssertNoThrow(try ConfigBackup.open(payload([.init(connection: wireGuard, wireGuardProfile: Self.wireGuard)]), password: "correct horse"))
        let invalid: [[BackupPayload.Entry]] = [
            [.init(connection: wireGuard)], // Profile missing.
            [.init(connection: wireGuard, wireGuardProfile: "[Interface]\nPostUp = rm -rf /\n")],
            [.init(connection: fortinet), .init(connection: fortinet)], // Duplicate identifiers.
            [.init(connection: Connection(name: "X", server: "vpn.invalid\nset-dns = 1", username: "a"))],
            [.init(connection: fortinet, password: "a\nb")],
        ]
        for entries in invalid {
            XCTAssertThrowsError(try ConfigBackup.open(payload(entries), password: "correct horse"))
        }
    }

    func testPlanSeparatesNewReplacedAndMissingMaterial() throws {
        let existing = Connection(name: "Antiga", server: "a.invalid", username: "u")
        var withCertificate = Connection(name: "Cert", server: "b.invalid", username: "u")
        withCertificate.clientCertificate = ClientCertificateReference(sha1: String(repeating: "ab", count: 20), name: "Meu certificado")
        let saml = Connection(name: "SAML", server: "c.invalid", authentication: .saml)
        let payload = BackupPayload(connections: [.init(connection: existing, password: "x"), .init(connection: withCertificate), .init(connection: saml)])
        let plan = ConfigBackup.plan(payload, current: SavedData(connections: [existing]), certificates: [])
        XCTAssertEqual(plan.replacing, ["Antiga"])
        XCTAssertEqual(plan.adding, ["Cert", "SAML"])
        XCTAssertEqual(plan.missingPasswords, ["Cert"], "SAML não usa senha")
        XCTAssertEqual(plan.missingCertificates, ["Cert (Meu certificado)"])
        let present = ConfigBackup.plan(payload, current: SavedData(), certificates: [String(repeating: "ab", count: 20)])
        XCTAssertTrue(present.missingCertificates.isEmpty)
    }
}

final class BackupPasswordTests: XCTestCase {
    func strength(_ password: String) -> BackupPassword.Strength { BackupPassword.evaluate(password).strength }

    func testWeakPasswordsAreRefused() {
        for weak in ["", "12345678", "password", "senha123", "Senha@2024", "aaaaaaaaaaaaaaaa", "abcdefghijklmnop", "qwertyuiopasdfgh",
                     "1234567890123456", "P@ssw0rdP@ssw0rd", "tunnelmacbackup1", "S3nh@Forte!", "Ab1!Ab1!Ab1", "Gato-azul-37", "Cachorro-Amarelo-2024", "MARIANA-SILVA-1990"] {
            XCTAssertFalse(BackupPassword.evaluate(weak).acceptable, "Senha fraca aceita: \(weak) (\(strength(weak).title))")
            XCTAssertThrowsError(try BackupPassword.check(weak))
        }
        XCTAssertLessThanOrEqual(strength("Xk9#mQ2!"), .fair, "Curta demais para ser forte")
        XCTAssertFalse(BackupPassword.evaluate("senha").hints.isEmpty)
    }

    func testStrongPasswordsAreAccepted() {
        for strong in ["Vq7-Lago-Dourado-29!", "correct-Horse-battery-staple-9", "mT4#vL9@qZ2!wR7$", "Gato azul come 37 bananas!"] {
            XCTAssertTrue(BackupPassword.evaluate(strong).acceptable, "Senha forte recusada: \(strong) (\(strength(strong).title))")
            XCTAssertNoThrow(try BackupPassword.check(strong))
        }
    }

    func testGeneratedPasswordsLookLikeMacOSSuggestions() {
        var seen = Set<String>()
        for _ in 0..<200 {
            let password = BackupPassword.generate()
            let groups = password.split(separator: "-")
            XCTAssertEqual(groups.count, 3)
            XCTAssertTrue(groups.allSatisfy { $0.count == 6 && $0.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber) } }, password)
            XCTAssertTrue(password.contains { $0.isUppercase } && password.contains { $0.isNumber } && password.contains { $0.isLowercase }, password)
            XCTAssertFalse(password.contains { "0O1lI".contains($0) }, "Caractere ambíguo: \(password)")
            XCTAssertTrue(BackupPassword.evaluate(password).acceptable, password)
            seen.insert(password)
        }
        XCTAssertEqual(seen.count, 200, "Senhas geradas repetidas")
    }
}
