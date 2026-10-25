@testable import VPNApp
import Foundation
import Security
import VPNHelperShared

/// Client certificate (Fortinet): PEM rules, config lines, Keychain import/export with a
/// throwaway keychain, saved-profile compatibility and the connect flow.
@MainActor enum ClientCertificateTests {
    /// RSA-2048, EKU clientAuth, CN tunnelmac-client-fixture, password "fixture-p12" (test only).
    static let p12Base64 = [
        "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",
        "EHvWIpT1UxTAddU4AXD5Jq8CAggA",
    ].joined()
    static let fixtureSHA1 = "d172d8b767664330bb15b845f7777af1212e81a2"
    static let certificatePEM = """
    -----BEGIN CERTIFICATE-----
    MIIDKjCCAhKgAwIBAgIUP1VFaNJLO59wPBuxBAjs4iblbF8wDQYJKoZIhvcNAQEL
    BQAwIzEhMB8GA1UEAwwYdHVubmVsbWFjLWNsaWVudC1maXh0dXJlMCAXDTI2MTAy
    NDE5MTQ0MFoYDzIxMjYwOTMwMTkxNDQwWjAjMSEwHwYDVQQDDBh0dW5uZWxtYWMt
    Y2xpZW50LWZpeHR1cmUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCp
    xtDmJWc6UCqAzdnvHYvKkVJ0jtJYxwfN5MrvewXuMXSq05rm9hDsuCSO8ecIfzNL
    tV9G4BMrwE85fU6P/qXvT+w+v7QOWBW6hz2tQTewS8B38m2fnZTptSEGRab8xwLm
    2m25rfdJc5MlR/T9S9/MeGVI4WvzPkmTN7h/mKG58m49CH/SXAlcEK21WXByc7RQ
    S1apebnbmuuEJUaWzWl7GqEhCW6eDRKb4A651QpK7EVO6dKkq6HNWsHTHkBZVF3r
    U3PRXItafMIkWNSyOZtJHbHweXXMNEWRBfyB+6Xcnhd5i5ifvjDdwbcafs27m2y9
    wjdVBny1QtH3pKCaNgqZAgMBAAGjVDBSMB0GA1UdDgQWBBTFatS200zMmWdmzkx3
    ftOw+JHuEzAPBgNVHRMBAf8EBTADAQH/MBMGA1UdJQQMMAoGCCsGAQUFBwMCMAsG
    A1UdDwQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAQEAUHqZEn3UVZLKCAMwS3AR8U7q
    SJfN+jRqlrfVp3icd6mEVNaIbqGbfP+F6/5+eOqh0/OxEsVSypHiauYxgPLOQcrv
    JXBcho3CBpvuJigvRMb5f4vQwC+Ha881IBVL72pDJ7HiD3nH2hE1jIkdhyNBwo/d
    gLS/2QmXp5tOolAd50bNRTKSA1LGOoqVOPgnKZBHDHBIvEKbYArR7JYtw88w8KBa
    Oh3DAcwbZbYY069mEIzOjQfsx18CLxAxVazNSt4PKuDPnit9Tb+10r/vSCAdvskt
    WNoIAGdDfboIjGf0/xOJ4LogjZsZtVyjZU/q0H7fVKKpsXfRzTMWe5Zv5DzsuA==
    -----END CERTIFICATE-----
    """
    /// Structurally valid stand-in for an exported key (never decrypted by the checks).
    static let keyPEM = PEM.encode(Data((0..<96).map { UInt8($0) }), label: "ENCRYPTED PRIVATE KEY")
    static let passphrase = String(repeating: "ab", count: ClientCertificate.passphraseBytes)
    static var stub: ClientCertificate { ClientCertificate(certificate: certificatePEM, key: keyPEM, passphrase: passphrase) }

    static func run() -> Int {
        var failures = 0
        func test(_ name: String, _ block: () throws -> Void) {
            do { try block(); print("PASS: Certificado do cliente: \(name)") }
            catch { failures += 1; print("FAIL: Certificado do cliente: \(name): \(error.localizedDescription)") }
        }
        let require = TestSupport.require

        test("PEM: canônico, só os rótulos esperados, cadeia limitada e senha temporária em hex") {
            let ok = try stub.validated()
            try require(ok.certificate.hasPrefix("-----BEGIN CERTIFICATE-----\n") && ok.key.hasPrefix("-----BEGIN ENCRYPTED PRIVATE KEY-----\n"), "PEM não canônico")
            let bad: [ClientCertificate] = [
                ClientCertificate(certificate: "", key: keyPEM, passphrase: passphrase),
                ClientCertificate(certificate: certificatePEM + "\nuser-key = /etc/x", key: keyPEM, passphrase: passphrase),
                ClientCertificate(certificate: PEM.encode(Data([1, 2, 3]), label: "CERTIFICATE"), key: keyPEM, passphrase: passphrase),
                ClientCertificate(certificate: certificatePEM, key: PEM.encode(Data([1, 2, 3]), label: "PRIVATE KEY"), passphrase: passphrase),
                ClientCertificate(certificate: certificatePEM, key: keyPEM + keyPEM, passphrase: passphrase),
                ClientCertificate(certificate: certificatePEM, key: keyPEM, passphrase: "short"),
                ClientCertificate(certificate: certificatePEM, key: keyPEM, passphrase: String(repeating: "z", count: ClientCertificate.passphraseLength)),
                ClientCertificate(certificate: certificatePEM, key: keyPEM, passphrase: String(repeating: "ab", count: 32)),
                ClientCertificate(certificate: String(repeating: certificatePEM + "\n", count: 9), key: keyPEM, passphrase: passphrase),
                ClientCertificate(certificate: certificatePEM.replacingOccurrences(of: "-----END CERTIFICATE-----", with: ""), key: keyPEM, passphrase: passphrase)]
            for (index, value) in bad.enumerated() {
                try require((try? value.validated()) == nil, "Certificado inválido #\(index) aceito")
            }
        }

        test("Configuração: user-cert/user-key/pem-passphrase só com caminhos do helper e valores de uma linha") {
            let files = ClientCertificateFiles(certificatePath: "/var/db/x/a.crt", keyPath: "/var/db/x/a.key", passphrase: passphrase)
            let config = try ConfigRenderer.render(host: "vpn.invalid", port: 443, username: "u", password: "p", trustedCertificate: "", clientCertificate: files)
            try require(config.contains("user-cert = /var/db/x/a.crt\nuser-key = /var/db/x/a.key\npem-passphrase = \(passphrase)\n"), "Linhas do certificado ausentes")
            for broken in [ClientCertificateFiles(certificatePath: "/a\nset-dns = 0", keyPath: "/b", passphrase: passphrase),
                           ClientCertificateFiles(certificatePath: "a.crt", keyPath: "/b", passphrase: passphrase),
                           ClientCertificateFiles(certificatePath: "/a", keyPath: "/b", passphrase: "x\npppd-plugin = /x")] {
                try require((try? ConfigRenderer.render(host: "vpn.invalid", port: 443, username: "u", password: nil, trustedCertificate: "", clientCertificate: broken)) == nil, "Caminho inválido aceito")
            }
            let request = ConnectionRequest(connectionID: UUID(), host: "vpn.invalid", port: 443, username: "u", authentication: .password,
                                            trustedCertificate: "", password: "p", mode: .none, cookie: nil,
                                            clientCertificate: ClientCertificate(certificate: "x", key: keyPEM, passphrase: passphrase))
            try require((try? request.validatedPlan(capabilities: RuntimeCapabilities(help: SAMLCookieTests.help))) == nil, "Requisição com certificado inválido aceita")
        }

        test("Keychain: importa .p12, lista só identidades de cliente e exporta a chave cifrada que confere com o certificado") {
            let path = FileManager.default.temporaryDirectory.appendingPathComponent("tunnelmac-cert-\(UUID()).keychain").path
            var keychain: SecKeychain?
            let password = "kc-\(UUID())"
            guard SecKeychainCreate(path, UInt32(password.utf8.count), password, false, nil, &keychain) == errSecSuccess, let keychain else {
                throw TestSupport.Failure("Keychain temporário não criado")
            }
            defer { SecKeychainDelete(keychain); ClientIdentities.searchList = nil }
            ClientIdentities.searchList = [keychain]
            let data = Data(base64Encoded: p12Base64)!
            do { _ = try ClientIdentities.importPKCS12(data, password: "errada"); throw TestSupport.Failure("Senha errada aceita") }
            catch let failure as AppFailure { try require(failure.localizedDescription.contains("Senha"), "Erro de senha inesperado: \(failure.localizedDescription)") }
            let imported = try ClientIdentities.importPKCS12(data, password: "fixture-p12")
            try require(imported.sha1 == fixtureSHA1 && imported.name == "tunnelmac-client-fixture" && !imported.expired, "Identidade importada inesperada: \(imported)")
            let listed = ClientIdentities.list()
            try require(listed.map(\.sha1) == [fixtureSHA1], "Lista inesperada: \(listed)")
            let exported = try ClientIdentities.export(imported.reference)
            try require(exported.key.hasPrefix("-----BEGIN ENCRYPTED PRIVATE KEY-----") && exported.passphrase.count == ClientCertificate.passphraseLength && exported.passphrase.count <= 31,
                        "Chave exportada sem cifra ou senha maior que o limite do openfortivpn")
            try require(try ClientIdentities.export(imported.reference).passphrase != exported.passphrase, "Senha temporária repetida")
            // The encrypted key opens with the passphrase and matches the certificate's public key.
            var parameters = SecItemImportExportKeyParameters()
            parameters.version = UInt32(SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION)
            parameters.passphrase = Unmanaged.passUnretained(exported.passphrase as CFString)
            var format = SecExternalFormat.formatWrappedPKCS8, type = SecExternalItemType.itemTypePrivateKey
            var items: CFArray?
            let status = SecItemImport(Data(exported.key.utf8) as CFData, nil, &format, &type, [], &parameters, nil, &items)
            guard status == errSecSuccess, let key = (items as? [SecKey])?.first, let publicKey = SecKeyCopyPublicKey(key) else {
                throw TestSupport.Failure("Chave exportada não abriu com a senha (\(status))")
            }
            let der = try PEM.blocks(exported.certificate, label: "CERTIFICATE")
            guard let certificate = SecCertificateCreateWithData(nil, der[0] as CFData), let certificateKey = SecCertificateCopyKey(certificate) else {
                throw TestSupport.Failure("Certificado exportado inválido")
            }
            try require(SecKeyCopyExternalRepresentation(publicKey, nil) as Data? == SecKeyCopyExternalRepresentation(certificateKey, nil) as Data?,
                        "Chave exportada não corresponde ao certificado")
            do { _ = try ClientIdentities.export(ClientCertificateReference(sha1: String(repeating: "0", count: 40), name: "Sumido")); throw TestSupport.Failure("Certificado ausente exportado") }
            catch let failure as AppFailure { try require(failure.localizedDescription.contains("não foi encontrado"), "Erro inesperado") }
        }

        test("Cadastro: perfis antigos sem certificado continuam abrindo; OpenVPN/WireGuard nunca levam certificado") {
            var c = Connection(name: "Gateway", server: "vpn.invalid", port: 10443, username: "u", authentication: .password, trustedCertificate: "")
            c.clientCertificate = ClientCertificateReference(sha1: fixtureSHA1, name: "fixture")
            let encoded = try JSONEncoder().encode(c)
            try require(try JSONDecoder().decode(Connection.self, from: encoded).clientCertificate == c.clientCertificate, "Referência não salva")
            var legacy = try JSONSerialization.jsonObject(with: encoded) as! [String: Any]
            legacy.removeValue(forKey: "clientCertificate")
            let old = try JSONDecoder().decode(Connection.self, from: JSONSerialization.data(withJSONObject: legacy))
            try require(old.clientCertificate == nil, "Perfil antigo com certificado")
            try require(try c.validated().clientCertificate == c.clientCertificate, "Validação removeu o certificado")
            var broken = c
            broken.clientCertificate?.sha1 = "xyz"
            try require((try? broken.validated()) == nil, "Hash inválido aceito")
            var other = c
            other.kind = .wireguard
            other.wireGuard = WireGuardSummary(endpoints: [], addresses: [], dns: [], allowedIPs: [], fullTunnel: false, publicKey: "")
            try require((try? other.validated())?.clientCertificate == nil, "WireGuard levou certificado")
        }

        test("Conectar: certificado exportado vai na requisição; recusa do Keychain falha sem iniciar nem repetir") {
            let root = FileManager.default.temporaryDirectory.appendingPathComponent("VPNGUI-cert-tests-\(UUID())")
            defer { try? FileManager.default.removeItem(at: root) }
            let passwords = PasswordStore(service: "com.luiz.vpngui.tests.cert-password.\(UUID())")
            let model = AppModel(store: try JSONStore(directory: root), passwords: passwords,
                                 cookies: SAMLCookieStore(service: "com.luiz.vpngui.tests.cert-cookie.\(UUID())"),
                                 service: HelperTests.readyService())
            let recorder = SAMLCookieTests.harness(model)
            var c = Connection(name: "Gateway", server: "vpn.invalid", port: 10443, username: "u", authentication: .password, trustedCertificate: "")
            c.clientCertificate = ClientCertificateReference(sha1: fixtureSHA1, name: "fixture")
            defer { try? passwords.delete(c.id) }
            try model.save(c, password: "fixturePASSvalue42")
            var exported: [String] = []
            model.manager.certificateExporter = { reference in exported.append(reference.sha1); return stub }
            model.connect(c)
            let session = model.manager.session(c.id)
            try require(TestSupport.spin(5) { recorder.requests.count == 1 }, "Conexão com certificado não iniciou: \(session.logs.suffix(2))")
            try require(recorder.requests[0].clientCertificate == stub && exported == [fixtureSHA1], "Certificado não enviado")
            // A second cadastro: the harness never reports the first session's exit.
            var d = c
            d.id = UUID()
            defer { try? passwords.delete(d.id) }
            try model.save(d, password: "fixturePASSvalue42")
            model.manager.certificateExporter = { _ in throw AppFailure("acesso à chave negado no Keychain.") }
            model.connect(d)
            let refused = model.manager.session(d.id)
            try require(TestSupport.spin(5) { refused.state == .failed }, "Recusa do Keychain não falhou: \(refused.state)")
            try require(recorder.requests.count == 1 && refused.logs.contains { $0.contains("negado") }, "Recusa iniciou sessão ou sumiu do log")
            model.manager.disconnect(c.id)
        }
        return failures
    }
}
