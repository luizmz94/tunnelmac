@testable import VPNApp
import Foundation
import AppKit
import SwiftUI
import VPNHelperShared

/// Backup round trip through the real Keychain, with throwaway services and folders:
/// export from one "Mac" (store + password service) and import into another.
@MainActor
enum BackupLocalTests {
    static func run() -> Int {
        var failures = 0
        func test(_ name: String, _ block: () throws -> Void) {
            do { try block(); print("PASS: Backup: \(name)") }
            catch { failures += 1; print("FAIL: Backup: \(name): \(error.localizedDescription)") }
        }
        let require = TestSupport.require
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("VPNGUI-backup-tests-\(UUID())")
        defer { try? FileManager.default.removeItem(at: root) }
        let source = PasswordStore(service: "com.luiz.vpngui.tests.backup-source.\(UUID())")
        let target = PasswordStore(service: "com.luiz.vpngui.tests.backup-target.\(UUID())")
        let cookies = SAMLCookieStore(service: "com.luiz.vpngui.tests.backup-cookie.\(UUID())")
        var created: [UUID] = []
        defer { for id in created { try? source.delete(id); try? target.delete(id); try? cookies.delete(id) } }

        func wait<T>(_ operation: @escaping @MainActor () async throws -> T) throws -> T {
            var result: Result<T, Error>?
            Task { @MainActor in
                do { result = .success(try await operation()) } catch { result = .failure(error) }
            }
            guard TestSupport.spin(60, until: { result != nil }), let result else { throw AppFailure("Operação assíncrona sem resposta") }
            return try result.get()
        }

        test("Exportar de um Mac e importar em outro: senhas, perfis, substituição por identificador e preferências") {
            let storeA = try JSONStore(directory: root.appendingPathComponent("a"))
            let office = Connection(name: "Escritório", server: "vpn.exemplo.invalid", port: 10443, realm: "r1", username: "ana")
            let home = Connection(name: "Casa", kind: .wireguard,
                                  wireGuard: WireGuardSummary(endpoints: ["203.0.113.10:51820"], addresses: [], dns: [], allowedIPs: ["0.0.0.0/0"], fullTunnel: true, publicKey: WireGuardTests.publicKey))
            let saml = Connection(name: "SSO", server: "sso.exemplo.invalid", authentication: .saml)
            created += [office.id, home.id, saml.id]
            let saveA = ConnectionSave(store: storeA, passwords: source, cookies: cookies)
            var dataA = try saveA.run(current: SavedData(), connection: office, password: "s3nha;#\"x", openVPNProfile: nil, wireGuardProfile: nil)
            dataA = try saveA.run(current: dataA, connection: home, password: "", openVPNProfile: nil, wireGuardProfile: WireGuardTests.fullTunnel)
            dataA = try saveA.run(current: dataA, connection: saml, password: "", openVPNProfile: nil, wireGuardProfile: nil)
            let modelA = AppModel(store: storeA, passwords: source, cookies: cookies, service: HelperTests.readyService())
            let preferencesA = AppPreferences.disposable()
            preferencesA.showMenuBarIcon = false
            preferencesA.addCustomDNS(try InternetDNSOption.custom(name: "Casa", servers: "192.0.2.53"))
            let sealed = try wait { try await modelA.exportBackupAsync(password: "Vq7-Lago-Dourado-29!", preferences: preferencesA.backup) }
            for secret in ["s3nha", WireGuardTests.privateKey, "vpn.exemplo.invalid"] {
                try require(sealed.range(of: Data(secret.utf8)) == nil, "Texto em claro no backup: \(secret)")
            }

            // The other Mac already has an older copy of "Escritório" and one connection of its own.
            let storeB = try JSONStore(directory: root.appendingPathComponent("b"))
            var stale = office
            stale.name = "Escritório antigo"; stale.username = "velho"
            let local = Connection(name: "Só aqui", server: "local.exemplo.invalid", username: "bia")
            created.append(local.id)
            let saveB = ConnectionSave(store: storeB, passwords: target, cookies: cookies)
            var dataB = try saveB.run(current: SavedData(), connection: stale, password: "antiga", openVPNProfile: nil, wireGuardProfile: nil)
            dataB = try saveB.run(current: dataB, connection: local, password: "local", openVPNProfile: nil, wireGuardProfile: nil)
            let modelB = AppModel(store: storeB, passwords: target, cookies: cookies, service: HelperTests.readyService())

            try require((try? wait { try await modelB.openBackupAsync(sealed, password: "senha errada") }) == nil, "Senha errada abriu o backup")
            let tooWeak = String(repeating: "senha1", count: 3) // Common word, repeated: rated very weak.
            try require((try? wait { try await modelA.exportBackupAsync(password: tooWeak, preferences: nil) }) == nil, "Senha fraca exportou")
            let plan = try wait { try await modelB.openBackupAsync(sealed, password: "Vq7-Lago-Dourado-29!") }
            try require(plan.replacing == ["Escritório"] && plan.adding == ["Casa", "SSO"], "Plano: \(plan.replacing) \(plan.adding)")
            try require(plan.missingPasswords.isEmpty && plan.missingCertificates.isEmpty && plan.hasPreferences, "Plano com pendências inesperadas")
            try require(try storeB.load().connections.map(\.name) == ["Escritório antigo", "Só aqui"], "Abrir o backup já gravou dados")

            try wait { try await modelB.importBackupAsync(plan) }
            try require(modelB.data.connections.map(\.name) == ["Escritório", "Só aqui", "Casa", "SSO"], "Conexões: \(modelB.data.connections.map(\.name))")
            try require(try storeB.load().connections == modelB.data.connections, "Arquivo diferente da interface")
            try require(modelB.data.connections.first == office, "Conexão substituída difere do original")
            try require(try target.read(office.id) == "s3nha;#\"x" && target.read(local.id) == "local", "Senhas no Keychain")
            try require(try target.read(saml.id) == nil && target.read(home.id) == nil, "Senha gravada para conexão sem senha")
            try require(try ProfileStore.wireGuard(storeB).read(home.id) == WireGuardTests.fullTunnel, "Perfil WireGuard")
            let mode = try FileManager.default.attributesOfItem(atPath: ProfileStore.wireGuard(storeB).file(home.id).path)[.posixPermissions] as? NSNumber
            try require(mode?.intValue == 0o600, "Perfil importado sem 0600")

            let preferencesB = AppPreferences.disposable()
            preferencesB.restore(try plan.payload.preferences.unwrap())
            try require(!preferencesB.showMenuBarIcon && preferencesB.internetDNSServers == ["192.0.2.53"], "Preferências não aplicadas")
            try require(preferencesB.customInternetDNS == preferencesA.customInternetDNS, "DNS personalizado diferente")
        }

        test("Backup sem senha salva: importa e pede a senha ao conectar; preferências inválidas descartadas") {
            let store = try JSONStore(directory: root.appendingPathComponent("c"))
            let office = Connection(name: "Sem senha", server: "vpn.exemplo.invalid", username: "ana")
            created.append(office.id)
            var preferences = AppPreferences.disposable().backup
            preferences.customInternetDNS = [InternetDNSOption(id: "x", name: "Ruim", servers: ["dns.invalid"]),
                                             InternetDNSOption(id: "google", name: "Falso", servers: ["192.0.2.1"])]
            preferences.internetDNSSelection = "x"
            let payload = BackupPayload(connections: [.init(connection: office)], preferences: preferences)
            let sealed = try BackupCipher.seal(JSONEncoder().encode(payload), password: "Vq7-Lago-Dourado-29!")
            let model = AppModel(store: store, passwords: target, cookies: cookies, service: HelperTests.readyService())
            let plan = try wait { try await model.openBackupAsync(sealed, password: "Vq7-Lago-Dourado-29!") }
            try require(plan.missingPasswords == ["Sem senha"], "Senha ausente não sinalizada")
            try wait { try await model.importBackupAsync(plan) }
            try require(try target.read(office.id) == nil && model.data.connections == [office], "Importação sem senha")
            let restored = AppPreferences.disposable()
            restored.restore(try plan.payload.preferences.unwrap())
            try require(restored.customInternetDNS.isEmpty && restored.internetDNSServers == nil, "DNS inválido ou preset falso aceito")
        }
        test("Renderização fora da tela: exportar e medidor de força, claro e escuro") {
            let output = Bundle.main.bundleURL.deletingLastPathComponent().appendingPathComponent("ui-review/backup", isDirectory: true)
            try? FileManager.default.removeItem(at: output)
            try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)
            let model = AppModel(store: try JSONStore(directory: root.appendingPathComponent("render")), passwords: target, cookies: cookies,
                                 service: HelperTests.readyService())
            let meters = VStack(alignment: .leading, spacing: 14) {
                ForEach(["senha123", "Gatinho2024", "Cachorro-Amarelo-2024", "Gato azul come 37 bananas!", BackupPassword.generate()], id: \.self) { sample in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(sample).font(.caption.monospaced())
                        PasswordStrengthMeter(evaluation: BackupPassword.evaluate(sample))
                    }
                }
            }.padding(20)
            for (appearance, suffix) in [(NSAppearance.Name.aqua, "light"), (.darkAqua, "dark")] {
                try UIPreviewTests.snapshot(ExportBackupSheet(model: model, preferences: AppPreferences.disposable()) { _ in },
                                            size: NSSize(width: 460, height: 360), appearance: appearance,
                                            to: output.appendingPathComponent("export-\(suffix).png"))
                try UIPreviewTests.snapshot(meters, size: NSSize(width: 460, height: 380), appearance: appearance,
                                            to: output.appendingPathComponent("strength-\(suffix).png"))
            }
        }
        return failures
    }
}

private extension Optional {
    func unwrap() throws -> Wrapped {
        guard let self else { throw AppFailure("Valor ausente") }
        return self
    }
}
