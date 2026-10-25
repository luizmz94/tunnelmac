import SwiftUI
import AppKit
import VPNHelperShared

@MainActor
final class AppModel: ObservableObject {
    @Published var data = SavedData()
    @Published var error: String?
    @Published var ready = false
    let manager = VPNManager()
    /// Display order for the window and the menu bar: by name as Finder sorts it
    /// (case, accents and numbers), then by server for equal names. Storage keeps its order.
    var sortedConnections: [Connection] {
        data.connections.sorted {
            switch $0.name.localizedStandardCompare($1.name) {
            case .orderedAscending: return true
            case .orderedDescending: return false
            case .orderedSame: return $0.endpoint.localizedStandardCompare($1.endpoint) == .orderedAscending
            }
        }
    }
    let passwords: PasswordStore
    let cookies: SAMLCookieStore
    /// Privileged service (SMAppService + authenticated XPC); the manager's transport.
    let service: ServiceController
    /// Called on a user Conectar (not on automatic reconnects). Must return at once:
    /// the update check it triggers never delays or changes the connection.
    var onUserConnect: (() -> Void)?
    private var store: JSONStore?
    /// Imported OpenVPN profiles, next to connections.json.
    private(set) var profiles: ProfileStore?
    /// Imported WireGuard profiles (with their private keys), next to connections.json.
    private(set) var wireGuardProfiles: ProfileStore?
    init(store suppliedStore: JSONStore? = nil, passwords: PasswordStore = PasswordStore(),
         cookies: SAMLCookieStore = SAMLCookieStore(), service: ServiceController? = nil) {
        self.passwords = passwords
        self.cookies = cookies
        self.service = service ?? .production()
        manager.cookies = cookies
        manager.transport = self.service
        self.service.manager = manager
        if let suppliedStore {
            do {
                try ConnectionTransaction(store: suppliedStore, passwords: passwords, cookies: cookies).recover()
                installLoaded(suppliedStore, data: try suppliedStore.load())
            } catch { self.error = "Falha ao ler os dados. O arquivo existente foi preservado. \(error.localizedDescription)" }
        } else {
            Task {
                do {
                    let (store, saved) = try await PersistenceIO.run {
                        let store = try JSONStore()
                        try ConnectionTransaction(store: store, passwords: passwords, cookies: cookies).recover()
                        return (store, try store.load())
                    }
                    installLoaded(store, data: saved)
                } catch { self.error = "Falha ao ler/recuperar os dados. Os arquivos foram preservados. \(error.localizedDescription)" }
            }
        }
        manager.retry = { [weak self] id in
            guard let self, let connection = self.data.connections.first(where: { $0.id == id }) else { return }
            self.connect(connection, retrying: true)
        }
    }
    private func installLoaded(_ store: JSONStore, data: SavedData) {
        self.store = store
        profiles = .openVPN(store)
        wireGuardProfiles = .wireGuard(store)
        self.data = data
        for connection in data.connections { _ = manager.session(connection.id) }
        ready = true
    }
    /// `openVPNProfile` is the normalized profile of a new import (or a replacement);
    /// nil keeps the profile already saved for this connection. `wireGuardProfile` likewise.
    func save(_ connection: Connection, password: String, openVPNProfile: String? = nil, wireGuardProfile: String? = nil) throws {
        guard ready, let store else { throw AppFailure("Os dados não foram carregados; o arquivo foi preservado.") }
        guard manager.sessions[connection.id]?.state.active != true else { throw AppFailure("Desconecte antes de editar.") }
        let updated = try ConnectionSave(store: store, passwords: passwords, cookies: cookies).run(
            current: data, connection: connection, password: password, openVPNProfile: openVPNProfile, wireGuardProfile: wireGuardProfile)
        let c = connection
        data = updated
        manager.session(c.id).authenticationRejected = false
        manager.session(c.id).digestFix = nil
    }
    @Published private(set) var writing = false
    func saveAsync(_ connection: Connection, password: String, openVPNProfile: String? = nil, wireGuardProfile: String? = nil) async throws {
        guard ready, let store, !writing else { throw AppFailure("Dados indisponíveis ou operação em andamento.") }
        guard manager.sessions[connection.id]?.state.active != true else { throw AppFailure("Desconecte antes de editar.") }
        writing = true
        defer { writing = false }
        let useCase = ConnectionSave(store: store, passwords: passwords, cookies: cookies)
        let current = data
        do {
            data = try await PersistenceIO.run {
                try useCase.run(current: current, connection: connection, password: password,
                                openVPNProfile: openVPNProfile, wireGuardProfile: wireGuardProfile)
            }
        } catch {
            if error.localizedDescription.hasPrefix("Operação pendente") { ready = false }
            throw error
        }
        manager.session(connection.id).authenticationRejected = false
        manager.session(connection.id).digestFix = nil
    }
    func deleteAsync(_ connection: Connection) async throws {
        guard ready, let store, !writing else { throw AppFailure("Dados indisponíveis ou operação em andamento.") }
        guard manager.sessions[connection.id]?.state.active != true else { throw AppFailure("Desconecte antes de excluir.") }
        writing = true
        defer { writing = false }
        var updated = data
        updated.connections.removeAll { $0.id == connection.id }
        let transaction = ConnectionTransaction(store: store, passwords: passwords, cookies: cookies)
        let snapshot = updated
        do { try await PersistenceIO.run { try transaction.delete(connection.id, updated: snapshot) } }
        catch { if error.localizedDescription.hasPrefix("Operação pendente") { ready = false }; throw error }
        data = updated
        manager.sessions.removeValue(forKey: connection.id)
    }
    /// Encrypted backup of every connection with its password and profile.
    func exportBackupAsync(password: String, preferences: BackupPreferences?) async throws -> Data {
        guard ready, let store, !writing else { throw AppFailure("Dados indisponíveis ou operação em andamento.") }
        let snapshot = data, passwords = passwords
        return try await PersistenceIO.run {
            try ConfigBackup.export(snapshot, store: store, passwords: passwords, preferences: preferences, password: password)
        }
    }
    /// Decrypts and validates a backup; nothing is written yet.
    func openBackupAsync(_ file: Data, password: String) async throws -> BackupImportPlan {
        let current = data
        return try await Task.detached {
            let payload = try ConfigBackup.open(file, password: password)
            let certificates = payload.connections.contains { $0.connection.clientCertificate != nil }
                ? Set(ClientIdentities.list().map { $0.sha1.lowercased() }) : []
            return ConfigBackup.plan(payload, current: current, certificates: certificates)
        }.value
    }
    /// Adds the backup's connections and replaces those with the same identifier; the rest stays.
    func importBackupAsync(_ plan: BackupImportPlan) async throws {
        guard ready, let store, !writing else { throw AppFailure("Dados indisponíveis ou operação em andamento.") }
        let ids = Set(plan.payload.connections.map(\.connection.id))
        if let active = data.connections.first(where: { ids.contains($0.id) && manager.sessions[$0.id]?.state.active == true }) {
            throw AppFailure("Desconecte \u{201C}\(active.name)\u{201D} antes de importar: o backup substitui essa conexão.")
        }
        writing = true
        defer { writing = false }
        let current = data, passwords = passwords, cookies = cookies, payload = plan.payload
        do {
            data = try await PersistenceIO.run {
                try ConfigBackup.apply(payload, current: current, store: store, passwords: passwords, cookies: cookies)
            }
        } catch let failure as BackupImportFailure {
            data = failure.saved
            refreshImported(ids)
            if failure.message.contains("Operação pendente") { ready = false }
            throw failure
        }
        refreshImported(ids)
    }
    private func refreshImported(_ ids: Set<UUID>) {
        for id in ids where data.connections.contains(where: { $0.id == id }) {
            let session = manager.session(id)
            session.authenticationRejected = false
            session.digestFix = nil
        }
    }
    func delete(_ connection: Connection) throws {
        guard ready, let store else { throw AppFailure("Os dados não foram carregados.") }
        guard manager.sessions[connection.id]?.state.active != true else { throw AppFailure("Desconecte antes de excluir.") }
        var updated = data
        updated.connections.removeAll { $0.id == connection.id }
        try ConnectionTransaction(store: store, passwords: passwords, cookies: cookies).delete(connection.id, updated: updated)
        data = updated
        manager.sessions.removeValue(forKey: connection.id)
    }
    func trustCertificateAsync(_ connection: Connection, digest: String) async throws {
        let session = manager.session(connection.id)
        guard ready, let store, !writing, !session.state.active, session.certificateValidationFailed,
              session.suggestedCertificate == digest else { throw AppFailure("O certificado sugerido não está mais disponível.") }
        var revised = connection
        revised.trustedCertificate = digest
        let next = revised
        let current = data, passwords = passwords, cookies = cookies
        writing = true
        do {
            data = try await PersistenceIO.run {
                let password = next.usesPassword ? try passwords.read(next.id) ?? "" : ""
                return try ConnectionSave(store: store, passwords: passwords, cookies: cookies).run(
                    current: current, connection: next, password: password, openVPNProfile: nil, wireGuardProfile: nil)
            }
        } catch {
            writing = false
            if error.localizedDescription.hasPrefix("Operação pendente") { ready = false }
            throw error
        }
        writing = false
        session.suggestedCertificate = nil
        connect(next)
    }
    func applyDigestFixAsync(_ connection: Connection, _ fix: OpenVPNCompatibility.DigestFix) async throws {
        guard ready, let store, !writing, connection.isOpenVPN, !manager.session(connection.id).state.active else {
            throw AppFailure("Desconecte antes de corrigir o perfil.")
        }
        writing = true
        let current = data, passwords = passwords, cookies = cookies
        do {
            data = try await PersistenceIO.run {
                let profile = try OpenVPNProfile.validated(ProfileStore.openVPN(store).read(connection.id))
                guard OpenVPNCompatibility.digestFix(for: profile) == fix else { throw AppFailure("A correção sugerida não se aplica mais ao perfil.") }
                let password = connection.usesPassword ? try passwords.read(connection.id) ?? "" : ""
                return try ConnectionSave(store: store, passwords: passwords, cookies: cookies).run(
                    current: current, connection: connection, password: password,
                    openVPNProfile: OpenVPNCompatibility.apply(fix, to: profile).text, wireGuardProfile: nil)
            }
        } catch {
            writing = false
            if error.localizedDescription.hasPrefix("Operação pendente") { ready = false }
            throw error
        }
        writing = false
        manager.session(connection.id).digestFix = nil
        connect(connection)
    }
    func trustCertificate(_ connection: Connection, digest: String) throws {
        let session = manager.session(connection.id)
        guard ready, let store, !session.state.active, session.certificateValidationFailed,
              session.suggestedCertificate == digest else { throw AppFailure("O certificado sugerido não está mais disponível.") }
        guard let index = data.connections.firstIndex(where: { $0.id == connection.id }) else { throw AppFailure("Conexão não encontrada.") }
        var updated = data
        updated.connections[index].trustedCertificate = digest
        _ = try updated.connections[index].validated()
        try store.save(updated) // Password stays in Keychain, untouched by certificate approval.
        try? cookies.delete(connection.id) // A new trusted certificate is a new gateway identity.
        data = updated
        session.suggestedCertificate = nil
        connect(updated.connections[index])
    }
    /// Rewrites only `auth RSA-SHAx` → `auth SHAx` in the app's copy of the profile, after the
    /// user confirmed it in the interface, then connects again. The original file is untouched.
    func applyDigestFix(_ connection: Connection, _ fix: OpenVPNCompatibility.DigestFix) throws {
        guard connection.isOpenVPN, let profiles, !manager.session(connection.id).state.active else {
            throw AppFailure("Desconecte antes de corrigir o perfil.")
        }
        let profile: OpenVPNProfile
        do { profile = try OpenVPNProfile.validated(try profiles.read(connection.id)) }
        catch let violation as RuleViolation { throw AppFailure(violation.message) }
        guard OpenVPNCompatibility.digestFix(for: profile) == fix else { throw AppFailure("A correção sugerida não se aplica mais a este perfil.") }
        try profiles.write(OpenVPNCompatibility.apply(fix, to: profile).text, id: connection.id)
        manager.session(connection.id).digestFix = nil
        connect(connection)
    }
    func connect(_ connection: Connection, retrying: Bool = false) {
        guard !writing else { error = "Aguarde a gravação dos dados antes de conectar."; return }
        guard ready else { error = "Aguarde a leitura dos dados."; return }
        if !retrying { onUserConnect?() }
        if manager.harness == nil {
            prepareConnection(connection, retrying: retrying)
            return
        }
        do {
            guard !manager.session(connection.id).authenticationRejected else {
                throw AppFailure("A última autenticação foi recusada. Edite a conexão e confirme as credenciais antes de tentar novamente, para evitar bloquear o usuário.")
            }
            let password = connection.usesPassword ? try passwords.read(connection.id) : nil
            if connection.usesPassword && (password?.isEmpty ?? true) {
                throw AppFailure("Senha não encontrada no Keychain. Edite a conexão e salve a senha novamente.")
            }
            var profile: String?
            if connection.isOpenVPN {
                guard let profiles else { throw AppFailure("Pasta de perfis indisponível.") }
                profile = try profiles.read(connection.id)
            }
            if connection.isWireGuard {
                guard let wireGuardProfiles else { throw AppFailure("Pasta de perfis indisponível.") }
                profile = try wireGuardProfiles.read(connection.id)
            }
            // Fail locally instead of looping on a service that cannot run the session.
            if service.blockNewSessions { throw AppFailure("O serviço está sendo removido ou atualizado; novas conexões aguardam.") }
            if manager.harness == nil, let reason = service.unavailableReason(for: connection.kind.runtime) { throw AppFailure(reason) }
            manager.connect(connection, password: password, retrying: retrying, profile: profile)
        } catch {
            if retrying { manager.retryFailed(connection.id, message: error.localizedDescription) }
            self.error = error.localizedDescription
        }
    }
    private func prepareConnection(_ connection: Connection, retrying: Bool) {
        let session = manager.session(connection.id)
        guard !session.state.active || (retrying && session.state == .reconnecting) else { return }
        guard !session.authenticationRejected else { error = "Confira as credenciais antes de tentar novamente."; return }
        if let reason = service.unavailableReason(for: connection.kind.runtime) { error = reason; return }
        session.begin(retrying: retrying, client: "Lendo credenciais e perfil")
        let generation = session.generation
        let passwords = passwords, profiles = profiles, wireGuardProfiles = wireGuardProfiles
        Task {
            do {
                let (password, profile) = try await Task.detached {
                    let password = connection.usesPassword ? try passwords.read(connection.id) : nil
                    if connection.usesPassword && (password?.isEmpty ?? true) { throw AppFailure("Senha não encontrada no Keychain. Edite e salve novamente.") }
                    let profile = connection.isOpenVPN ? try profiles?.read(connection.id)
                        : connection.isWireGuard ? try wireGuardProfiles?.read(connection.id) : nil
                    return (password, profile)
                }.value
                guard session.generation == generation, session.state.active else { return }
                if session.wantsDisconnect { manager.end(session, exit: 0); return }
                if let reason = service.unavailableReason(for: connection.kind.runtime) { throw AppFailure(reason) }
                session.state = .disconnected
                manager.connect(connection, password: password, retrying: retrying, profile: profile)
            } catch {
                guard session.generation == generation else { return }
                manager.end(session, exit: nil, error: error.localizedDescription)
                self.error = error.localizedDescription
            }
        }
    }

}

