import Foundation

/// One durable roll-forward operation. Password staging stays in a separate Keychain
/// service; the journal contains only the same private profile material as ProfileStore.
/// No live resource is changed until a prepared operation is durably recorded.
struct ConnectionTransaction {
    struct Secrets {
        var readStaged: (UUID) throws -> String?
        var writeStaged: (String, UUID) throws -> Void
        var deleteStaged: (UUID) throws -> Void
        var writePassword: (String, UUID) throws -> Void
        var deletePassword: (UUID) throws -> Void
        var deleteCookie: (UUID) throws -> Void
    }
    struct Operation: Codable {
        var committed: Bool = false
        var id: UUID
        var updated: SavedData
        var deleting: Bool
        var prepared: Bool
        var hasPassword: Bool
        var openVPN: String?
        var wireGuard: String?
    }
    let store: JSONStore
    private let secrets: Secrets
    private let checkpoint: (String) throws -> Void
    init(store: JSONStore, passwords: PasswordStore, cookies: SAMLCookieStore,
         secrets: Secrets? = nil, checkpoint: @escaping (String) throws -> Void = { _ in }) {
        self.store = store; self.checkpoint = checkpoint
        let staging = PasswordStore(service: passwords.service + ".transaction")
        self.secrets = secrets ?? Secrets(readStaged: staging.read,
            writeStaged: { try staging.write($0, id: $1) }, deleteStaged: staging.delete,
            writePassword: { try passwords.write($0, id: $1) }, deletePassword: passwords.delete,
            deleteCookie: cookies.delete)
    }
    private var journal: URL { store.directory.appendingPathComponent("pending-operation.json") }

    func save(connection: Connection, updated: SavedData, password: String?, openVPN: String?, wireGuard: String?) throws {
        try recover()
        _ = try store.encoded(updated) // Reject an unreadable-sized result before touching live resources.
        var op = Operation(id: connection.id, updated: updated, deleting: false, prepared: false,
                           hasPassword: password != nil, openVPN: openVPN, wireGuard: wireGuard)
        try write(op)
        try checkpoint("intent")
        if let password { try secrets.writeStaged(password, op.id) }
        else { try secrets.deleteStaged(op.id) }
        try checkpoint("staged")
        op.prepared = true
        try write(op)
        try checkpoint("prepared")
        try finish(op)
    }
    func delete(_ id: UUID, updated: SavedData) throws {
        try recover()
        _ = try store.encoded(updated)
        let op = Operation(id: id, updated: updated, deleting: true, prepared: true, hasPassword: false)
        try write(op)
        try checkpoint("prepared")
        try finish(op)
    }
    func recover() throws {
        guard FileManager.default.fileExists(atPath: journal.path) else { return }
        let op = try JSONDecoder().decode(Operation.self, from: BoundedFile.read(journal, limit: 8 * 1024 * 1024))
        if op.prepared { try finish(op) }
        else {
            try secrets.deleteStaged(op.id)
            try FileManager.default.removeItem(at: journal)
        }
    }
    private func write(_ op: Operation) throws { try BoundedFile.replace(journal, data: JSONEncoder().encode(op)) }
    private func finish(_ op: Operation) throws {
        do {
            if op.committed {
                try secrets.deleteStaged(op.id)
                try FileManager.default.removeItem(at: journal)
                return
            }
            let profiles = ProfileStore.openVPN(store), wg = ProfileStore.wireGuard(store)
            if !op.deleting {
                if let text = op.openVPN { try profiles.write(text, id: op.id) }
                if let text = op.wireGuard { try wg.write(text, id: op.id) }
                try checkpoint("profiles")
                if op.hasPassword {
                    guard let password = try secrets.readStaged(op.id) else { throw AppFailure(String(localized: "Senha pendente não encontrada; recuperação exige intervenção.")) }
                    try secrets.writePassword(password, op.id)
                } else { try secrets.deletePassword(op.id) }
            }
            try checkpoint("credentials")
            // Cookie invalidation is idempotent, including recovery after an interrupted save.
            let old = try store.load().connections.first { $0.id == op.id }
            let next = op.updated.connections.first { $0.id == op.id }
            if op.deleting || old.map(SAMLCookieIdentity.init) != next.map(SAMLCookieIdentity.init) { try secrets.deleteCookie(op.id) }
            if let next, !op.deleting {
                if !next.isOpenVPN { try profiles.delete(op.id) }
                if !next.isWireGuard { try wg.delete(op.id) }
            }
            if op.deleting {
                // Keep the visible connection until all secret material has been removed.
                try secrets.deleteCookie(op.id)
                try profiles.delete(op.id)
                try wg.delete(op.id)
                try secrets.deletePassword(op.id)
            }
            try checkpoint("cleanup")
            try store.save(op.updated)
            try checkpoint("json")
            var committed = op
            committed.committed = true
            try write(committed)
            try checkpoint("committed")
            try secrets.deleteStaged(op.id)
            try FileManager.default.removeItem(at: journal)
        } catch {
            throw AppFailure(String(localized: "Operação pendente de recuperação; os dados foram preservados. Reinicie o app para repetir: \(error.localizedDescription)"),
                             pendingRecovery: true)
        }
    }
}
