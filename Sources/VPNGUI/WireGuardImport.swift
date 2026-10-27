import Foundation
import Darwin
import CryptoKit
import VPNHelperShared

/// Result of reading a WireGuard configuration chosen by the user. Nothing is saved yet
/// and the original file is never modified.
struct WireGuardImport: Equatable {
    var profile: WireGuardProfile
    var name: String
    var warnings: [String]
    var source: String
    /// The original file; after the private copy is saved the user may move it to the Trash.
    var sourceFiles: [URL] = []
    var exposedOriginals: [String] = []

    var summary: WireGuardSummary {
        WireGuardSummary(endpoints: profile.peers.compactMap { $0.endpoint?.display },
                         addresses: profile.addresses.map(\.text),
                         dns: profile.dnsServers + profile.dnsSearch,
                         allowedIPs: profile.allowedIPs.map(\.text),
                         fullTunnel: profile.routesAllIPv4 || profile.routesAllIPv6,
                         publicKey: WireGuardImporter.publicKey(of: profile.privateKey) ?? "",
                         warnings: warnings, source: source,
                         exposedOriginals: exposedOriginals.isEmpty ? nil : exposedOriginals)
    }
}

/// Reads a wg-quick style .conf (the format exported by WireGuard servers and apps).
enum WireGuardImporter {
    static func load(_ urls: [URL]) throws -> WireGuardImport {
        guard urls.count == 1, let url = urls.first else {
            throw AppFailure(urls.isEmpty ? String(localized: "Nenhum arquivo escolhido.") : String(localized: "Escolha um único arquivo .conf do WireGuard."))
        }
        return try load(url)
    }

    static func load(_ url: URL) throws -> WireGuardImport {
        guard let real = realpath(url.path, nil) else { throw AppFailure(String(localized: "Arquivo não encontrado: \(url.path)")) }
        let resolved = String(cString: real); free(real)
        let fd = open(resolved, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw AppFailure(String(localized: "Não foi possível ler \(url.lastPathComponent).")) }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG, info.st_size <= WireGuardProfile.maximumSize else {
            throw AppFailure(String(localized: "Escolha o arquivo .conf do WireGuard (um arquivo de texto de até 64 KB), não uma pasta."))
        }
        let data = try BoundedFile.read(fd: fd, limit: WireGuardProfile.maximumSize)
        guard let text = String(data: data, encoding: .utf8) else { throw AppFailure(String(localized: "O arquivo não está em texto UTF-8.")) }
        let source = url.path.replacingOccurrences(of: FileManager.default.homeDirectoryForCurrentUser.path, with: "~")
        var imported = try importText(text, suggestedName: url.deletingPathExtension().lastPathComponent, source: source)
        imported.sourceFiles = [url.standardizedFileURL]
        if info.st_mode & 0o077 != 0 {
            imported.exposedOriginals = [resolved]
            imported.warnings.append(String(localized: "O arquivo original \(url.lastPathComponent) contém a chave privada e pode ser lido por outros usuários do Mac (recomendado: apagá-lo ou chmod 600). A cópia do app é privada."))
        }
        return imported
    }

    static func importText(_ text: String, suggestedName: String, source: String) throws -> WireGuardImport {
        let parsed: WireGuardProfile.Parsed
        do { parsed = try WireGuardProfile.parse(text) } catch let violation as RuleViolation { throw AppFailure(violation.message) }
        var warnings: [String] = parsed.dropped.map { name in
            let reason = WireGuardProfile.dropped[name.lowercased()] ?? String(localized: "não suportado")
            return String(localized: "\(name) removido: \(reason).")
        }
        let profile = parsed.profile
        if profile.peers.allSatisfy({ $0.endpoint == nil }) {
            warnings.append(String(localized: "Nenhum peer tem Endpoint: o túnel só funciona se o outro lado iniciar a conexão."))
        }
        if profile.table == .off {
            warnings.append(String(localized: "Table = off: nenhuma rota é criada; só o tráfego para as redes que você rotear por conta própria usará o túnel."))
        }
        // The helper checks the normalized text again before anything runs as root.
        do { _ = try WireGuardProfile.validated(profile.text) } catch let violation as RuleViolation { throw AppFailure(violation.message) }
        let name = suggestedName.trimmingCharacters(in: .whitespacesAndNewlines)
        return WireGuardImport(profile: profile, name: name.isEmpty ? "WireGuard" : name, warnings: warnings, source: source)
    }

    /// Curve25519 public key of a WireGuard private key (CryptoKit clamps like WireGuard).
    static func publicKey(of privateKey: String) -> String? {
        guard let raw = WireGuardKey.decode(privateKey),
              let key = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: raw) else { return nil }
        return key.publicKey.rawRepresentation.base64EncodedString()
    }

    /// Moves the original file of a saved import to the Trash. Returns the names that failed.
    @discardableResult
    static func trashSources(of imported: WireGuardImport) -> [String] {
        var failed: [String] = []
        for url in imported.sourceFiles {
            do { try FileManager.default.trashItem(at: url, resultingItemURL: nil) }
            catch { failed.append(url.lastPathComponent) }
        }
        return failed
    }
}
