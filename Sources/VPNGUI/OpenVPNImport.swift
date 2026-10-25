import Foundation
import Darwin
import VPNHelperShared

/// Result of reading an OpenVPN profile chosen by the user. Nothing is saved yet and the
/// original files are never modified.
struct OpenVPNImport: Equatable {
    var profile: OpenVPNProfile
    var name: String
    var username: String
    var password: String
    var warnings: [String]
    /// `auth RSA-SHA256`-style value found; applied only if the user accepts.
    var digestFix: OpenVPNCompatibility.DigestFix?
    var source: String
    /// Original files this import read (profile and referenced material). After the
    /// private copy is saved the user may move them to the Trash.
    var sourceFiles: [URL] = []
    /// A .visc folder whose every visible entry was used: trashed as a whole.
    var sourceFolder: URL?
    var exposedOriginals: [String] = []

    var summary: OpenVPNSummary {
        OpenVPNSummary(remotes: profile.remotes, requiresCredentials: profile.requiresCredentials,
                       warnings: warnings, source: source, compatibility: digestFix,
                       exposedOriginals: exposedOriginals.isEmpty ? nil : exposedOriginals)
    }
    func profileText(applyingFix: Bool) -> String {
        guard applyingFix, let digestFix else { return profile.text }
        return OpenVPNCompatibility.apply(digestFix, to: profile).text
    }
}

/// Reads a single .ovpn/.conf file, a Viscosity .visc folder or a .zip of one. Referenced
/// certificates and keys are read only from inside the profile's own folder and become
/// inline blocks.
enum OpenVPNImporter {
    static let maximumReferencedFile = 64 * 1024
    /// Limits for a zipped profile: checked on the archive's listing before extracting.
    static let maximumArchive = 1024 * 1024
    static let maximumArchiveEntries = 64
    static let maximumExtracted = 4 * 1024 * 1024

    /// Several files chosen together: exactly one profile (.ovpn/.conf) plus the
    /// certificates and keys it references, matched by file name. Files left out of the
    /// selection are still looked up next to the profile, with the usual folder rules.
    static func load(_ urls: [URL]) throws -> OpenVPNImport {
        guard urls.count > 1 else {
            guard let url = urls.first else { throw AppFailure("Nenhum arquivo escolhido.") }
            return try load(url)
        }
        var configs: [URL] = []
        var attachments: [String: URL] = [:]
        for url in urls {
            var isDirectory: ObjCBool = false
            guard FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory), !isDirectory.boolValue else {
                throw AppFailure("Ao escolher vários itens, escolha só arquivos (o perfil e seus certificados), não pastas.")
            }
            if ["ovpn", "conf"].contains(url.pathExtension.lowercased()) { configs.append(url); continue }
            guard attachments[url.lastPathComponent] == nil else {
                throw AppFailure("Dois arquivos escolhidos têm o mesmo nome: \(url.lastPathComponent).")
            }
            attachments[url.lastPathComponent] = url
        }
        guard configs.count == 1, let config = configs.first else {
            throw AppFailure(configs.isEmpty ? "Entre os arquivos escolhidos não há um perfil .ovpn ou .conf."
                                             : "Escolha um único perfil .ovpn ou .conf junto com os certificados.")
        }
        return try load(config, attachments: attachments)
    }

    static func load(_ url: URL, attachments: [String: URL] = [:]) throws -> OpenVPNImport {
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory) else {
            throw AppFailure("Arquivo não encontrado: \(url.path)")
        }
        if !isDirectory.boolValue, isZip(url) { return try loadArchive(url) }
        let file = isDirectory.boolValue ? try configuration(inFolder: url) : url
        let attributes = try FileManager.default.attributesOfItem(atPath: file.path)
        guard (attributes[.type] as? FileAttributeType) == .typeRegular,
              (attributes[.size] as? Int ?? .max) <= OpenVPNConfigText.maximumSize else {
            throw AppFailure("O perfil precisa ser um arquivo de texto de até 256 KB.")
        }
        let data = try BoundedFile.read(file, limit: OpenVPNConfigText.maximumSize)
        guard let text = String(data: data, encoding: .utf8) ?? String(data: data, encoding: .isoLatin1) else {
            throw AppFailure("O perfil não está em texto legível.")
        }
        let base = file.deletingLastPathComponent()
        var stem = file.deletingPathExtension().lastPathComponent
        if stem.lowercased() == "config", isDirectory.boolValue { stem = url.deletingPathExtension().lastPathComponent }
        let source = (isDirectory.boolValue ? url : file).path
            .replacingOccurrences(of: FileManager.default.homeDirectoryForCurrentUser.path, with: "~")
        var imported = try importText(text, baseDirectory: base, suggestedName: stem, source: source, attachments: attachments)
        imported.sourceFiles.insert(file.standardizedFileURL, at: 0)
        if isDirectory.boolValue {
            let used = Set(imported.sourceFiles.map { $0.resolvingSymlinksInPath().path })
            let entries = (try? FileManager.default.contentsOfDirectory(at: url, includingPropertiesForKeys: nil)) ?? []
            let visible = entries.filter { !$0.lastPathComponent.hasPrefix(".") }
            if !visible.isEmpty, visible.allSatisfy({ used.contains($0.resolvingSymlinksInPath().path) }) {
                imported.sourceFolder = url.standardizedFileURL
            }
        }
        return imported
    }

    // MARK: Zip (e.g. Viscosity.visc.zip, as exported or mailed)

    static func isZip(_ url: URL) -> Bool {
        if url.pathExtension.lowercased() == "zip" { return true }
        guard let handle = try? FileHandle(forReadingFrom: url) else { return false }
        defer { try? handle.close() }
        return (try? handle.read(upToCount: 4)) == Data([0x50, 0x4b, 0x03, 0x04])
    }

    /// The listing is checked first (entry count, relative names, total size), then the
    /// system's ditto extracts into a private temporary folder, read like a .visc folder
    /// and removed afterwards. The archive itself is the only original.
    static func loadArchive(_ archive: URL) throws -> OpenVPNImport {
        let attributes = try FileManager.default.attributesOfItem(atPath: archive.path)
        guard (attributes[.type] as? FileAttributeType) == .typeRegular, (attributes[.size] as? Int ?? .max) <= maximumArchive else {
            throw AppFailure("O .zip precisa ser um arquivo de até 1 MB.")
        }
        let names = try tool("/usr/bin/zipinfo", ["-1", archive.path]).split(separator: "\n").map(String.init)
        guard !names.isEmpty, names.count <= maximumArchiveEntries else {
            throw AppFailure("O .zip precisa conter só o perfil e seus certificados (até \(maximumArchiveEntries) itens).")
        }
        guard names.allSatisfy({ !$0.hasPrefix("/") && !$0.split(separator: "/").contains("..") }) else {
            throw AppFailure("O .zip contém caminhos fora da própria pasta; nada foi importado.")
        }
        let totals = try tool("/usr/bin/zipinfo", ["-t", archive.path])
        guard let match = totals.range(of: #"([0-9]+) bytes uncompressed"#, options: .regularExpression),
              let size = Int(totals[match].split(separator: " ")[0]), size <= maximumExtracted else {
            throw AppFailure("O conteúdo do .zip passa de 4 MB; não parece um perfil OpenVPN.")
        }
        let temporary = FileManager.default.temporaryDirectory.appendingPathComponent("TunnelMac-import-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: temporary, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: temporary) }
        _ = try tool("/usr/bin/ditto", ["-x", "-k", archive.path, temporary.path])
        // Private like the app's copy, so only the archive's own permissions are reported.
        let items = FileManager.default.enumerator(at: temporary, includingPropertiesForKeys: [.isSymbolicLinkKey, .isDirectoryKey])
        while let item = items?.nextObject() as? URL {
            let values = try item.resourceValues(forKeys: [.isSymbolicLinkKey, .isDirectoryKey])
            guard values.isSymbolicLink != true else { throw AppFailure("O .zip contém links simbólicos; nada foi importado.") }
            chmod(item.path, values.isDirectory == true ? 0o700 : 0o600)
        }
        var imported = try load(try profileFolder(in: temporary))
        imported.source = archive.path.replacingOccurrences(of: FileManager.default.homeDirectoryForCurrentUser.path, with: "~")
        imported.sourceFiles = [archive.standardizedFileURL]
        imported.sourceFolder = nil
        imported.exposedOriginals = []
        let mode = (attributes[.posixPermissions] as? NSNumber)?.intValue ?? 0
        if mode & 0o077 != 0, imported.profile.blocks.contains(where: { $0.content.contains("PRIVATE KEY") || $0.content.contains("Static key") }) {
            imported.exposedOriginals = [archive.resolvingSymlinksInPath().path]
            imported.warnings.append("O arquivo original \(archive.lastPathComponent) contém chaves e pode ser lido por outros usuários do Mac (recomendado: chmod 600). A cópia do app é privada.")
        }
        return imported
    }

    /// The .visc (or any single) folder at the top of the archive, or the top itself when
    /// the profile sits there.
    static func profileFolder(in root: URL) throws -> URL {
        let entries = try FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: [.isDirectoryKey])
            .filter { !$0.lastPathComponent.hasPrefix(".") && $0.lastPathComponent != "__MACOSX" }
        if entries.contains(where: { ["ovpn", "conf"].contains($0.pathExtension.lowercased()) }) { return root }
        let folders = entries.filter { (try? $0.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) == true }
        guard entries.count == 1, let folder = folders.first else {
            throw AppFailure("O .zip não contém uma pasta .visc nem um perfil .ovpn.")
        }
        return folder
    }

    /// One fixed system tool, literal arguments, no shell; stdout on success.
    private static func tool(_ path: String, _ arguments: [String]) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = arguments
        process.environment = ["PATH": "/usr/bin:/bin", "LANG": "C"]
        let output = Pipe()
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        try process.run()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else { throw AppFailure("Não foi possível abrir o .zip (está corrompido?).") }
        return String(decoding: data, as: UTF8.self)
    }

    /// Moves the originals of a saved import to the Trash (recoverable until emptied).
    /// Returns the names that could not be moved.
    @discardableResult
    static func trashSources(of imported: OpenVPNImport) -> [String] {
        let targets = imported.sourceFolder.map { [$0] } ?? imported.sourceFiles
        var failed: [String] = []
        for url in targets {
            do { try FileManager.default.trashItem(at: url, resultingItemURL: nil) }
            catch { failed.append(url.lastPathComponent) }
        }
        return failed
    }

    /// Viscosity bundles hold one config.conf (or a single .ovpn) next to the key files.
    static func configuration(inFolder folder: URL) throws -> URL {
        let entries = try FileManager.default.contentsOfDirectory(at: folder, includingPropertiesForKeys: nil)
            .filter { !$0.lastPathComponent.hasPrefix(".") && ["ovpn", "conf"].contains($0.pathExtension.lowercased()) }
        if entries.count == 1 { return entries[0] }
        if let config = entries.first(where: { $0.lastPathComponent.lowercased() == "config.conf" }) { return config }
        if entries.isEmpty { throw AppFailure("A pasta não contém um perfil .ovpn ou config.conf.") }
        throw AppFailure("A pasta contém mais de um perfil (\(entries.map(\.lastPathComponent).sorted().joined(separator: ", "))). Escolha o arquivo desejado.")
    }

    static func importText(_ text: String, baseDirectory: URL, suggestedName: String, source: String,
                           attachments: [String: URL] = [:]) throws -> OpenVPNImport {
        var used = Set<String>()
        var readFiles: [URL] = []
        var exposedFiles: [String] = []
        func read(_ path: String, line: Int) throws -> (content: String, exposed: Bool) {
            let name = (path as NSString).lastPathComponent
            if !path.split(separator: "/").contains(".."), let attached = attachments[name] {
                used.insert(name)
                readFiles.append(attached.standardizedFileURL)
                return try readFile(attached, label: path, line: line)
            }
            let result = try readReferenced(path, base: baseDirectory, line: line)
            readFiles.append(baseDirectory.appendingPathComponent(path).standardizedFileURL)
            return result
        }
        let parsed: OpenVPNConfigText
        do { parsed = try OpenVPNConfigText.parse(text) } catch let violation as RuleViolation { throw AppFailure(violation.message) }
        var blocks: [String: String] = [:]
        var order: [String] = []
        var username = "", password = ""
        var warnings: [String] = []
        var droppedNames = Set<String>()
        var unsupported: [String] = []
        func addBlock(_ tag: String, _ content: String) throws {
            guard blocks[tag] == nil else { throw AppFailure("O material de <\(tag)> aparece mais de uma vez no perfil.") }
            blocks[tag] = content
            order.append(tag)
        }
        func credentials(from content: String) {
            let lines = content.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
            username = lines.first?.trimmingCharacters(in: .whitespaces) ?? ""
            password = lines.count > 1 ? lines[1] : ""
        }
        for block in parsed.blocks {
            switch block.tag {
            case _ where OpenVPNRules.blockTags.contains(block.tag): try addBlock(block.tag, block.content)
            case "auth-user-pass": credentials(from: block.content)
            case "connection": throw AppFailure("Blocos <connection> ainda não são suportados. Use diretivas remote no próprio perfil.")
            case "pkcs12": throw AppFailure("Certificados PKCS#12 ainda não são suportados; exporte o perfil com ca/cert/key em PEM.")
            case "http-proxy-user-pass": throw AppFailure("Conexão por proxy ainda não é suportada.")
            default: unsupported.append("<\(block.tag)>")
            }
        }
        var directives: [OpenVPNDirective] = []
        var keyDirection: String?
        for line in parsed.lines {
            var directive = line.directive
            let name = directive.name
            if OpenVPNRules.blockTags.contains(name) {
                guard let path = directive.arguments.first else { throw AppFailure("Linha \(line.number): \(name) sem arquivo.") }
                if path != "[inline]" {
                    if name == "crl-verify" && directive.arguments.count > 1 {
                        throw AppFailure("crl-verify com diretório não é suportado.")
                    }
                    let (content, exposed) = try read(path, line: line.number)
                    try addBlock(name, content)
                    if exposed {
                        if let last = readFiles.last { exposedFiles.append(last.resolvingSymlinksInPath().path) }
                        warnings.append("O arquivo original \(path) pode ser lido por outros usuários do Mac (recomendado: chmod 600). A cópia do app é privada.")
                    }
                }
                if name == "tls-auth", directive.arguments.count > 1 {
                    let direction = directive.arguments[1]
                    guard ["0", "1"].contains(direction) else { throw AppFailure("Linha \(line.number): direção de tls-auth inválida.") }
                    if let keyDirection, keyDirection != direction { throw AppFailure("key-direction diverge da direção de tls-auth.") }
                    keyDirection = direction
                }
                continue
            }
            switch name {
            case "key-direction":
                if let value = directive.arguments.first {
                    if let keyDirection, keyDirection != value { throw AppFailure("key-direction diverge da direção de tls-auth.") }
                    keyDirection = value
                }
                continue
            case "auth-user-pass":
                if let file = directive.arguments.first {
                    guard file != "username-only" else { throw AppFailure("Perfis só com usuário (SSO) ainda não são suportados.") }
                    let (content, _) = try read(file, line: line.number)
                    credentials(from: content)
                    warnings.append("Usuário e senha lidos de \(file); a senha passa a ficar no Keychain.")
                }
                directive.arguments = []
            case "pkcs12": throw AppFailure("Certificados PKCS#12 ainda não são suportados; exporte o perfil com ca/cert/key em PEM.")
            case "secret": throw AppFailure("Chave estática (secret) não é suportada; ela foi removida do OpenVPN 2.7.")
            case "askpass": throw AppFailure("Chave privada protegida por senha ainda não é suportada.")
            case "config": throw AppFailure("O perfil inclui outro arquivo (config), o que não é suportado.")
            case "http-proxy", "socks-proxy", "http-proxy-option": throw AppFailure("Conexão por proxy ainda não é suportada.")
            case "verb":
                if let value = directive.arguments.first.flatMap(Int.init), value > 3 {
                    directive.arguments = ["3"]
                    warnings.append("verb \(value) reduzido para 3: níveis maiores despejam toda a configuração no log.")
                }
            default: break
            }
            if ["tls-verify", "plugin"].contains(directive.name) {
                throw AppFailure("\(directive.name) pode validar a identidade do servidor. Solicite um perfil com remote-cert-tls server e verify-x509-name, sem scripts ou plugins; a política não será removida automaticamente.")
            }
            if let reason = OpenVPNRules.dropped[name] {
                if droppedNames.insert(name).inserted { warnings.append("Diretiva \(name) removida: \(reason).") }
                continue
            }
            guard OpenVPNRules.allowed[name] != nil else {
                unsupported.append(name)
                continue
            }
            directives.append(directive)
        }
        for directive in directives {
            let arguments = directive.arguments.joined(separator: ":").uppercased()
            if (directive.name == "auth" && ["MD4", "MD5", "SHA1"].contains(arguments)) ||
               (["cipher", "data-ciphers", "data-ciphers-fallback", "tls-cipher"].contains(directive.name) &&
                ["DES", "BF-CBC", "RC4", "RC2"].contains(where: arguments.contains)) ||
               (directive.name == "tls-cert-profile" && arguments == "LEGACY") {
                warnings.append("\(directive.name) usa uma política criptográfica antiga. Confirme a necessidade com o administrador; o app preservou o parâmetro.")
            }
            if ["compress", "comp-lzo"].contains(directive.name), !["NO", "STUB", "STUB-V2"].contains(arguments) {
                warnings.append("Compressão do túnel pode expor informações do tráfego. Solicite um perfil sem compressão; o parâmetro foi preservado para compatibilidade.")
            }
        }
        if !unsupported.isEmpty {
            throw AppFailure("O perfil usa diretivas que o app ainda não suporta: \(Array(Set(unsupported)).sorted().joined(separator: ", ")). Nada foi importado.")
        }
        if let keyDirection { directives.append(OpenVPNDirective("key-direction", [keyDirection])) }
        if directives.contains(where: { ["comp-lzo", "compress"].contains($0.name) && !($0.arguments.first ?? "").hasPrefix("stub") && $0.arguments.first != "no" }) {
            warnings.append("O perfil ativa compressão (comp-lzo/compress), que tem riscos conhecidos de segurança. Ela foi mantida porque o servidor pode exigi-la; prefira desativá-la no servidor.")
        }
        let profile = OpenVPNProfile(directives: directives, blocks: order.map { OpenVPNBlock(tag: $0, content: blocks[$0]!) })
        do { try profile.check() } catch let violation as RuleViolation { throw AppFailure(violation.message) }
        for unused in Set(attachments.keys).subtracting(used).sorted() {
            warnings.append("O arquivo escolhido \(unused) não é usado pelo perfil e foi ignorado.")
        }
        let name = suggestedName.lowercased() == "config" ? (parsed.viscosity["name"] ?? suggestedName) : suggestedName
        return OpenVPNImport(profile: profile, name: name, username: username, password: password, warnings: warnings,
                             digestFix: OpenVPNCompatibility.digestFix(for: profile), source: source,
                             sourceFiles: readFiles, exposedOriginals: exposedFiles)
    }

    /// Only relative names inside the profile's folder: no absolute paths, no "..", and the
    /// resolved file (after symlinks) must still be inside the folder.
    static func readReferenced(_ path: String, base: URL, line: Int) throws -> (content: String, exposed: Bool) {
        guard !path.hasPrefix("/"), !path.hasPrefix("~"), !path.split(separator: "/").contains(".."), !path.isEmpty else {
            throw AppFailure("Linha \(line): \(path) aponta para fora da pasta do perfil. Coloque os arquivos ao lado do .ovpn e use nomes relativos.")
        }
        guard let baseReal = realpath(base.path, nil) else { throw AppFailure("Pasta do perfil inacessível.") }
        let root = String(cString: baseReal); free(baseReal)
        guard let fileReal = realpath(base.appendingPathComponent(path).path, nil) else {
            throw AppFailure("Linha \(line): arquivo \(path) não encontrado ao lado do perfil.")
        }
        let resolved = String(cString: fileReal); free(fileReal)
        guard resolved.hasPrefix(root + "/") else {
            throw AppFailure("Linha \(line): \(path) aponta para fora da pasta do perfil.")
        }
        return try readFile(URL(fileURLWithPath: resolved), label: path, line: line)
    }

    /// Reads one certificate/key file chosen or referenced by the user: regular, ≤ 64 KB, text.
    static func readFile(_ url: URL, label path: String, line: Int) throws -> (content: String, exposed: Bool) {
        guard let real = realpath(url.path, nil) else { throw AppFailure("Linha \(line): arquivo \(path) não encontrado.") }
        let resolved = String(cString: real); free(real)
        let fd = open(resolved, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw AppFailure("Linha \(line): não foi possível ler \(path).") }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG, info.st_size <= maximumReferencedFile else {
            throw AppFailure("Linha \(line): \(path) não é um arquivo regular de até 64 KB.")
        }
        let data = try BoundedFile.read(fd: fd, limit: maximumReferencedFile)
        guard let text = String(data: data, encoding: .utf8) else { throw AppFailure("Linha \(line): \(path) não está em texto (PEM).") }
        let content = text.replacingOccurrences(of: "\r\n", with: "\n").trimmingCharacters(in: .newlines)
        return (content, info.st_mode & 0o077 != 0 && content.contains("PRIVATE KEY") || (info.st_mode & 0o077 != 0 && content.contains("Static key")))
    }
}
