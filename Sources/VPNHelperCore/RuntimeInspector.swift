import Foundation
import Darwin
import VPNHelperShared

/// One Mach-O image of the candidate installation, read once from a descriptor.
struct InspectedImage {
    let role: InventoryItem.Role
    let resolvedPath: String
    let original: Data
    let image: MachOImage
    let sha256: String
    let ownerUID: uid_t
    let mutableLocation: Bool
    /// Every dependency name of this image that resolved to another inspected image.
    var resolvedDependencies: [String: String] = [:]
}

/// A shell script shipped with the client (OpenVPN's dns-updown), frozen like the images.
/// Its interpreter must be a SIP-protected system shell.
struct InspectedScript {
    let relativePath: String          // inside the managed copy
    let resolvedPath: String
    let data: Data
    let sha256: String
    let ownerUID: uid_t
    let mutableLocation: Bool
}

public struct Inventory {
    public let kind: RuntimeKind
    public let candidatePath: String
    let images: [InspectedImage]          // [0] is the executable
    let systemLibraries: [String]
    let packageVersion: String?
    let licenseSources: [String]          // keg roots whose license files are preserved
    let warnings: [String]
    let scripts: [InspectedScript]
    public let digest: String

    var executable: InspectedImage { images[0] }
    public var report: RuntimeInspection {
        RuntimeInspection(candidatePath: candidatePath, resolvedPath: executable.resolvedPath, digest: digest,
                          items: images.map { InventoryItem(role: $0.role, sourcePath: $0.resolvedPath, sha256: $0.sha256,
                                                            size: $0.original.count, ownerUID: $0.ownerUID,
                                                            mutableLocation: $0.mutableLocation) }
                            + scripts.map { InventoryItem(role: .script, sourcePath: $0.resolvedPath, sha256: $0.sha256,
                                                          size: $0.data.count, ownerUID: $0.ownerUID, mutableLocation: $0.mutableLocation) },
                          systemLibraries: systemLibraries, packageVersion: packageVersion, warnings: warnings, kind: kind)
    }
}

/// Builds the closed dependency inventory of a candidate openfortivpn without executing it.
/// System libraries (/usr/lib, /System/Library) are SIP-protected and stay in place;
/// everything else must be resolvable, regular, Mach-O and becomes part of the copy.
public enum RuntimeInspector {
    static let maximumImages = 24
    static let maximumImageSize = 64 * 1024 * 1024

    static func isSystemLibrary(_ name: String) -> Bool {
        (name.hasPrefix("/usr/lib/") || name.hasPrefix("/System/Library/")) && !name.contains("/../") && !name.contains("/./")
    }

    /// Rejects files whose path can be changed by a user other than root or the requester
    /// (foreign owner, or world-writable directory without the sticky bit).
    static func checkForeignControl(_ path: String, requester: uid_t) throws {
        var current = path
        while true {
            var info = stat()
            guard lstat(current, &info) == 0 else { throw failure(.runtimeRejected, ServiceLanguage.text("Caminho inacessível: \(current)")) }
            guard info.st_uid == 0 || info.st_uid == requester else {
                throw failure(.runtimeRejected, ServiceLanguage.text("\(current) pertence a outro usuário (uid \(info.st_uid)); não é aceito."))
            }
            if (info.st_mode & S_IFMT) == S_IFDIR, info.st_mode & S_IWOTH != 0, info.st_mode & S_ISVTX == 0 {
                throw failure(.runtimeRejected, ServiceLanguage.text("\(current) pode ser alterado por qualquer usuário; não é aceito."))
            }
            if current == "/" { return }
            current = (current as NSString).deletingLastPathComponent
            if current.isEmpty { current = "/" }
        }
    }

    public static func inspect(candidate: String, requester: uid_t, kind: RuntimeKind = .openfortivpn) throws -> Inventory {
        let name = kind.executableName
        guard candidate.hasPrefix("/"), candidate.utf8.count <= 1024, !candidate.contains("\0"),
              (candidate as NSString).lastPathComponent == name else {
            throw failure(.invalidRequest, ServiceLanguage.text("Indique o caminho absoluto de um executável chamado \(name)."))
        }
        let resolved = try SecureFile.realPath(candidate)
        guard (resolved as NSString).lastPathComponent == name else {
            throw failure(.runtimeRejected, ServiceLanguage.text("O caminho resolve para outro arquivo: \(resolved)"))
        }
        var images: [InspectedImage] = []
        var indexByPath: [String: Int] = [:]
        var system = Set<String>()
        var queue: [(path: String, role: InventoryItem.Role)] = [(resolved, .executable)]
        while !queue.isEmpty {
            let (path, role) = queue.removeFirst()
            guard indexByPath[path] == nil else { continue }
            guard images.count < maximumImages else { throw failure(.runtimeRejected, ServiceLanguage.text("Dependências demais para uma cópia gerenciada.")) }
            try checkForeignControl(path, requester: requester)
            let (data, info) = try SecureFile.read(path, limit: maximumImageSize)
            guard MachOImage.isMachO(data) else { throw failure(.runtimeRejected, ServiceLanguage.text("Não é Mach-O: \(path)")) }
            let image = try MachOImage(file: data)
            guard image.fileType == (role == .executable ? MachOImage.executable : MachOImage.dylib) else {
                throw failure(.runtimeRejected, ServiceLanguage.text("Tipo Mach-O inesperado: \(path)"))
            }
            guard !image.hasDyldEnvironment else { throw failure(.runtimeRejected, ServiceLanguage.text("LC_DYLD_ENVIRONMENT não é aceito: \(path)")) }
            if role == .executable, image.dylinker != "/usr/lib/dyld" {
                throw failure(.runtimeRejected, ServiceLanguage.text("Carregador dinâmico inesperado em \(path)."))
            }
            var entry = InspectedImage(role: role, resolvedPath: path, original: data, image: image,
                                       sha256: Digest.sha256(data), ownerUID: info.st_uid,
                                       mutableLocation: SecureFile.mutableLocation(path))
            let executableDirectory = ((images.first?.resolvedPath ?? path) as NSString).deletingLastPathComponent
            let loaderDirectory = (path as NSString).deletingLastPathComponent
            let rpaths = image.rpaths.map { expand($0, loader: loaderDirectory, executable: executableDirectory) }
                + (images.first?.image.rpaths ?? []).map { expand($0, loader: executableDirectory, executable: executableDirectory) }
            for name in image.dependencies {
                if isSystemLibrary(name) { system.insert(name); continue }
                let target = try resolve(name, loader: loaderDirectory, executable: executableDirectory, rpaths: rpaths)
                if isSystemLibrary(target) { system.insert(target); continue }
                entry.resolvedDependencies[name] = target
                queue.append((target, .library))
            }
            indexByPath[path] = images.count
            images.append(entry)
        }
        var leaves = Set<String>()
        for library in images.dropFirst() {
            let leaf = (library.resolvedPath as NSString).lastPathComponent
            guard leaf.range(of: #"^[A-Za-z0-9._+-]+\.dylib$"#, options: .regularExpression) != nil, leaves.insert(leaf).inserted else {
                throw failure(.runtimeRejected, ServiceLanguage.text("Nome de biblioteca inválido ou repetido: \(leaf)"))
            }
        }
        let package = kegVersion(resolved)
        var scripts: [InspectedScript] = []
        var notes: [String] = []
        if kind == .openvpn {
            if let script = try dnsScript(for: resolved, requester: requester) { scripts.append(script) }
            else { notes.append(ServiceLanguage.text("Script dns-updown do OpenVPN não encontrado junto ao executável: o túnel funcionará, mas o DNS da VPN não será configurado.")) }
        }
        let warnings = images.filter(\.mutableLocation).map {
            ServiceLanguage.text("\($0.resolvedPath) está em local alterável sem senha de administrador (dono uid \($0.ownerUID)). A aprovação congela exatamente estes bytes numa cópia protegida; confira a origem antes de aprovar.")
        } + scripts.filter(\.mutableLocation).map {
            ServiceLanguage.text("\($0.resolvedPath) (script de DNS executado como root) está em local alterável sem senha de administrador. A aprovação congela estes bytes.")
        } + notes
        let listing = (images.map { "\($0.role.rawValue)\t\($0.resolvedPath)\t\($0.sha256)" }
                       + scripts.map { "script\t\($0.relativePath)\t\($0.resolvedPath)\t\($0.sha256)" })
            .sorted().joined(separator: "\n")
        let kegs = images.compactMap { kegRoot($0.resolvedPath) }
        return Inventory(kind: kind, candidatePath: candidate, images: images, systemLibraries: system.sorted(), packageVersion: package,
                         licenseSources: Array(Set(kegs)).sorted(), warnings: warnings, scripts: scripts,
                         digest: Digest.sha256(Data((kind.rawValue + "\n" + listing).utf8)))
    }

    static let maximumScriptSize = 1024 * 1024

    /// OpenVPN 2.7 runs `<prefix>/libexec/openvpn/dns-updown` as root after the tunnel is up.
    /// The compiled-in path points into the (user-writable) Homebrew prefix, so the helper
    /// freezes this script and passes the frozen copy explicitly instead.
    static func dnsScript(for executable: String, requester: uid_t) throws -> InspectedScript? {
        let prefix = ((executable as NSString).deletingLastPathComponent as NSString).deletingLastPathComponent
        let candidate = prefix + "/libexec/openvpn/dns-updown"
        guard let path = try? SecureFile.realPath(candidate) else { return nil }
        try checkForeignControl(path, requester: requester)
        let (data, info) = try SecureFile.read(path, limit: maximumScriptSize)
        let firstLine = data.prefix(64).split(separator: 10).first.map { String(decoding: $0, as: UTF8.self) } ?? ""
        guard ["#!/bin/bash", "#!/bin/sh"].contains(firstLine.trimmingCharacters(in: .whitespaces)) else {
            throw failure(.runtimeRejected, ServiceLanguage.text("O script dns-updown não usa um interpretador do sistema (/bin/bash ou /bin/sh)."))
        }
        return InspectedScript(relativePath: "libexec/dns-updown", resolvedPath: path, data: data, sha256: Digest.sha256(data),
                               ownerUID: info.st_uid, mutableLocation: SecureFile.mutableLocation(path))
    }

    static func expand(_ value: String, loader: String, executable: String) -> String {
        if value.hasPrefix("@loader_path") { return loader + value.dropFirst("@loader_path".count) }
        if value.hasPrefix("@executable_path") { return executable + value.dropFirst("@executable_path".count) }
        return value
    }

    static func resolve(_ name: String, loader: String, executable: String, rpaths: [String]) throws -> String {
        var candidates: [String] = []
        if name.hasPrefix("@rpath/") {
            candidates = rpaths.map { $0 + "/" + name.dropFirst("@rpath/".count) }
        } else if name.hasPrefix("@loader_path/") || name.hasPrefix("@executable_path/") {
            candidates = [expand(name, loader: loader, executable: executable)]
        } else if name.hasPrefix("/") {
            candidates = [name]
        }
        for candidate in candidates where candidate.hasPrefix("/") {
            if let real = try? SecureFile.realPath(candidate) { return real }
        }
        throw failure(.runtimeRejected, ServiceLanguage.text("Dependência não resolvida com segurança: \(name)"))
    }

    /// ".../Cellar/<formula>/<version>/..." → "<formula> <version>" (provenance only).
    static func kegVersion(_ path: String) -> String? {
        guard let root = kegRoot(path) else { return nil }
        let parts = root.split(separator: "/")
        return parts.count >= 2 ? "\(parts[parts.count - 2]) \(parts[parts.count - 1])" : nil
    }
    static func kegRoot(_ path: String) -> String? {
        let parts = path.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard let index = parts.firstIndex(of: "Cellar"), parts.count > index + 3 else { return nil }
        return parts[0...(index + 2)].joined(separator: "/")
    }
}
