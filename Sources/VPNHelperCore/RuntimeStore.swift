import Foundation
import Darwin
import ProcessBridge
import VPNHelperShared

struct ManagedFile: Codable, Equatable {
    var path: String       // relative to the runtime root
    var sha256: String
    var mode: UInt16
}

struct RuntimeManifest: Codable {
    var format = 1
    var id: String
    var approvedAt: Date
    var approvedByUID: UInt32
    var version: String
    var capabilities: RuntimeCapabilities
    var inventoryDigest: String
    var sourcePath: String
    var sourceSHA256: String
    var files: [ManagedFile]
    var sources: [InventoryItem]
    var systemLibraries: [String]
    var packageVersion: String?
    var notes: [String]
    /// nil in manifests written before OpenVPN support: openfortivpn.
    var kind: RuntimeKind?
    var runtimeKind: RuntimeKind { kind ?? .openfortivpn }
}

struct HelperState: Codable {
    var format = 1
    var activeRuntime: String?
    var previousRuntime: String?
    var authorizedUsers: [UInt32] = []
    var activeOpenVPNRuntime: String?
    var previousOpenVPNRuntime: String?
    var activeWireGuardRuntime: String?
    var previousWireGuardRuntime: String?

    func active(_ kind: RuntimeKind) -> String? {
        switch kind {
        case .openfortivpn: return activeRuntime
        case .openvpn: return activeOpenVPNRuntime
        case .wireguard: return activeWireGuardRuntime
        }
    }
    mutating func activate(_ id: String, kind: RuntimeKind) {
        switch kind {
        case .openfortivpn:
            if activeRuntime != id { previousRuntime = activeRuntime }
            activeRuntime = id
        case .openvpn:
            if activeOpenVPNRuntime != id { previousOpenVPNRuntime = activeOpenVPNRuntime }
            activeOpenVPNRuntime = id
        case .wireguard:
            if activeWireGuardRuntime != id { previousWireGuardRuntime = activeWireGuardRuntime }
            activeWireGuardRuntime = id
        }
    }
    var kept: [String] {
        [activeRuntime, previousRuntime, activeOpenVPNRuntime, previousOpenVPNRuntime,
         activeWireGuardRuntime, previousWireGuardRuntime].compactMap { $0 }
    }
}

/// A verified, ready-to-execute runtime. Valid only for the request being served.
public struct ActiveRuntime {
    public let root: String
    public let executable: String
    let manifest: RuntimeManifest
    public var version: String { manifest.version }
    public var kind: RuntimeKind { manifest.runtimeKind }
    /// Frozen OpenVPN dns-updown script, when the approved installation shipped one.
    public var dnsScript: String? {
        manifest.files.contains { $0.path == "libexec/dns-updown" } ? root + "/libexec/dns-updown" : nil
    }
    public var files: [String] { manifest.files.map(\.path) }
    public var environment: [String: String] { RuntimeEnvironment.variables(root: root) }
    public var summary: RuntimeSummary {
        RuntimeSummary(id: manifest.id, version: manifest.version, approvedAt: manifest.approvedAt,
                       capabilities: manifest.capabilities, sourcePath: manifest.sourcePath, sourceSHA256: manifest.sourceSHA256, sources: manifest.sources, inventoryDigest: manifest.inventoryDigest)
    }
}

/// Environment of every root child: fixed PATH; OpenSSL configuration, providers and
/// engines pointed at empty root-owned locations inside the runtime (the Homebrew
/// OPENSSLDIR/MODULESDIR are user-writable and would otherwise be read as root);
/// TLS trust anchors from the SIP-protected system bundle. Nothing is inherited.
public enum RuntimeEnvironment {
    public static func variables(root: String) -> [String: String] {
        ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
         "LANG": "C",
         "OPENSSL_CONF": root + "/etc/openssl.cnf",
         "OPENSSL_MODULES": root + "/lib/ossl-modules",
         "OPENSSL_ENGINES": root + "/lib/engines",
         "SSL_CERT_FILE": "/private/etc/ssl/cert.pem",
         "SSL_CERT_DIR": "/private/etc/ssl/certs"]
    }
    static func list(_ values: [String: String]) -> [String] { values.keys.sorted().map { "\($0)=\(values[$0]!)" } }
}

/// Runs a short command with a fixed environment, optionally as another identity.
enum Probe {
    struct Output { let status: Int32; let text: String }
    static func run(_ path: String, _ arguments: [String], environment: [String], identity: (uid_t, gid_t)?, timeout: Int32 = 10_000) throws -> Output {
        var argv: [UnsafeMutablePointer<CChar>?] = ([path] + arguments).map { strdup($0) } + [nil]
        var envp: [UnsafeMutablePointer<CChar>?] = environment.map { strdup($0) } + [nil]
        defer { argv.forEach { free($0) }; envp.forEach { free($0) } }
        var buffer = [CChar](repeating: 0, count: 256 * 1024)
        var length = 0, status: Int32 = 0
        let uid = identity?.0 ?? uid_t.max, gid = identity?.1 ?? gid_t.max
        let result = argv.withUnsafeMutableBufferPointer { a in
            envp.withUnsafeMutableBufferPointer { e in
                vpn_run_probe(path, a.baseAddress, e.baseAddress, uid, gid, timeout, &buffer, buffer.count, &length, &status)
            }
        }
        guard result == 0 else { throw failure(.internalError, "Não foi possível executar \(path).") }
        let text = buffer.prefix(length).withUnsafeBufferPointer { String(decoding: UnsafeRawBufferPointer($0), as: UTF8.self) }
        return Output(status: status, text: text)
    }
}

public final class RuntimeStore {
    public let root: String
    public let ownership: TrustedOwnership
    let probeIdentity: (uid_t, gid_t)?
    let codesign: String
    public init(root: String, ownership: TrustedOwnership, probeIdentity: (uid_t, gid_t)?, codesign: String = "/usr/bin/codesign") {
        self.root = root; self.ownership = ownership; self.probeIdentity = probeIdentity; self.codesign = codesign
    }
    public var statePath: String { root + "/state.json" }
    public var runtimes: String { root + "/runtime" }
    public var work: String { root + "/work" }
    public var supervisors: String { root + "/supervisor" }
    public var registryPath: String { root + "/sessions.json" }
    /// What WireGuard sessions changed outside their interface (routes, DNS), until undone.
    public var wireGuardRecords: String { root + "/wireguard" }
    /// Client certificate files of running openfortivpn sessions (<token>.crt / <token>.key).
    public var clientCertificates: String { root + "/client-cert" }
    /// Previous DNS of the primary service while the "DNS da internet" is applied.
    public var internetDNSRecord: String { root + "/internet-dns.json" }
    public var dnsBaselineRecord: String { root + "/dns-baseline.json" }

    // MARK: State

    public func prepareDirectories() throws {
        try SecureFile.makeDirectory(root, mode: 0o755)
        try SecureFile.makeDirectory(runtimes, mode: 0o755)
        try SecureFile.makeDirectory(supervisors, mode: 0o755)
        try SecureFile.makeDirectory(work, mode: 0o700)
        try SecureFile.makeDirectory(wireGuardRecords, mode: 0o700)
        try SecureFile.makeDirectory(clientCertificates, mode: 0o700)
        try ownership.verifyChain(work)
    }

    /// Explicit recovery only; directory preparation never removes live session files.
    func sweepWork(keeping live: Set<String>) {
        for entry in (try? FileManager.default.contentsOfDirectory(atPath: work)) ?? [] {
            if entry.hasPrefix("cfg.") { unlink(work + "/" + entry) }
            else if entry.hasPrefix("wg."), entry.hasSuffix(".name") {
                let token = String(entry.dropFirst(3).dropLast(5))
                if !live.contains(token) { unlink(work + "/" + entry) }
            }
        }
    }

    func loadState() throws -> HelperState {
        var info = stat()
        guard lstat(statePath, &info) == 0 else { return HelperState() }
        try ownership.verifyChain(statePath)
        let (data, _) = try SecureFile.read(statePath, limit: 64 * 1024)
        guard let state = try? JSONDecoder().decode(HelperState.self, from: data), state.format == 1 else {
            throw failure(.runtimeRejected, "Estado do serviço ilegível; aprove o openfortivpn novamente.")
        }
        return state
    }

    func saveState(_ state: HelperState) throws {
        try SecureFile.makeDirectory(root, mode: 0o755)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try SecureFile.replace(statePath, data: try encoder.encode(state), mode: 0o644)
    }

    // MARK: Verification (every start)

    public func loadActive(_ kind: RuntimeKind = .openfortivpn) throws -> ActiveRuntime {
        let state = try loadState()
        guard let id = state.active(kind), Self.validID(id) else {
            throw failure(.runtimeUnavailable, "Nenhum \(kind.title) aprovado para o serviço.")
        }
        let base = runtimes + "/" + id
        try ownership.verifyChain(base + "/manifest.json")
        let (data, _) = try SecureFile.read(base + "/manifest.json", limit: 1024 * 1024)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        guard let manifest = try? decoder.decode(RuntimeManifest.self, from: data), manifest.format == 1, manifest.id == id,
              manifest.runtimeKind == kind else {
            throw failure(.runtimeRejected, "Manifesto do runtime inválido.")
        }
        for file in manifest.files {
            guard !file.path.hasPrefix("/"), !file.path.split(separator: "/").contains("..") else {
                throw failure(.runtimeRejected, "Manifesto com caminho inválido.")
            }
            let path = base + "/" + file.path
            try ownership.verifyChain(path)
            let (bytes, info) = try SecureFile.read(path, limit: RuntimeInspector.maximumImageSize)
            guard Digest.sha256(bytes) == file.sha256, UInt16(info.st_mode & 0o7777) == file.mode else {
                throw failure(.runtimeRejected, "O runtime aprovado foi alterado (\(file.path)); aprove novamente.")
            }
        }
        // dyld loads only the names written into the images, but no extra code may sit
        // next to them, and the OpenSSL provider/engine directories must stay empty.
        let listed = Set(manifest.files.map(\.path))
        for directory in ["bin", "lib", "libexec"] {
            for entry in (try? FileManager.default.contentsOfDirectory(atPath: base + "/" + directory)) ?? [] {
                let relative = directory + "/" + entry
                if ["lib/ossl-modules", "lib/engines"].contains(relative) {
                    let contents = (try? FileManager.default.contentsOfDirectory(atPath: base + "/" + relative)) ?? ["?"]
                    guard contents.isEmpty else { throw failure(.runtimeRejected, "Conteúdo inesperado em \(relative).") }
                    try ownership.verifyChain(base + "/" + relative)
                    continue
                }
                guard listed.contains(relative) else { throw failure(.runtimeRejected, "Arquivo não aprovado no runtime: \(relative)") }
            }
        }
        let executable = "bin/" + kind.executableName
        guard listed.contains(executable) else { throw failure(.runtimeRejected, "Manifesto sem o executável \(kind.title).") }
        return ActiveRuntime(root: base, executable: base + "/" + executable, manifest: manifest)
    }

    /// File name of each library in the managed copy: the Cellar file name, or, when the new
    /// path with that name does not fit a load command naming the library, the leaf of its
    /// install name. Intel Homebrew needs this: /usr/local/opt/… leaves less room in the
    /// commands than /opt/homebrew/opt/…, e.g. liblz4.1.10.0.dylib vs liblz4.1.dylib.
    static func managedLeaves(_ images: [InspectedImage]) -> [String: String] {
        let dependencyCommands: Set<MachOImage.Command> = [.loadDylib, .loadWeakDylib, .reexportDylib, .lazyLoadDylib, .loadUpwardDylib]
        var leaves: [String: String] = [:]
        for library in images.dropFirst() { leaves[library.resolvedPath] = (library.resolvedPath as NSString).lastPathComponent }
        var used = Set(leaves.values)
        for library in images.dropFirst() {
            func fits(_ leaf: String) -> Bool {
                let replacement = "@executable_path/../lib/" + leaf
                let referrers = images.allSatisfy { image in
                    image.resolvedDependencies.allSatisfy { name, target in
                        target != library.resolvedPath || image.image.fits(replacement, for: name, commands: dependencyCommands)
                    }
                }
                let own = library.image.installName.map { library.image.fits(replacement, for: $0, commands: [.idDylib]) } ?? true
                return referrers && own
            }
            let current = leaves[library.resolvedPath]!
            guard !fits(current), let installName = library.image.installName else { continue }
            let alternative = (installName as NSString).lastPathComponent
            guard alternative.range(of: #"^[A-Za-z0-9._+-]+\.dylib$"#, options: .regularExpression) != nil,
                  !used.contains(alternative), fits(alternative) else { continue }
            used.remove(current)
            used.insert(alternative)
            leaves[library.resolvedPath] = alternative
        }
        return leaves
    }

    static func validID(_ id: String) -> Bool { id.range(of: #"^[0-9a-f]{24}$"#, options: .regularExpression) != nil }

    // MARK: Installation (admin-approved only)

    @discardableResult
    public func install(_ inventory: Inventory, approvedBy uid: uid_t) throws -> RuntimeSummary {
        try prepareDirectories()
        var state = try loadState()
        let kind = inventory.kind
        if let active = try? loadActive(kind), active.manifest.inventoryDigest == inventory.digest {
            // Same bytes already approved: only authorize this user.
            if !state.authorizedUsers.contains(uid) { state.authorizedUsers.append(uid); try saveState(state) }
            return active.summary
        }
        let id = String(Digest.sha256(Data((inventory.digest + "\(Date().timeIntervalSince1970)").utf8)).prefix(24))
        let staging = runtimes + "/.staging-" + id
        SecureFile.removeTree(staging)
        do {
            for directory in [staging, staging + "/bin", staging + "/lib", staging + "/lib/ossl-modules",
                              staging + "/lib/engines", staging + "/etc", staging + "/licenses"]
                + (inventory.scripts.isEmpty ? [] : [staging + "/libexec"]) {
                try SecureFile.makeDirectory(directory, mode: 0o755)
            }
            let leafByPath = Self.managedLeaves(inventory.images)
            var files: [ManagedFile] = []
            for image in inventory.images {
                var patched = image.image
                var dependencies: [String: String] = [:]
                for (name, target) in image.resolvedDependencies { dependencies[name] = "@executable_path/../lib/" + leafByPath[target]! }
                try patched.rewrite(dependencies, commands: [.loadDylib, .loadWeakDylib, .reexportDylib, .lazyLoadDylib, .loadUpwardDylib])
                var rpaths: [String: String] = [:]
                for rpath in patched.rpaths { rpaths[rpath] = "@executable_path/../lib" }
                try patched.rewrite(rpaths, commands: [.rpath])
                let relative: String
                if image.role == .executable {
                    relative = "bin/" + kind.executableName
                } else {
                    relative = "lib/" + leafByPath[image.resolvedPath]!
                    if let name = patched.installName { try patched.rewrite([name: "@executable_path/../" + relative], commands: [.idDylib]) }
                }
                let path = staging + "/" + relative
                try SecureFile.create(path, data: patched.data, mode: 0o644)
                // Load commands changed: the original (ad hoc) signature no longer matches.
                // /usr/bin/codesign is a SIP-protected system tool; developer tools are never run as root.
                let signed = try Probe.run(codesign, ["--force", "--sign", "-", path],
                                           environment: ["PATH=/usr/bin:/bin"], identity: nil, timeout: 60_000)
                guard signed.status == 0, CodeTrust.validate(file: URL(fileURLWithPath: path), requirement: nil) else {
                    throw failure(.runtimeRejected, "Não foi possível assinar ad hoc a cópia gerenciada de \(relative).")
                }
                let mode: UInt16 = image.role == .executable ? 0o555 : 0o444
                guard chmod(path, mode_t(mode)) == 0 else { throw failure(.internalError, "Permissões da cópia gerenciada.") }
                let (final, _) = try SecureFile.read(path, limit: RuntimeInspector.maximumImageSize)
                files.append(ManagedFile(path: relative, sha256: Digest.sha256(final), mode: mode))
            }
            for script in inventory.scripts {
                // Same bytes as inspected (part of the digest); root-owned and read-only.
                try SecureFile.create(staging + "/" + script.relativePath, data: script.data, mode: 0o555)
                files.append(ManagedFile(path: script.relativePath, sha256: script.sha256, mode: 0o555))
            }
            let config = Data("# TunnelMac: configuração OpenSSL intencionalmente vazia (sem módulos, engines ou includes).\n".utf8)
            try SecureFile.create(staging + "/etc/openssl.cnf", data: config, mode: 0o444)
            files.append(ManagedFile(path: "etc/openssl.cnf", sha256: Digest.sha256(config), mode: 0o444))
            let notes = copyLicenses(inventory.licenseSources, into: staging + "/licenses")
            // Probe the staged copy exactly as it will run, without root when possible.
            let environment = RuntimeEnvironment.list(RuntimeEnvironment.variables(root: staging))
            let executable = staging + "/bin/" + kind.executableName
            // wireguard-go has no --help: any other argument is taken as an interface name.
            let help = kind == .wireguard ? nil : try Probe.run(executable, ["--help"], environment: environment, identity: probeIdentity)
            let versionOutput = try Probe.run(executable, ["--version"], environment: environment, identity: probeIdentity)
            let recognized: Bool
            switch kind {
            case .openfortivpn: recognized = RuntimeCapabilities.looksLikeOpenFortiVPN(help?.text ?? "")
            case .openvpn: recognized = RuntimeCapabilities.looksLikeOpenVPN(help?.text ?? "")
            case .wireguard: recognized = versionOutput.status == 0 && RuntimeCapabilities.looksLikeWireGuardGo(versionOutput.text)
            }
            guard recognized else {
                let expected: String
                switch kind {
                case .openfortivpn: expected = "as opções esperadas do openfortivpn"
                case .openvpn: expected = "as opções esperadas do OpenVPN 2.7 ou superior (--dns-updown)"
                case .wireguard: expected = "a versão do wireguard-go para macOS"
                }
                throw failure(.runtimeRejected, "A cópia gerenciada não apresentou \(expected) (código \((help ?? versionOutput).status)).")
            }
            var firstLine = versionOutput.text.split(separator: "\n").first.map(String.init)?.trimmingCharacters(in: .whitespaces) ?? ""
            // "OpenVPN 2.7.8 aarch64-apple-darwin… [SSL (OpenSSL)] …"
            if kind == .openvpn, firstLine.hasPrefix("OpenVPN ") {
                firstLine = firstLine.split(separator: " ").dropFirst().first.map(String.init) ?? ""
            }
            // "wireguard-go v0.0.20250522"
            if kind == .wireguard, firstLine.hasPrefix("wireguard-go v") {
                firstLine = String(firstLine.dropFirst("wireguard-go v".count))
            }
            let version = firstLine.range(of: #"^[0-9][0-9A-Za-z.+_-]{0,31}$"#, options: .regularExpression) != nil ? firstLine : "desconhecida"
            let manifest = RuntimeManifest(id: id, approvedAt: Date(), approvedByUID: uid, version: version,
                                           capabilities: RuntimeCapabilities(help: help?.text ?? ""),
                                           inventoryDigest: inventory.digest, sourcePath: inventory.executable.resolvedPath,
                                           sourceSHA256: inventory.executable.sha256, files: files,
                                           sources: inventory.report.items, systemLibraries: inventory.systemLibraries,
                                           packageVersion: inventory.packageVersion, notes: notes, kind: kind)
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            encoder.dateEncodingStrategy = .secondsSince1970
            try SecureFile.create(staging + "/manifest.json", data: try encoder.encode(manifest), mode: 0o444)
            let final = runtimes + "/" + id
            guard rename(staging, final) == 0 else { throw failure(.internalError, "Não foi possível ativar o runtime.") }
            // The previous runtime stays as rollback until the next approval of the same kind.
            state.activate(id, kind: kind)
            if !state.authorizedUsers.contains(uid) { state.authorizedUsers.append(uid) }
            try saveState(state)
            prune(keeping: state.kept)
            return try loadActive(kind).summary
        } catch {
            SecureFile.removeTree(staging)
            throw error
        }
    }

    public func authorize(_ uid: uid_t) throws {
        var state = try loadState()
        if !state.authorizedUsers.contains(uid) { state.authorizedUsers.append(uid); try saveState(state) }
    }

    private func copyLicenses(_ kegs: [String], into directory: String) -> [String] {
        var notes: [String] = []
        for keg in kegs {
            let name = keg.split(separator: "/").suffix(2).joined(separator: "-")
            guard name.range(of: #"^[A-Za-z0-9@._+-]+$"#, options: .regularExpression) != nil else { continue }
            let target = directory + "/" + name
            guard (try? SecureFile.makeDirectory(target, mode: 0o755)) != nil else { continue }
            let entries = (try? FileManager.default.contentsOfDirectory(atPath: keg)) ?? []
            for entry in entries.sorted() where entry.hasPrefix("LICENSE") || entry.hasPrefix("COPYING")
                || entry == "INSTALL_RECEIPT.json" || entry == "sbom.spdx.json" {
                guard let (data, _) = try? SecureFile.read(keg + "/" + entry, limit: 2 * 1024 * 1024),
                      (try? SecureFile.create(target + "/" + entry, data: data, mode: 0o444)) != nil else { continue }
                notes.append("\(name)/\(entry) sha256=\(Digest.sha256(data))")
            }
        }
        return notes
    }

    private func prune(keeping: [String]) {
        for entry in (try? FileManager.default.contentsOfDirectory(atPath: runtimes)) ?? [] {
            let known = Self.validID(entry) || entry.hasPrefix(".staging-")
            if known && !keeping.contains(entry) { SecureFile.removeTree(runtimes + "/" + entry) }
        }
    }

    /// Removes only the helper's own managed files (runtime copies, supervisor copy,
    /// state and work directory). Nothing outside `root` is touched.
    public func removeAll() {
        for path in [runtimes, supervisors, work, wireGuardRecords, clientCertificates, internetDNSRecord, dnsBaselineRecord, statePath, registryPath] { SecureFile.removeTree(path) }
        rmdir(root)
    }

    // MARK: Client certificates

    /// Writes one session's certificate chain and encrypted key (mode 0600, root only).
    /// openfortivpn opens them by path on every TLS connection of the session (login,
    /// tunnel, logout), so they stay until the session ends.
    public func writeClientCertificate(_ certificate: ClientCertificate, token: String) throws -> ClientCertificateFiles {
        guard UUID(uuidString: token) != nil else { throw HelperFailure(.internalError, "Sessão inválida.") }
        try prepareDirectories()
        try ownership.verifyChain(clientCertificates)
        let paths = clientCertificatePaths(token)
        do {
            try SecureFile.create(paths.certificate, data: Data(certificate.certificate.utf8), mode: 0o600)
            try SecureFile.create(paths.key, data: Data(certificate.key.utf8), mode: 0o600)
        } catch {
            removeClientCertificate(token: token)
            throw error
        }
        return ClientCertificateFiles(certificatePath: paths.certificate, keyPath: paths.key, passphrase: certificate.passphrase)
    }

    public func removeClientCertificate(token: String) {
        let paths = clientCertificatePaths(token)
        unlink(paths.certificate); unlink(paths.key)
    }

    /// Leftovers of sessions that are gone (helper crash or restart).
    public func sweepClientCertificates(keeping live: Set<String>) {
        for entry in (try? FileManager.default.contentsOfDirectory(atPath: clientCertificates)) ?? [] {
            let token = (entry as NSString).deletingPathExtension
            if !live.contains(token) { unlink(clientCertificates + "/" + entry) }
        }
    }

    private func clientCertificatePaths(_ token: String) -> (certificate: String, key: String) {
        (clientCertificates + "/\(token).crt", clientCertificates + "/\(token).key")
    }

    // MARK: Supervisor

    /// Copies the bundle's supervisor into the protected directory from one descriptor,
    /// validates the *copy's* signature (same Team) and returns its path. A later change
    /// to the app bundle cannot affect what root executes.
    public func preparedSupervisor(source: String, requirement: String?) throws -> String {
        guard let requirement else { return source } // Local checks only (configuration built in tests).
        try prepareDirectories()
        let (data, _) = try SecureFile.read(source, limit: 16 * 1024 * 1024)
        let digest = Digest.sha256(data)
        let target = supervisors + "/VPNSupervisor-" + digest.prefix(24)
        if let (existing, _) = try? SecureFile.read(target, limit: 16 * 1024 * 1024), Digest.sha256(existing) == digest {
            try ownership.verifyChain(target)
            return target
        }
        SecureFile.removeTree(target)
        let temporary = target + ".new"
        SecureFile.removeTree(temporary)
        try SecureFile.create(temporary, data: data, mode: 0o555)
        guard CodeTrust.validate(file: URL(fileURLWithPath: temporary), requirement: requirement) else {
            SecureFile.removeTree(temporary)
            throw failure(.runtimeRejected, "O supervisor do bundle não tem a assinatura esperada.")
        }
        guard rename(temporary, target) == 0 else { throw failure(.internalError, "Não foi possível preparar o supervisor.") }
        for entry in (try? FileManager.default.contentsOfDirectory(atPath: supervisors)) ?? []
        where entry.hasPrefix("VPNSupervisor-") && supervisors + "/" + entry != target {
            SecureFile.removeTree(supervisors + "/" + entry)
        }
        try ownership.verifyChain(target)
        return target
    }
}
