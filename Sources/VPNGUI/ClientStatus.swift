import Foundation
import CryptoKit
import VPNHelperShared

/// Plain-language state of one VPN client (openfortivpn or OpenVPN) for the service tab.
enum ClientState: Equatable {
    case notInstalled
    /// Installed but not approved; `latest` set when Homebrew already has a newer version.
    case notApproved(installed: String?, latest: String?)
    /// Homebrew now has a newer version than the approved copy: upgrade, then approve again.
    case updateAvailable(current: String, latest: String)
    /// The Homebrew installation changed (upgrade done) after the approval: approve again.
    case approvalOutdated(approved: String, installed: String?)
    case upToDate(String)

    var needsAction: Bool { if case .upToDate = self { return false }; return true }

    static func evaluate(approved: String?, installed: String?, installedExists: Bool, sourceChanged: Bool, latest: String?) -> ClientState {
        guard let approved else {
            guard installedExists else { return .notInstalled }
            var newer: String?
            if let latest, let installed, ClientVersion.isNewer(latest, than: installed) { newer = latest }
            return .notApproved(installed: installed, latest: newer)
        }
        let newest = [approved, installed].compactMap { $0 }.max { ClientVersion.isNewer($1, than: $0) } ?? approved
        if let latest, ClientVersion.isNewer(latest, than: newest) {
            return .updateAvailable(current: newest, latest: latest)
        }
        // Homebrew went back to an older release: the approved copy in use stays current,
        // and approving the older installation would be a downgrade.
        if let installed, ClientVersion.isNewer(approved, than: installed) { return .upToDate(approved) }
        if sourceChanged || installed.map({ ClientVersion.isNewer($0, than: approved) }) == true {
            return .approvalOutdated(approved: approved, installed: installed)
        }
        return .upToDate(approved)
    }
}

enum ClientVersion {
    /// "2.7.8_1" (Homebrew keg) → "2.7.8".
    static func clean(_ value: String) -> String {
        String(value.split(separator: "_").first ?? Substring(value))
    }
    static func components(_ value: String) -> [Int] {
        clean(value).split { !$0.isNumber }.map { Int($0) ?? 0 }
    }
    static func isNewer(_ candidate: String, than current: String) -> Bool {
        let a = components(candidate), b = components(current)
        guard !a.isEmpty, !b.isEmpty else { return false }
        for index in 0..<max(a.count, b.count) {
            let x = index < a.count ? a[index] : 0, y = index < b.count ? b[index] : 0
            if x != y { return x > y }
        }
        return false
    }
    /// ".../Cellar/openvpn/2.7.8_1/sbin/openvpn" → "2.7.8".
    static func homebrewVersion(of path: String) -> String? {
        let parts = path.split(separator: "/").map(String.init)
        guard let index = parts.firstIndex(of: "Cellar"), parts.count > index + 2 else { return nil }
        return clean(parts[index + 2])
    }
}

/// Local installation facts plus the latest stable version published by Homebrew.
/// The only network request is an anonymous GET of the public formula JSON.
@MainActor
final class ClientVersionChecker: ObservableObject {
    struct Local: Equatable {
        var path: String
        var exists: Bool
        var version: String?
        var sourceChanged: Bool
    }
    @Published private(set) var latest: [RuntimeKind: String] = [:]
    @Published private(set) var local: [RuntimeKind: Local] = [:]
    @Published private(set) var checking = false
    private let transport: UpdateTransport
    private let helper: HelperClient?
    private let automaticUpdates: () -> Bool
    private var lastCheck: Date?
    private var localGeneration = 0

    init(transport: UpdateTransport, helper: HelperClient? = nil,
         automaticUpdates: @escaping () -> Bool = { UserDefaults.standard.object(forKey: AppPreferences.Key.checkForUpdates) as? Bool != false }) {
        self.transport = transport; self.helper = helper; self.automaticUpdates = automaticUpdates
    }

    static func production(helper: HelperClient? = nil) -> ClientVersionChecker {
        let offline = MenuBarCoordinator.isLocalChecks
        return ClientVersionChecker(transport: offline ? DisabledUpdateTransport() : URLSessionUpdateTransport(), helper: helper)
    }

    func formulaURL(_ kind: RuntimeKind) -> URL {
        URL(string: "https://formulae.brew.sh/api/formula/\(kind.executableName).json")!
    }

    /// Reads the installations and, at most every 10 minutes unless forced, asks Homebrew.
    func refresh(status: HelperStatus?, force: Bool = false) {
        localGeneration += 1
        let generation = localGeneration
        Task {
            let facts = await Task.detached(priority: .utility) {
                RuntimeKind.allCases.map { kind -> (RuntimeKind, Local) in
                    let path = BinaryLocator.defaultPath(for: kind)
                    let resolved = URL(fileURLWithPath: path).resolvingSymlinksInPath().path
                    let exists = FileManager.default.isExecutableFile(atPath: path)
                    let changed = status?.runtime(kind).map { RuntimeSourceCheck.changed($0) } ?? false
                    return (kind, Local(path: path, exists: exists,
                                        version: exists ? ClientVersion.homebrewVersion(of: resolved) : nil, sourceChanged: changed))
                }
            }.value
            guard generation == self.localGeneration else { return }
            self.local = Dictionary(uniqueKeysWithValues: facts)
            // Re-inspect the CURRENT installation, resolving opt/keg symlinks afresh.
            // Hashing old resolved source files alone misses a newly installed dependency.
            if let helper = self.helper {
                for (kind, fact) in facts {
                    guard let expected = status?.runtime(kind)?.inventoryDigest else { continue }
                    let request: HelperRequest
                    switch kind {
                    case .openfortivpn: request = .inspectRuntime(path: fact.path)
                    case .openvpn: request = .inspectOpenVPNRuntime(path: fact.path)
                    case .wireguard: request = .inspectWireGuardRuntime(path: fact.path)
                    case .openconnect: request = .inspectOpenConnectRuntime(path: fact.path)
                    }
                    helper.request(request, timeout: 60) { [weak self] result in
                        guard let self, generation == self.localGeneration else { return }
                        if case .success(.inspection(let inspection)) = result {
                            self.local[kind]?.sourceChanged = inspection.digest != expected
                        } else { self.local[kind]?.sourceChanged = true }
                    }
                }
            }
        }
        guard force || automaticUpdates() else { return }
        guard !checking else { return }
        if !force, let lastCheck, Date().timeIntervalSince(lastCheck) < 600 { return }
        lastCheck = Date()
        checking = true
        var remaining = RuntimeKind.allCases.count
        for kind in RuntimeKind.allCases {
            var request = URLRequest(url: formulaURL(kind))
            request.setValue("application/json", forHTTPHeaderField: "Accept")
            request.setValue("TunnelMac/\(HelperConstants.releaseVersion)", forHTTPHeaderField: "User-Agent")
            transport.fetch(request, limit: 512 * 1024) { [weak self] result in
                guard let self else { return }
                if case .success((200, let data)) = result, let version = Self.stableVersion(data) { self.latest[kind] = version }
                remaining -= 1
                if remaining == 0 { self.checking = false }
            }
        }
    }

    static func stableVersion(_ data: Data) -> String? {
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let versions = object["versions"] as? [String: Any], let stable = versions["stable"] as? String,
              stable.range(of: #"^[0-9][0-9A-Za-z.+-]{0,31}$"#, options: .regularExpression) != nil else { return nil }
        return stable
    }

    func state(_ kind: RuntimeKind, status: HelperStatus?) -> ClientState {
        let info = local[kind]
        return ClientState.evaluate(approved: status?.runtime(kind).map { ClientVersion.clean($0.version) },
                                    installed: info?.version, installedExists: info?.exists ?? false,
                                    sourceChanged: info?.sourceChanged ?? false, latest: latest[kind])
    }

    /// Test seam.
    func setForChecks(local: [RuntimeKind: Local], latest: [RuntimeKind: String]) {
        self.local = local; self.latest = latest; lastCheck = Date()
    }
}
