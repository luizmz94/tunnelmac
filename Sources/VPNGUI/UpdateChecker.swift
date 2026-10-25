import Foundation
import AppKit
import VPNHelperShared

// Update check: reads the public GitHub releases list and tells the user. It never
// downloads, opens or runs a release asset, never runs brew, a shell or AppleScript.
// Installation is AppUpdater's (Sparkle, on the user's click) or Homebrew's.

/// `MAJOR.MINOR.PATCH` with an optional `-rc.N`. A release candidate sorts before its
/// final version: 0.3.0-rc.3 < 0.3.0-rc.4 < 0.3.0 < 0.3.1-rc.1 < 0.3.1.
struct ReleaseVersion: Comparable, Hashable, CustomStringConvertible {
    let major: Int, minor: Int, patch: Int
    let candidate: Int?

    var isPrerelease: Bool { candidate != nil }
    var description: String { "\(major).\(minor).\(patch)" + (candidate.map { "-rc.\($0)" } ?? "") }

    /// Release tag: `v0.3.0` or `v0.3.0-rc.4`, nothing else.
    init?(tag: String) {
        guard tag.hasPrefix("v") else { return nil }
        self.init(String(tag.dropFirst()))
    }

    /// Bare version, as in HelperConstants.releaseVersion.
    init?(_ text: String) {
        // ASCII digits only, without leading/trailing text or whitespace.
        let parts = text.split(separator: "-", maxSplits: 1, omittingEmptySubsequences: false)
        let numbers = parts[0].split(separator: ".", omittingEmptySubsequences: false)
        let values = numbers.compactMap(Self.number)
        guard numbers.count == 3, values.count == 3 else { return nil }
        var candidate: Int?
        if parts.count == 2 {
            guard parts[1].hasPrefix("rc."), let value = Self.number(parts[1].dropFirst(3)) else { return nil }
            candidate = value
        }
        (major, minor, patch) = (values[0], values[1], values[2])
        self.candidate = candidate
    }

    private static func number(_ text: Substring) -> Int? {
        guard !text.isEmpty, text.count <= 6, text.unicodeScalars.allSatisfy({ ("0"..."9").contains($0) }) else { return nil }
        return Int(text)
    }

    static func < (a: ReleaseVersion, b: ReleaseVersion) -> Bool {
        if (a.major, a.minor, a.patch) != (b.major, b.minor, b.patch) {
            return (a.major, a.minor, a.patch) < (b.major, b.minor, b.patch)
        }
        switch (a.candidate, b.candidate) {
        case let (x?, y?): return x < y
        case (_?, nil): return true
        default: return false
        }
    }

    static var current: ReleaseVersion { ReleaseVersion(HelperConstants.releaseVersion)! }
}

/// The fields read from one entry of the GitHub releases API.
struct GitHubRelease: Decodable {
    let tagName: String
    let htmlURL: String
    let draft: Bool
    let prerelease: Bool
    let body: String?
    let publishedAt: Date?
    enum CodingKeys: String, CodingKey {
        case tagName = "tag_name", htmlURL = "html_url", draft, prerelease, body, publishedAt = "published_at"
    }
}

/// A newer release, already validated and reduced to plain text.
struct UpdateOffer: Codable, Equatable {
    let version: String
    let url: String
    let notes: String
    let publishedAt: Date?
    let prerelease: Bool
    var releaseVersion: ReleaseVersion? { ReleaseVersion(version) }
    var pageURL: URL? { UpdateFeed.isTrustedPage(url) ? URL(string: url) : nil }
}

enum UpdateFeed {
    static let repository = "luizmz94/tunnelmac"
    static let endpoint = URL(string: "https://api.github.com/repos/\(repository)/releases?per_page=20")!
    static let releasePagePrefix = "https://github.com/\(repository)/releases/"
    static let repositoryPage = URL(string: "https://github.com/\(repository)")!
    static let maximumResponseSize = 1024 * 1024
    static let timeout: TimeInterval = 15

    static func request(version: String = HelperConstants.releaseVersion) -> URLRequest {
        var request = URLRequest(url: endpoint, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData, timeoutInterval: timeout)
        request.httpMethod = "GET"
        request.httpShouldHandleCookies = false
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        request.setValue("2022-11-28", forHTTPHeaderField: "X-GitHub-Api-Version")
        request.setValue("TunnelMac/\(version)", forHTTPHeaderField: "User-Agent")
        return request
    }

    static func isTrustedPage(_ url: String) -> Bool {
        url.hasPrefix(releasePagePrefix) && URL(string: url)?.host == "github.com"
            && !url.contains(where: { $0.isWhitespace || $0 == "\\" }) && !url.contains("..")
    }

    static func releasePage(for version: String) -> URL? { URL(string: releasePagePrefix + "tag/v" + version) }

    /// Decodes the list, skipping malformed entries instead of failing the whole check.
    static func decode(_ data: Data) throws -> [GitHubRelease] {
        struct Lossy: Decodable {
            let value: GitHubRelease?
            init(from decoder: Decoder) throws { value = try? GitHubRelease(from: decoder) }
        }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode([Lossy].self, from: data).compactMap(\.value)
    }

    /// The highest accepted release above both the running version and a skipped one.
    static func select(_ releases: [GitHubRelease], current: ReleaseVersion, includePrereleases: Bool,
                       skipped: String?) -> UpdateOffer? {
        var floor = current
        if let skipped = skipped.flatMap({ ReleaseVersion($0) }), skipped > floor { floor = skipped }
        let best = releases.compactMap { release -> (ReleaseVersion, GitHubRelease)? in
            guard !release.draft, includePrereleases || !release.prerelease,
                  let version = ReleaseVersion(tag: release.tagName), version > floor,
                  isTrustedPage(release.htmlURL) else { return nil }
            // A candidate tag published as stable still counts as a test version.
            if version.isPrerelease && !includePrereleases { return nil }
            return (version, release)
        }.max { $0.0 < $1.0 }
        guard let (version, release) = best else { return nil }
        return UpdateOffer(version: version.description, url: release.htmlURL, notes: plainText(release.body ?? ""),
                           publishedAt: release.publishedAt, prerelease: release.prerelease || version.isPrerelease)
    }

    /// Release notes as plain text: basic Markdown removed, HTML tags dropped, a few lines.
    static func plainText(_ markdown: String, maxLines: Int = 12, maxCharacters: Int = 1200) -> String {
        var lines: [String] = []
        var previousBlank = true
        let source = markdown.replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: #"(?is)<(script|style)\b.*?</\1\s*>|<!--.*?-->"#, with: "", options: .regularExpression)
        for raw in source.split(separator: "\n", omittingEmptySubsequences: false) {
            var line = String(raw.unicodeScalars.filter { !CharacterSet.controlCharacters.contains($0) || $0 == "\t" })
                .trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("```") { continue }
            line = replace(#"<[^>]*>"#, in: line, with: "")                  // HTML tags
            line = replace(#"!\[[^\]]*\]\([^)]*\)"#, in: line, with: "")     // images
            line = replace(#"\[([^\]]*)\]\([^)]*\)"#, in: line, with: "$1")  // links keep their text
            line = replace(#"^#{1,6}\s*"#, in: line, with: "")                // headings
            line = replace(#"^>\s?"#, in: line, with: "")                     // quotes
            line = replace(#"^[-*+]\s+"#, in: line, with: "• ")               // bullets
            line = replace(#"(\*\*|__|`)"#, in: line, with: "")               // emphasis, code
            line = replace(#"^[-*_]{3,}$"#, in: line, with: "")               // rules
            line = line.trimmingCharacters(in: .whitespaces)
            if line.isEmpty {
                if !previousBlank { lines.append("") }
                previousBlank = true
            } else {
                lines.append(line)
                previousBlank = false
            }
        }
        while lines.last == "" { lines.removeLast() }
        var truncated = lines.count > maxLines
        var text = lines.prefix(maxLines).joined(separator: "\n")
        if text.count > maxCharacters { text = String(text.prefix(maxCharacters)); truncated = true }
        return truncated ? text.trimmingCharacters(in: .whitespacesAndNewlines) + "…" : text
    }

    private static func replace(_ pattern: String, in text: String, with template: String) -> String {
        text.replacingOccurrences(of: pattern, with: template, options: .regularExpression)
    }
}

// MARK: - Transport

enum UpdateTransportError: Error, Equatable {
    case tooLarge, notHTTPS, invalidResponse
}

/// The only network access of the update check; local checks use canned responses.
protocol UpdateTransport: AnyObject {
    /// Calls `completion` once, on the main queue.
    func fetch(_ request: URLRequest, limit: Int, completion: @escaping (Result<(Int, Data), Error>) -> Void)
}

/// Ephemeral session, no cache, no cookies, HTTPS only, no redirects, size-limited body.
final class URLSessionUpdateTransport: NSObject, UpdateTransport, URLSessionDataDelegate {
    private final class Pending {
        var data = Data()
        let limit: Int
        let completion: (Result<(Int, Data), Error>) -> Void
        var failure: Error?
        init(limit: Int, completion: @escaping (Result<(Int, Data), Error>) -> Void) { self.limit = limit; self.completion = completion }
    }
    private let lock = NSLock()
    private var pending: [Int: Pending] = [:]
    /// Local checks only: an in-process URLProtocol answers instead of the network.
    private let protocolClasses: [AnyClass]
    init(protocolClasses: [AnyClass] = []) {
        self.protocolClasses = protocolClasses
        super.init()
    }
    private lazy var session: URLSession = {
        let configuration = URLSessionConfiguration.ephemeral
        if !protocolClasses.isEmpty { configuration.protocolClasses = protocolClasses }
        configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        configuration.urlCache = nil
        configuration.httpCookieStorage = nil
        configuration.httpCookieAcceptPolicy = .never
        configuration.httpShouldSetCookies = false
        configuration.urlCredentialStorage = nil
        configuration.timeoutIntervalForRequest = UpdateFeed.timeout
        configuration.timeoutIntervalForResource = UpdateFeed.timeout
        configuration.waitsForConnectivity = false
        let queue = OperationQueue()
        queue.maxConcurrentOperationCount = 1
        return URLSession(configuration: configuration, delegate: self, delegateQueue: queue)
    }()

    func fetch(_ request: URLRequest, limit: Int, completion: @escaping (Result<(Int, Data), Error>) -> Void) {
        guard request.url?.scheme == "https" else {
            DispatchQueue.main.async { completion(.failure(UpdateTransportError.notHTTPS)) }
            return
        }
        let task = session.dataTask(with: request)
        lock.withLock { pending[task.taskIdentifier] = Pending(limit: limit, completion: completion) }
        task.resume()
    }

    private func entry(_ task: URLSessionTask) -> Pending? { lock.withLock { pending[task.taskIdentifier] } }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse,
                    completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        if response.expectedContentLength > Int64(entry(dataTask)?.limit ?? 0) {
            entry(dataTask)?.failure = UpdateTransportError.tooLarge
            completionHandler(.cancel)
            return
        }
        completionHandler(.allow)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        guard let entry = entry(dataTask) else { return }
        entry.data.append(data)
        if entry.data.count > entry.limit {
            entry.failure = UpdateTransportError.tooLarge
            dataTask.cancel()
        }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil) // The API answers directly; a redirect is answered as received.
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        guard let entry = lock.withLock({ pending.removeValue(forKey: task.taskIdentifier) }) else { return }
        let result: Result<(Int, Data), Error>
        if let failure = entry.failure { result = .failure(failure) }
        else if let error { result = .failure(error) }
        else if let response = task.response as? HTTPURLResponse { result = .success((response.statusCode, entry.data)) }
        else { result = .failure(UpdateTransportError.invalidResponse) }
        DispatchQueue.main.async { entry.completion(result) }
    }
}

/// Used where no request may ever leave the process (local checks runner, visual review).
final class DisabledUpdateTransport: UpdateTransport {
    struct Disabled: Error {}
    func fetch(_ request: URLRequest, limit: Int, completion: @escaping (Result<(Int, Data), Error>) -> Void) {
        DispatchQueue.main.async { completion(.failure(Disabled())) }
    }
}

// MARK: - Checker

/// Schedules checks (launch, Conectar, hourly timer, manual) and keeps the pending offer.
/// Never two checks at a time; automatic checks respect a 4-hour interval measured from
/// the last attempt, successful or not.
@MainActor
final class UpdateChecker: ObservableObject {
    enum Outcome: Equatable { case none, upToDate, available, failed }

    @Published private(set) var offer: UpdateOffer?
    @Published private(set) var checking = false
    @Published private(set) var outcome: Outcome = .none
    /// "Depois": hides the card until the next launch or a newer version is found.
    @Published private(set) var deferred = false
    /// Called once when the launch check finds an offer that was not postponed.
    var onLaunchOffer: ((UpdateOffer) -> Void)?
    private var launchCheck = false

    let preferences: AppPreferences
    let current: ReleaseVersion
    let interval: TimeInterval
    var now: () -> Date
    private let transport: UpdateTransport
    private var timer: Timer?

    init(preferences: AppPreferences, transport: UpdateTransport, current: ReleaseVersion = .current,
         interval: TimeInterval = 4 * 3600, now: @escaping () -> Date = Date.init) {
        self.preferences = preferences
        self.transport = transport
        self.current = current
        self.interval = interval
        self.now = now
        offer = acceptable(preferences.cachedOffer)
        if offer == nil { preferences.cachedOffer = nil }
    }

    static func production(preferences: AppPreferences) -> UpdateChecker {
        let offline = MenuBarCoordinator.isLocalChecks
        return UpdateChecker(preferences: preferences,
                             transport: offline ? DisabledUpdateTransport() : URLSessionUpdateTransport())
    }

    var pending: Bool { offer != nil }
    var showsCard: Bool { offer != nil && !deferred }

    /// Drops an offer that the running version reached, a skipped one or a channel mismatch.
    private func acceptable(_ offer: UpdateOffer?) -> UpdateOffer? {
        guard let offer, let version = offer.releaseVersion, version > current, offer.pageURL != nil else { return nil }
        if let skipped = preferences.skippedVersion.flatMap({ ReleaseVersion($0) }), version <= skipped { return nil }
        if offer.prerelease && !preferences.includePrereleases { return nil }
        return offer
    }

    var isDue: Bool {
        guard let last = preferences.lastUpdateAttempt else { return true }
        let elapsed = now().timeIntervalSince(last)
        return elapsed >= interval || elapsed < 0 // A clock moved backwards does not block forever.
    }

    /// A few seconds after launch.
    func checkOnLaunch() {
        guard preferences.checkForUpdates, !checking else { return }
        launchCheck = true
        check()
    }

    /// Conectar and the hourly timer: only when the interval has passed.
    func checkIfDue() {
        guard preferences.checkForUpdates, isDue else { return }
        check()
    }

    /// The user asked: ignore the interval and the automatic switch.
    func checkNow() { check() }

    func startTimer(every period: TimeInterval = 3600) {
        timer?.invalidate()
        timer = Timer.scheduledTimer(withTimeInterval: period, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.checkIfDue() }
        }
        timer?.tolerance = 300
    }

    func stopTimer() {
        timer?.invalidate()
        timer = nil
    }

    func postpone() { deferred = true }

    func skipOffer() {
        guard let offer else { return }
        preferences.skippedVersion = offer.version
        self.offer = nil
        preferences.cachedOffer = nil
    }

    /// The channel switch changed: re-filter now, look again when candidates were added.
    func channelChanged() {
        if offer != nil, acceptable(offer) == nil { set(nil) }
        if preferences.includePrereleases && preferences.checkForUpdates { check() }
    }

    private func check() {
        guard !checking else { return }
        checking = true
        preferences.lastUpdateAttempt = now()
        transport.fetch(UpdateFeed.request(), limit: UpdateFeed.maximumResponseSize) { [weak self] result in
            MainActor.assumeIsolated { self?.finish(result) }
        }
    }

    private func finish(_ result: Result<(Int, Data), Error>) {
        let launch = launchCheck
        launchCheck = false
        defer { checking = false }
        guard case .success((let status, let data)) = result, status == 200, data.count <= UpdateFeed.maximumResponseSize,
              let releases = try? UpdateFeed.decode(data) else {
            outcome = .failed // 403/429, offline, timeout, invalid JSON: retried by the next scheduled check.
            return
        }
        preferences.lastUpdateSuccess = now()
        let found = UpdateFeed.select(releases, current: current, includePrereleases: preferences.includePrereleases,
                                      skipped: preferences.skippedVersion)
        set(found)
        outcome = found == nil ? .upToDate : .available
        if launch, let found, !deferred { onLaunchOffer?(found) }
    }

    private func set(_ found: UpdateOffer?) {
        if let found, let version = found.releaseVersion,
           offer?.releaseVersion.map({ version > $0 }) ?? true { deferred = false }
        offer = found
        preferences.cachedOffer = found
    }
}

// MARK: - Homebrew

/// Installation by the tap, detected only by the existence of the Caskroom directory.
enum HomebrewInstall {
    static let caskrooms = ["/opt/homebrew/Caskroom/tunnelmac", "/usr/local/Caskroom/tunnelmac"]
    static let upgradeCommand = "brew upgrade --cask luizmz94/tunnelmac/tunnelmac"

    static func detect(caskrooms: [String] = caskrooms,
                       exists: (String) -> Bool = { FileManager.default.fileExists(atPath: $0) }) -> Bool {
        caskrooms.contains(where: exists)
    }

    /// Opens Terminal.app only: no script, no arguments.
    static func openTerminal() {
        guard let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: "com.apple.Terminal") else { return }
        NSWorkspace.shared.openApplication(at: url, configuration: NSWorkspace.OpenConfiguration())
    }

    static func copyCommand() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(upgradeCommand, forType: .string)
    }
}
