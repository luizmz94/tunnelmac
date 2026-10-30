import Foundation
import AppKit
import CryptoKit
import Security
import VPNHelperShared

/// Browser login of a GlobalProtect gateway. The app asks the gateway's prelogin.esp for the
/// SAML request, opens it in the default browser (where the user's identity provider session
/// lives) and waits for the gateway's `globalprotectcallback:` URL, which macOS hands to the
/// app that claims the scheme. The result (user + cookie) stays in memory only and goes to
/// the helper, which gives it to openconnect on stdin.
///
/// The official GlobalProtect app claims the same scheme: while a login waits, TunnelMac
/// becomes its handler and gives it back to the previous app afterwards. The callback carries
/// no state tied to the request, so only one login waits at a time and a callback that
/// arrives while none waits is ignored.
@MainActor
final class GlobalProtectLogin {
    static let shared = GlobalProtectLogin()
    static let timeout: TimeInterval = 300

    private struct Pending {
        let id: UUID
        let continuation: CheckedContinuation<GlobalProtectCookie, Error>
    }
    private var pending: Pending?
    private var timeoutTask: DispatchWorkItem?
    private var previousHandler: URL?
    private var claimedHandler = false
    private var formFile: URL?
    /// Gateway of the waiting login: its "Authentication Complete" tab is closed afterwards.
    private var gatewayHost: String?
    /// Logins cancelled while their prelogin was still running.
    private var cancelled: Set<UUID> = []
    /// Replaced by local checks: opens a URL in the default browser.
    var openBrowser: (URL) -> Bool = { NSWorkspace.shared.open($0) }

    func isWaiting(for id: UUID) -> Bool { pending?.id == id }

    /// A `globalprotectcallback:` URL from the browser (Apple Event) or pasted by the user.
    func receive(_ text: String) {
        guard pending != nil else { return } // Nothing waits: never kept.
        do { finish(.success(try GlobalProtectRules.parseCallback(text.trimmingCharacters(in: .whitespacesAndNewlines)))) }
        catch let violation as RuleViolation { finish(.failure(AppFailure(violation.message))) }
        catch { finish(.failure(error)) }
    }

    func cancel(_ id: UUID) {
        guard pending?.id == id else { cancelled.insert(id); return }
        finish(.failure(CancellationError()))
    }

    func login(_ connection: Connection, log: @escaping (String) -> Void) async throws -> GlobalProtectCookie {
        guard pending == nil else { throw AppFailure(String(localized: "Outro login GlobalProtect está aguardando o navegador.")) }
        cancelled.remove(connection.id)
        let prelogin = try await Self.prelogin(host: connection.server, port: connection.port, pin: connection.trustedCertificate)
        guard let method = prelogin.method else {
            throw AppFailure(String(localized: "Este gateway não usa SAML. Edite a conexão e escolha Senha."))
        }
        if !prelogin.defaultBrowser {
            log(String(localized: "O gateway não anunciou login pelo navegador padrão; o retorno pode não chegar ao TunnelMac."))
        }
        guard pending == nil else { throw AppFailure(String(localized: "Outro login GlobalProtect está aguardando o navegador.")) }
        if cancelled.remove(connection.id) != nil { throw CancellationError() }
        return try await withCheckedThrowingContinuation { continuation in
            pending = Pending(id: connection.id, continuation: continuation)
            gatewayHost = connection.server
            claimHandler()
            let task = DispatchWorkItem { [weak self] in
                self?.finish(.failure(AppFailure(String(localized: "O login no navegador não retornou em 5 minutos."))))
            }
            timeoutTask = task
            DispatchQueue.main.asyncAfter(deadline: .now() + Self.timeout, execute: task)
            let opened: Bool
            switch method {
            case .redirect:
                opened = URL(string: prelogin.request.trimmingCharacters(in: .whitespacesAndNewlines)).map(openBrowser) ?? false
            case .post:
                opened = openForm(prelogin.request)
            }
            if opened {
                log(String(localized: "Navegador aberto. Conclua o login e permita que o navegador abra o TunnelMac."))
            } else {
                finish(.failure(AppFailure(String(localized: "Não foi possível abrir o navegador padrão."))))
            }
        }
    }

    private func finish(_ result: Result<GlobalProtectCookie, Error>) {
        guard let pending else { return }
        self.pending = nil
        timeoutTask?.cancel(); timeoutTask = nil
        if let formFile { try? FileManager.default.removeItem(at: formFile); self.formFile = nil }
        restoreHandler()
        if case .success = result, let gatewayHost, gatewayHost.range(of: #"^[A-Za-z0-9.-]+$"#, options: .regularExpression) != nil {
            Self.closeReturnTabs(prefix: "https://\(gatewayHost.lowercased())/SAML20/")
        }
        gatewayHost = nil
        pending.continuation.resume(with: result)
    }

    /// Browsers whose AppleScript dictionary lists tabs with a URL.
    static let scriptableBrowsers: Set<String> = ["com.apple.Safari", "com.google.Chrome", "com.brave.Browser",
                                                  "com.microsoft.edgemac", "com.vivaldi.Vivaldi"]

    /// Closes the page a SAML login leaves behind in the default browser (GlobalProtect:
    /// https://<gateway>/SAML20/…; Fortinet: http://127.0.0.1:8020/…), if that browser is running
    /// and scriptable. macOS asks once whether TunnelMac may control it; a refusal only leaves
    /// the tab open. Only tabs starting with `prefix` are closed; the prefix travels as an
    /// argument, never inside the script.
    static func closeReturnTabs(prefix: String) {
        guard let browser = NSWorkspace.shared.urlForApplication(toOpen: URL(string: "https://example.invalid")!),
              let identifier = Bundle(url: browser)?.bundleIdentifier, scriptableBrowsers.contains(identifier),
              !NSRunningApplication.runningApplications(withBundleIdentifier: identifier).isEmpty else { return }
        let script = """
        on run argv
            set prefix to item 1 of argv
            tell application id "\(identifier)"
                repeat with w in windows
                    try
                        close (every tab of w whose URL starts with prefix)
                    end try
                end repeat
            end tell
        end run
        """
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = ["-e", script, prefix]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try? process.run()
    }

    /// SAML POST: the gateway's own form, submitted by the browser from a private file.
    private func openForm(_ html: String) -> Bool {
        let file = FileManager.default.temporaryDirectory.appendingPathComponent("TunnelMac-GlobalProtect-\(UUID().uuidString).html")
        guard FileManager.default.createFile(atPath: file.path, contents: Data(html.utf8), attributes: [.posixPermissions: 0o600]) else { return false }
        formFile = file
        guard let browser = NSWorkspace.shared.urlForApplication(toOpen: URL(string: "https://example.invalid")!) else { return false }
        NSWorkspace.shared.open([file], withApplicationAt: browser, configuration: NSWorkspace.OpenConfiguration())
        return true
    }

    // MARK: URL scheme

    private func claimHandler() {
        let mine = Bundle.main.bundleURL.standardizedFileURL
        guard let probe = URL(string: GlobalProtectRules.callbackScheme + ":") else { return }
        let current = NSWorkspace.shared.urlForApplication(toOpen: probe)?.standardizedFileURL
        guard current != mine else { return }
        previousHandler = current
        claimedHandler = true
        NSWorkspace.shared.setDefaultApplication(at: mine, toOpenURLsWithScheme: GlobalProtectRules.callbackScheme) { _ in }
    }

    private func restoreHandler() {
        guard claimedHandler else { return }
        claimedHandler = false
        defer { previousHandler = nil }
        guard let previous = previousHandler, FileManager.default.fileExists(atPath: previous.path) else { return }
        NSWorkspace.shared.setDefaultApplication(at: previous, toOpenURLsWithScheme: GlobalProtectRules.callbackScheme) { _ in }
    }

    // MARK: Prelogin

    /// POST /ssl-vpn/prelogin.esp, as the GlobalProtect client does. TLS is validated by macOS;
    /// the pinned SHA-256, when set, is accepted only if that validation fails (as openconnect does).
    static func prelogin(host: String, port: Int, pin: String) async throws -> GlobalProtectPrelogin {
        var components = URLComponents()
        components.scheme = "https"
        components.host = host.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        if port != 443 { components.port = port }
        components.path = "/ssl-vpn/prelogin.esp"
        guard let url = components.url else { throw AppFailure(String(localized: "Servidor inválido.")) }
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 30)
        request.httpMethod = "POST"
        request.setValue("PAN GlobalProtect", forHTTPHeaderField: "User-Agent")
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.httpBody = Data("tmp=tmp&clientVer=4100&clientos=Mac&default-browser=1&cas-support=yes".utf8)
        let session = URLSession(configuration: .ephemeral, delegate: PinnedTrust(pin: pin), delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }
        let data: Data
        let response: URLResponse
        do { (data, response) = try await session.data(for: request) }
        catch let error as URLError where [.serverCertificateUntrusted, .serverCertificateHasBadDate, .serverCertificateHasUnknownRoot,
                                            .serverCertificateNotYetValid, .secureConnectionFailed, .cancelled].contains(error.code) {
            throw AppFailure(String(localized: "O certificado do gateway não foi validado pelo macOS. Confira o servidor ou informe o SHA-256 confiável."))
        } catch {
            throw AppFailure(String(localized: "Não foi possível consultar o gateway GlobalProtect: \(error.localizedDescription)"))
        }
        guard (response as? HTTPURLResponse)?.statusCode == 200 else {
            throw AppFailure(String(localized: "O gateway respondeu ao prelogin com HTTP \((response as? HTTPURLResponse)?.statusCode ?? 0)."))
        }
        do { return try GlobalProtectPrelogin.parse(data) }
        catch let violation as RuleViolation { throw AppFailure(violation.message) }
    }

    final class PinnedTrust: NSObject, URLSessionDelegate {
        let pin: String
        init(pin: String) { self.pin = pin.lowercased() }
        func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
            guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
                  let trust = challenge.protectionSpace.serverTrust else { completionHandler(.performDefaultHandling, nil); return }
            if SecTrustEvaluateWithError(trust, nil) { completionHandler(.useCredential, URLCredential(trust: trust)); return }
            guard !pin.isEmpty, let leaf = (SecTrustCopyCertificateChain(trust) as? [SecCertificate])?.first else {
                completionHandler(.cancelAuthenticationChallenge, nil); return
            }
            let digest = SHA256.hash(data: SecCertificateCopyData(leaf) as Data).map { String(format: "%02x", $0) }.joined()
            if digest == pin { completionHandler(.useCredential, URLCredential(trust: trust)) }
            else { completionHandler(.cancelAuthenticationChallenge, nil) }
        }
    }
}
