import Foundation
import Darwin

// GlobalProtect through OpenConnect (--protocol=gp). The app performs the SAML prelogin and
// browser login; the gateway hands the result back through a globalprotectcallback: URL.
// openconnect stays responsible for the gateway login, TLS, tunnel and logout; the helper's
// own vpnc-script configures addresses, routes and DNS.
//
// Verified on 30/10/2026 against PAN-OS GlobalProtect 6.3 (Azure SAML, REDIRECT) and
// OpenConnect 9.21: the callback is base64 of HTML whose XML fields sit inside an HTML
// comment; openconnect logs in with --usergroup=gateway:prelogin-cookie and the cookie as
// the password on stdin.

/// What a gateway SAML login returns: user name plus one of the two cookie kinds.
public struct GlobalProtectCookie: Codable, Equatable, Sendable {
    public enum Kind: String, Codable, Sendable {
        case preloginCookie = "prelogin-cookie"
        case portalUserauthcookie = "portal-userauthcookie"
    }
    public var username: String
    public var kind: Kind
    public var value: String
    public init(username: String, kind: Kind, value: String) {
        self.username = username; self.kind = kind; self.value = value
    }
}

public enum GlobalProtectRules {
    public static let callbackScheme = "globalprotectcallback"
    public static let maximumCallback = 65536
    /// Read by openconnect as one stdin line (password or cookie).
    public static let maximumSecret = 4096

    /// A cookie travels as one stdin line: visible ASCII only, never empty.
    public static func isValidCookie(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= maximumSecret && value.utf8.allSatisfy { $0 > 0x20 && $0 < 0x7f }
    }

    /// Password on stdin: one line, no control characters.
    public static func isValidPassword(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= maximumSecret
            && !value.unicodeScalars.contains { CharacterSet.controlCharacters.contains($0) }
    }

    /// Parses a `globalprotectcallback:` URL. Throws when the login did not succeed or a field
    /// is missing; never includes the callback text in the error.
    public static func parseCallback(_ raw: String) throws -> GlobalProtectCookie {
        let invalid = RuleViolation(ServiceLanguage.text("Retorno do GlobalProtect inválido."))
        let prefix = callbackScheme + ":"
        guard raw.utf8.count <= maximumCallback, raw.lowercased().hasPrefix(prefix) else { throw invalid }
        var payload = String(raw.dropFirst(prefix.count))
        payload = payload.removingPercentEncoding ?? payload
        payload = String(payload.drop { $0 == "/" })
        if payload.hasPrefix("cas-as=") { payload = String(payload.dropFirst("cas-as=".count)) }
        if !payload.hasPrefix("<") && !payload.hasPrefix("{") {
            var text = payload.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
            text += String(repeating: "=", count: (4 - text.count % 4) % 4)
            guard let data = Data(base64Encoded: text), let decoded = String(data: data, encoding: .utf8) else { throw invalid }
            payload = decoded.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        let status: String?, username: String?, cookie: String?, kind: GlobalProtectCookie.Kind
        if payload.hasPrefix("{") {
            guard let object = try? JSONSerialization.jsonObject(with: Data(payload.utf8)) as? [String: Any] else { throw invalid }
            status = (object["status"] as? String) ?? (object["status"] as? NSNumber)?.stringValue ?? "1"
            username = (object["username"] as? String) ?? (object["user"] as? String)
            if let value = object["preloginCookie"] as? String, !value.isEmpty { kind = .preloginCookie; cookie = value }
            else { kind = .portalUserauthcookie; cookie = object["portalUserauthcookie"] as? String }
        } else {
            // PAN-OS can wrap the result XML in an HTML comment.
            let xml = payload.replacingOccurrences(of: "<!--", with: "").replacingOccurrences(of: "-->", with: "")
            status = field("saml-auth-status", in: xml)
            username = field("saml-username", in: xml)
            if let value = field("prelogin-cookie", in: xml), !value.isEmpty { kind = .preloginCookie; cookie = value }
            else { kind = .portalUserauthcookie; cookie = field("portal-userauthcookie", in: xml) }
        }
        guard status == "1" else {
            throw RuleViolation(ServiceLanguage.text("O gateway informou que a autenticação SAML não foi concluída."))
        }
        guard let username, let cookie, !username.isEmpty, isValidCookie(cookie) else { throw invalid }
        do { try ConnectionRules.checkConfigValue(username, label: ServiceLanguage.text("Usuário")) } catch { throw invalid }
        return GlobalProtectCookie(username: username, kind: kind, value: cookie)
    }

    /// "Só redes internas": IPv4 networks routed through the tunnel instead of the gateway's
    /// policy. Canonical a.b.c.d/len (host bits cleared), /1 to /32, at most 32, no repeats.
    public static let defaultInternalNetworks = ["10.0.0.0/8", "172.16.0.0/12"]
    public static func internalNetworks(_ values: [String]) throws -> [String] {
        var result: [String] = []
        for raw in values {
            let value = raw.trimmingCharacters(in: .whitespaces)
            guard !value.isEmpty else { continue }
            let parts = value.split(separator: "/", omittingEmptySubsequences: false)
            var address = in_addr()
            guard parts.count <= 2, inet_pton(AF_INET, String(parts[0]), &address) == 1,
                  let length = parts.count == 2 ? Int(parts[1]) : 32, (1...32).contains(length) else {
                throw RuleViolation(ServiceLanguage.text("Rede interna inválida: \"\(String(value.prefix(40)))\". Use 10.0.0.0/8."))
            }
            let mask: UInt32 = length == 32 ? .max : ~(UInt32.max >> UInt32(length))
            address.s_addr = (UInt32(bigEndian: address.s_addr) & mask).bigEndian
            var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            inet_ntop(AF_INET, &address, &buffer, socklen_t(buffer.count))
            let canonical = "\(String(cString: buffer))/\(length)"
            if !result.contains(canonical) { result.append(canonical) }
        }
        guard (1...32).contains(result.count) else {
            throw RuleViolation(ServiceLanguage.text("Informe de 1 a 32 redes internas."))
        }
        return result
    }

    /// Text of the first `<name>…</name>`; nil when absent.
    static func field(_ name: String, in xml: String) -> String? {
        guard let start = xml.range(of: "<\(name)>"),
              let end = xml.range(of: "</\(name)>", range: start.upperBound..<xml.endIndex) else { return nil }
        return String(xml[start.upperBound..<end.lowerBound]).trimmingCharacters(in: .whitespacesAndNewlines)
    }
}

/// SAML options of a gateway, from its prelogin.esp answer.
public struct GlobalProtectPrelogin: Equatable, Sendable {
    public enum Method: String, Equatable, Sendable { case redirect = "REDIRECT", post = "POST" }
    /// nil when the gateway authenticates with a password (no SAML).
    public var method: Method?
    /// REDIRECT: the identity provider URL. POST: the HTML form to submit.
    public var request: String
    public var defaultBrowser: Bool
    public init(method: Method?, request: String, defaultBrowser: Bool) {
        self.method = method; self.request = request; self.defaultBrowser = defaultBrowser
    }

    public static func parse(_ data: Data) throws -> GlobalProtectPrelogin {
        let text = String(decoding: data.prefix(256 * 1024), as: UTF8.self)
        guard text.contains("<prelogin-response>") else {
            throw RuleViolation(ServiceLanguage.text("O servidor não respondeu como um gateway GlobalProtect."))
        }
        guard GlobalProtectRules.field("status", in: text) == "Success" else {
            let message = GlobalProtectRules.field("msg", in: text).map { String($0.prefix(200)) } ?? ""
            throw RuleViolation(ServiceLanguage.text("O gateway GlobalProtect recusou o prelogin. \(message)"))
        }
        let browser = GlobalProtectRules.field("saml-default-browser", in: text) == "yes"
        guard let raw = GlobalProtectRules.field("saml-auth-method", in: text), !raw.isEmpty else {
            return GlobalProtectPrelogin(method: nil, request: "", defaultBrowser: browser)
        }
        guard let method = Method(rawValue: raw.uppercased()) else {
            throw RuleViolation(ServiceLanguage.text("Método SAML não suportado: \(String(raw.prefix(32)))."))
        }
        guard let encoded = GlobalProtectRules.field("saml-request", in: text),
              let decoded = Data(base64Encoded: encoded, options: .ignoreUnknownCharacters),
              let request = String(data: decoded, encoding: .utf8), !request.isEmpty else {
            throw RuleViolation(ServiceLanguage.text("O gateway não enviou o pedido SAML."))
        }
        if method == .redirect {
            guard let url = URL(string: request.trimmingCharacters(in: .whitespacesAndNewlines)), url.scheme?.lowercased() == "https" else {
                throw RuleViolation(ServiceLanguage.text("O gateway indicou um login SAML fora de HTTPS."))
            }
        }
        return GlobalProtectPrelogin(method: method, request: request, defaultBrowser: browser)
    }
}

/// openconnect configuration rendered by the helper from validated fields only (one long
/// option per line, read with --config=/dev/fd/3). The server stays in argv; the password or
/// cookie only on stdin. Options such as script-tun, setuid, pid files or certificates are
/// never produced.
public enum OpenConnectConfigRenderer {
    /// The system's SIP-protected bundle; Homebrew's GnuTLS store is user-writable.
    public static let caFile = "/private/etc/ssl/cert.pem"

    public static func render(username: String, cookieKind: GlobalProtectCookie.Kind?, trustedCertificate: String,
                              script: String) throws -> String {
        try ConnectionRules.checkConfigValue(username, label: ServiceLanguage.text("Usuário"))
        guard !username.isEmpty else { throw RuleViolation(ServiceLanguage.text("Informe o usuário.")) }
        let certificate = try ConnectionRules.normalizedCertificate(trustedCertificate)
        guard script.hasPrefix("/"), script.range(of: #"^[A-Za-z0-9/._-]+$"#, options: .regularExpression) != nil else {
            throw RuleViolation(ServiceLanguage.text("Script de rede inválido."))
        }
        var content = "protocol=gp\nos=mac-intel\nnon-inter\ndisable-ipv6\nno-system-trust\ncafile=\(caFile)\n"
        content += "user=\(username)\n"
        if let cookieKind { content += "usergroup=gateway:\(cookieKind.rawValue)\n" }
        if !certificate.isEmpty { content += "servercert=sha256:\(certificate)\n" }
        content += "script=\(script)\n"
        return content
    }

    /// Positional server argument: host or host:port (443 omitted).
    public static func server(host: String, port: Int) throws -> String {
        let host = try ConnectionRules.normalizedHost(host)
        try ConnectionRules.checkPort(port)
        return port == 443 ? host : "\(host):\(port)"
    }
}

extension RuntimeCapabilities {
    /// Options the helper relies on, from openconnect --help.
    public static func looksLikeOpenConnect(_ help: String) -> Bool {
        ["--protocol=gp", "--config=", "--passwd-on-stdin", "--non-inter", "--script=", "--servercert", "--no-system-trust"]
            .allSatisfy(help.contains)
    }
}
