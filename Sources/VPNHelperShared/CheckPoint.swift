import Foundation
import Security

// Check Point Remote Access through snx-rs (standalone mode). snx-rs speaks the gateway's
// protocol, authenticates, creates the utun and sets routes and DNS itself; the helper only
// renders its configuration (fd 3, password inside), detects when the tunnel is ready and
// removes what a killed snx-rs leaves behind. No site name and no official client.
//
// Verified on 02/11/2026 against snx-rs 6.6.1 (Homebrew, tag v6.6.1) and a Check Point
// gateway with IPsec IKEv1: `-c <path>` reads `key=value` lines (`#` comments, quotes and
// surrounding spaces stripped, empty values ignored), the password is base64, and the user
// interface text follows the macOS locale of the process, not LANG.

/// One login type the gateway shows (`snx-rs -m info`).
public struct CheckPointLoginOption: Codable, Equatable, Sendable, Identifiable {
    public var displayName: String
    public var id: String
    /// Authentication factors in order (password, user_defined, identity_provider, certificate…).
    public var factors: [String]
    public init(displayName: String, id: String, factors: [String]) {
        self.displayName = displayName; self.id = id; self.factors = factors
    }
}

public enum CheckPointRules {
    /// Lines the helper writes into the session log: the tunnel is up (routes and DNS set by
    /// snx-rs), or it looked up but is missing a piece (the helper stops snx-rs).
    public static let networkReady = "[+] TunnelMac: túnel Check Point pronto em "
    public static let networkFailure = "[!] TunnelMac: túnel Check Point incompleto:"
    /// The tunnel was not ready when the connection timeout ended (followed by "<seconds> s.").
    public static let networkTimeout = "[!] TunnelMac: túnel Check Point não ficou pronto em "
    /// The ICA (Check Point internal CA) a connection trusts, DER encoded.
    public static let maximumAuthorityDER = 16 * 1024
    /// Base64 of the password fits one config line.
    public static let maximumPassword = 4096
    /// v1 logs in with a single password factor; anything else needs a TTY or a browser.
    public static let supportedFactors: Set<String> = ["password", "user_defined"]

    public static func isValidLoginType(_ value: String) -> Bool {
        value.range(of: #"^[A-Za-z0-9_.-]{1,64}$"#, options: .regularExpression) != nil
    }

    /// Not empty, bounded, no control characters.
    public static func isValidPassword(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= maximumPassword
            && !value.unicodeScalars.contains { CharacterSet.controlCharacters.contains($0) }
    }

    public static func isSupported(_ option: CheckPointLoginOption) -> Bool {
        option.factors.count == 1 && supportedFactors.contains(option.factors[0])
    }

    /// Lines `[<display name>]: <id> (<factors>)` of `snx-rs -m info`. This format is not
    /// translated by snx-rs (unlike the other labels); any other line is ignored.
    public static func loginOptions(fromInfo output: String) -> [CheckPointLoginOption] {
        var options: [CheckPointLoginOption] = []
        for line in output.split(whereSeparator: \.isNewline).map(String.init) {
            guard let match = line.firstMatch(of: #/^\s*\[(.{1,80})\]: ([A-Za-z0-9_.-]{1,64}) \(([a-z_, ]*)\)$/#) else { continue }
            let factors = match.3.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
            let option = CheckPointLoginOption(displayName: String(match.1), id: String(match.2), factors: factors)
            if !options.contains(where: { $0.id == option.id }) { options.append(option) }
            if options.count == 32 { break }
        }
        return options
    }

    /// "Internal CA fingerprint": twelve words of one to four capital letters. Recognized by
    /// the value alone, since the label is translated.
    public static func fingerprintWords(fromInfo output: String) -> String? {
        for line in output.split(whereSeparator: \.isNewline) {
            guard let separator = line.range(of: ": ") else { continue }
            let value = line[separator.upperBound...].trimmingCharacters(in: .whitespaces)
            let words = value.split(separator: " ")
            if words.count == 12, words.allSatisfy({ $0.range(of: #"^[A-Z]{1,4}$"#, options: .regularExpression) != nil }) {
                return words.joined(separator: " ")
            }
        }
        return nil
    }

    /// "Supported protocols" (display only): the first comma list of known protocol names.
    public static func supportedProtocols(fromInfo output: String) -> String? {
        let known: Set<String> = ["IPSec", "SSL", "L2TP", "IKEv1_Only", "IKEv2", "IKEv2_Only"]
        for line in output.split(whereSeparator: \.isNewline) {
            guard let separator = line.range(of: ": ") else { continue }
            let items = line[separator.upperBound...].split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
            if items.count > 1, items.allSatisfy(known.contains) { return items.joined(separator: ", ") }
        }
        return nil
    }

    /// Checks a trusted authority (DER, at most 16 KB, a certificate macOS can parse).
    public static func checkAuthority(_ der: Data) throws {
        guard !der.isEmpty, der.count <= maximumAuthorityDER, SecCertificateCreateWithData(nil, der as CFData) != nil else {
            throw RuleViolation(ServiceLanguage.text("Autoridade do gateway Check Point inválida."))
        }
    }

    public static func pem(_ der: Data) -> String {
        "-----BEGIN CERTIFICATE-----\n" + der.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
            + "\n-----END CERTIFICATE-----\n"
    }

    /// `server-name` as snx-rs reads it: host, or host:port when the port is not 443.
    public static func server(host: String, port: Int) throws -> String {
        let host = try ConnectionRules.normalizedHost(host)
        try ConnectionRules.checkPort(port)
        if port == 443 { return host }
        guard !host.contains(":") || host.hasPrefix("[") else {
            throw RuleViolation(ServiceLanguage.text("Informe um endereço IPv6 entre colchetes para usar outra porta."))
        }
        return "\(host):\(port)"
    }
}

/// What snx-rs 6.6.1 prints, in each of its 17 languages (crates/i18n/assets/*/main.ftl).
/// The language follows the macOS preferences of the process, so the app and the helper
/// recognize every translation; the helper's own markers stay the primary signal.
public enum CheckPointOutput {
    public enum Kind: Equatable, Sendable {
        case connected, disconnected, certificateFailed, authenticationFailed, needsTTY, unsupportedLoginType
    }

    /// cli-tunnel-connected
    public static let connected = [
        "Tunel připojen, stiskněte Ctrl+C pro ukončení.",
        "Tunnel forbundet, tryk Ctrl+C for at afslutte.",
        "Tunnel verbunden, drücken Sie Strg+C zum Beenden.",
        "Tunnel connected, press Ctrl-C to exit.",
        "Túnel conectado, presione Ctrl+C para salir.",
        "Tunneli yhdistetty, paina Ctrl+C lopettaaksesi.",
        "Tunnel connecté, appuyez sur Ctrl+C pour quitter.",
        "Tunel povezan, pritisnite Ctrl-C za izlaz.",
        "Tunnel connesso, premi Ctrl+C per uscire.",
        "Tunnel verbonden, druk op Ctrl+C om af te sluiten.",
        "Tunnel tilkoblet, trykk Ctrl+C for å avslutte.",
        "Tunel połączony, naciśnij Ctrl+C aby zakończyć.",
        "Túnel conectado, pressione Control+c para sair.",
        "Túnel conectado, prima Ctrl+C para sair.",
        "Туннель подключен, нажмите Ctrl-C для выхода.",
        "Tunel pripojený, stlačte Ctrl+C pre ukončenie.",
        "Tunnel ansluten, tryck Ctrl+C för att avsluta."
    ]
    /// cli-tunnel-disconnected
    public static let disconnected = [
        "Tunel odpojen", "Tunnel forbindelse afbrudt", "Tunnel getrennt", "Tunnel disconnected", "Túnel desconectado",
        "Tunneli katkaistu", "Tunnel déconnecté", "Tunel prekinut", "Tunnel disconnesso", "Tunnel verbroken",
        "Tunnel frakoblet", "Tunel rozłączony", "Túnel desconectado", "Túnel desconectado", "Туннель отключен",
        "Tunel odpojený", "Tunnel frånkopplad"
    ]
    /// error-certificate-verify-failed, plus OpenSSL's own English text.
    public static let certificateFailed = [
        "Ověření TLS certifikátu selhalo.", "TLS-certifikatvalidering mislykkedes.", "TLS-Zertifikatüberprüfung fehlgeschlagen.",
        "TLS certificate validation failed.", "Falló la validación del certificado TLS.", "TLS-varmenteen vahvistus epäonnistui.",
        "La validation du certificat TLS a échoué.", "TLS validacija certifikata nije uspjela.", "Validazione del certificato TLS fallita.",
        "TLS-certificaatvalidatie mislukt.", "TLS-sertifikatvalidering mislyktes.", "Weryfikacja certyfikatu TLS nie powiodła się.",
        "Validação do certificado TLS falhou.", "Проверка TLS-сертификата не удалась.", "Overenie TLS certifikátu zlyhalo.",
        "TLS-certifikatvalidering misslyckades.", "certificate verify failed"
    ]
    /// error-auth-failed
    public static let authenticationFailed = [
        "Ověření selhalo", "Godkendelse mislykkedes", "Authentifizierung fehlgeschlagen", "Authentication failed",
        "Error de autenticación", "Tunnistus epäonnistui", "Échec de l'authentification", "Autentifikacija nije uspjela",
        "Autenticazione fallita", "Authenticatie mislukt", "Autentisering mislyktes", "Uwierzytelnianie nie powiodło się",
        "A autenticação falhou", "Autenticação falhou", "Ошибка аутентификации", "Overenie zlyhalo", "Autentisering misslyckades"
    ]
    /// error-no-tty: a login step asked for input (a second factor, for instance).
    public static let needsTTY = [
        "Žádný TTY připojen pro vstup uživatele", "Ingen TTY tilsluttet til brugerinput", "Kein angeschlossenes TTY für Benutzereingabe",
        "No attached TTY to get user input", "No hay TTY conectado para obtener la entrada del usuario",
        "Ei TTY-yhteyttä käyttäjän syötteeseen", "Pas de TTY attaché pour obtenir la saisie utilisateur",
        "Nema priključenog TTY-a za korisnički unos", "Nessun TTY collegato per ottenere l'input dell'utente",
        "Geen TTY aangesloten voor gebruikersinvoer", "Ingen TTY tilkoblet for brukerinndata",
        "Brak podłączonego TTY do wprowadzania danych przez użytkownika", "Sem TTY conectado para entrada do usuário",
        "Sem TTY ligado para entrada do utilizador", "Нет подключенного TTY для получения ввода пользователя",
        "Žiadny TTY pripojený pre vstup používateľa", "Ingen TTY ansluten för användarinput"
    ]
    /// error-unsupported-login-type
    public static let unsupportedLoginType = [
        "Nepodporovaný typ přihlášení", "Logintypen understøttes ikke", "Nicht unterstützter Anmeldetyp", "Unsupported login type",
        "Tipo de inicio de sesión no compatible", "Kirjautumistyyppiä ei tueta", "Type de connexion non pris en charge",
        "Nepodržani tip prijave", "Tipo di accesso non supportato", "Niet-ondersteund inlogtype", "Innloggingstypen støttes ikke",
        "Nieobsługiwany typ logowania", "Tipo de login não suportado", "Tipo de início de sessão não suportado",
        "Неподдерживаемый тип входа", "Nepodporovaný typ prihlásenia", "Inloggningstypen stöds inte"
    ]

    public static func classify(_ line: String) -> Kind? {
        let text = line.trimmingCharacters(in: .whitespaces)
        if connected.contains(where: text.hasSuffix) { return .connected }
        if certificateFailed.contains(where: text.contains) { return .certificateFailed }
        if needsTTY.contains(where: text.contains) { return .needsTTY }
        if unsupportedLoginType.contains(where: text.contains) { return .unsupportedLoginType }
        if authenticationFailed.contains(where: text.contains) { return .authenticationFailed }
        if disconnected.contains(where: { text == $0 || text.hasSuffix(" " + $0) }) { return .disconnected }
        return nil
    }

    /// The tunnel interface from the connection block (`Interface: utun8`, label translated).
    public static func interface(_ line: String) -> String? {
        guard let match = line.firstMatch(of: #/^\s*[^:\[\]]{1,40}:\s+(utun[0-9]{1,3})\s*$/#) else { return nil }
        return String(match.1)
    }
}

/// snx-rs configuration rendered by the helper from validated fields only. Every key is
/// fixed here: options such as ignore-server-cert, cert-path or if-name are never produced.
public enum CheckPointConfigRenderer {
    public static let keys = ["server-name", "user-name", "password", "login-type", "tunnel-type", "ca-cert",
                              "default-route", "keychain", "ike-persist", "no-keepalive", "log-level"]

    public static func render(host: String, port: Int, username: String, password: String, loginType: String,
                              authorityPath: String?, allTraffic: Bool) throws -> String {
        let server = try CheckPointRules.server(host: host, port: port)
        try check(username, label: ServiceLanguage.text("Usuário"))
        guard CheckPointRules.isValidPassword(password) else {
            throw RuleViolation(ServiceLanguage.text("Senha vazia, longa demais ou com caracteres de controle."))
        }
        guard CheckPointRules.isValidLoginType(loginType) else {
            throw RuleViolation(ServiceLanguage.text("Tipo de login inválido: use letras, números, ponto, hífen ou sublinhado."))
        }
        var content = "server-name=\(server)\nuser-name=\(username)\n"
        content += "password=\(Data(password.utf8).base64EncodedString())\n"
        content += "login-type=\(loginType)\ntunnel-type=ipsec\n"
        if let authorityPath {
            guard authorityPath.hasPrefix("/"), authorityPath.range(of: #"^[A-Za-z0-9/._-]{1,512}$"#, options: .regularExpression) != nil else {
                throw RuleViolation(ServiceLanguage.text("Arquivo da autoridade inválido."))
            }
            content += "ca-cert=\(authorityPath)\n"
        }
        content += "default-route=\(allTraffic)\nkeychain=false\nike-persist=false\nno-keepalive=false\nlog-level=info\n"
        return content
    }

    /// snx-rs strips quotes and spaces around a value and ignores an empty one: such a value
    /// would not reach it as written.
    static func check(_ value: String, label: String) throws {
        try ConnectionRules.checkConfigValue(value, label: label)
        guard !value.isEmpty, !"\"'".contains(value.first!), !"\"'".contains(value.last!) else {
            throw RuleViolation(ServiceLanguage.text("\(label): vazio ou entre aspas não é suportado."))
        }
    }
}

/// Check Point session through snx-rs. The password goes only into the protected
/// configuration (fd 3); the authority is written by the helper to a root-only file.
public struct CheckPointRequest: Codable, Equatable, Sendable {
    public var connectionID: UUID
    public var host: String
    public var port: Int
    public var username: String
    public var password: String
    public var loginType: String
    public var authorityDER: Data?
    /// Default route through the tunnel (`default-route=true`); otherwise the gateway's routes.
    public var allTraffic: Bool
    public init(connectionID: UUID, host: String, port: Int, username: String, password: String, loginType: String,
                authorityDER: Data?, allTraffic: Bool) {
        self.connectionID = connectionID; self.host = host; self.port = port; self.username = username
        self.password = password; self.loginType = loginType; self.authorityDER = authorityDER; self.allTraffic = allTraffic
    }

    /// Validation run by the helper: every rule of the renderer, plus the authority.
    public func validated() throws -> CheckPointRequest {
        var value = self
        value.host = try ConnectionRules.normalizedHost(host)
        _ = try CheckPointConfigRenderer.render(host: value.host, port: port, username: username, password: password,
                                                loginType: loginType, authorityPath: nil, allTraffic: allTraffic)
        if let authorityDER { try CheckPointRules.checkAuthority(authorityDER) }
        return value
    }
}

/// `snx-rs -m info` of a gateway, run by the helper as an unprivileged user.
public struct CheckPointGatewayQuery: Codable, Equatable, Sendable {
    public var host: String
    public var port: Int
    public var authorityDER: Data?
    public init(host: String, port: Int, authorityDER: Data?) { self.host = host; self.port = port; self.authorityDER = authorityDER }

    public func validated() throws -> (server: String, authority: Data?) {
        let server = try CheckPointRules.server(host: host, port: port)
        if let authorityDER { try CheckPointRules.checkAuthority(authorityDER) }
        return (server, authorityDER)
    }
}

public struct CheckPointGatewayInfo: Codable, Equatable, Sendable {
    public var loginOptions: [CheckPointLoginOption]
    /// The gateway's "Internal CA fingerprint" words, to compare with the administrator.
    public var fingerprintWords: String?
    /// Display only.
    public var supportedProtocols: String?
    /// Why the query failed, already in the app's language; nil on success.
    public var failure: String?
    public init(loginOptions: [CheckPointLoginOption], fingerprintWords: String?, supportedProtocols: String?, failure: String?) {
        self.loginOptions = loginOptions; self.fingerprintWords = fingerprintWords
        self.supportedProtocols = supportedProtocols; self.failure = failure
    }
}

extension RuntimeCapabilities {
    /// Options the helper relies on, from snx-rs --help and --version.
    public static func looksLikeSnxRs(help: String, version: String) -> Bool {
        ["VPN client for Check Point security gateway", "--config-file", "--login-type", "--ca-cert", "--mode"].allSatisfy(help.contains)
            && version.range(of: #"^snx-rs [0-9]"#, options: .regularExpression) != nil
    }
}
