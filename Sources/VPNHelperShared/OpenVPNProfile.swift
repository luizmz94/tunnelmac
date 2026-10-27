import Foundation

// OpenVPN profiles, shared by the app (import) and the helper (validation before root runs it).
//
// A profile is reduced to an allowlist: directives that only describe the tunnel and its
// cryptography, plus inline key material. Anything that runs programs, loads modules, reads
// or writes files, opens a management channel or changes identity is never rendered. File
// references are resolved by the app at import time (inside the imported folder only) and
// become inline blocks, so the helper never opens a path named by a profile.
//
// Verified against OpenVPN 2.7.8 (man openvpn, options.c parse_line): one option per line,
// whitespace separated, "..." with \\ and \" escapes, '...' literal, # or ; starting a
// comment at a token boundary, inline files as <tag> ... </tag> lines.

public struct OpenVPNDirective: Codable, Equatable, Sendable {
    public var name: String
    public var arguments: [String]
    public init(_ name: String, _ arguments: [String] = []) { self.name = name; self.arguments = arguments }
}

public struct OpenVPNBlock: Codable, Equatable, Sendable {
    public var tag: String
    public var content: String
    public init(tag: String, content: String) { self.tag = tag; self.content = content }
}

/// Raw syntax of a config file, before any policy.
public struct OpenVPNConfigText: Equatable, Sendable {
    public struct Line: Equatable, Sendable {
        public var number: Int
        public var directive: OpenVPNDirective
    }
    public var lines: [Line] = []
    public var blocks: [OpenVPNBlock] = []
    /// "#viscosity name X" and similar comments (key → value), informational only.
    public var viscosity: [String: String] = [:]

    public static let maximumSize = 256 * 1024

    public static func parse(_ text: String) throws -> OpenVPNConfigText {
        guard text.utf8.count <= maximumSize else { throw RuleViolation(ServiceLanguage.text("Perfil OpenVPN acima de 256 KB.")) }
        guard !text.unicodeScalars.contains("\0") else { throw RuleViolation(ServiceLanguage.text("Perfil OpenVPN contém bytes nulos.")) }
        var result = OpenVPNConfigText()
        var openBlock: (tag: String, lines: [String], start: Int)?
        let rawLines = text.replacingOccurrences(of: "\r\n", with: "\n").replacingOccurrences(of: "\r", with: "\n")
            .split(separator: "\n", omittingEmptySubsequences: false)
        for (index, raw) in rawLines.enumerated() {
            let number = index + 1
            let line = String(raw)
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if let block = openBlock {
                if trimmed == "</\(block.tag)>" {
                    result.blocks.append(OpenVPNBlock(tag: block.tag, content: block.lines.joined(separator: "\n")))
                    openBlock = nil
                } else {
                    openBlock?.lines.append(line)
                }
                continue
            }
            if trimmed.hasPrefix("<") {
                guard trimmed.hasSuffix(">"), !trimmed.hasPrefix("</"),
                      let tag = Optional(String(trimmed.dropFirst().dropLast())),
                      tag.range(of: #"^[a-z0-9-]{1,32}$"#, options: .regularExpression) != nil else {
                    throw RuleViolation(ServiceLanguage.text("Linha \(number): marcação inválida \(trimmed.prefix(40))."))
                }
                openBlock = (tag, [], number)
                continue
            }
            if trimmed.hasPrefix("#") || trimmed.hasPrefix(";") {
                let comment = trimmed.drop { $0 == "#" || $0 == ";" }.trimmingCharacters(in: .whitespaces)
                if comment.hasPrefix("viscosity ") {
                    let parts = comment.dropFirst("viscosity ".count).split(separator: " ", maxSplits: 1).map(String.init)
                    if parts.count == 2 { result.viscosity[parts[0]] = parts[1] }
                }
                continue
            }
            let tokens = try tokenize(line, number: number)
            guard let name = tokens.first else { continue }
            result.lines.append(Line(number: number, directive: OpenVPNDirective(name, Array(tokens.dropFirst()))))
        }
        if let block = openBlock { throw RuleViolation(ServiceLanguage.text("Linha \(block.start): bloco <\(block.tag)> sem fechamento.")) }
        return result
    }

    static func tokenize(_ line: String, number: Int) throws -> [String] {
        var tokens: [String] = []
        var current = ""
        var inToken = false
        var quote: Character?
        var escape = false
        for character in line {
            if escape {
                current.append(character); escape = false; continue
            }
            if let open = quote {
                if open == "\"" && character == "\\" { escape = true; continue }
                if character == open { quote = nil; continue }
                current.append(character)
                continue
            }
            if character == " " || character == "\t" {
                if inToken { tokens.append(current); current = ""; inToken = false }
                continue
            }
            if !inToken && (character == "#" || character == ";") { break }
            inToken = true
            if character == "\\" { escape = true; continue }
            if character == "\"" || character == "'" { quote = character; continue }
            current.append(character)
        }
        if quote != nil { throw RuleViolation(ServiceLanguage.text("Linha \(number): aspas sem fechamento.")) }
        if escape { throw RuleViolation(ServiceLanguage.text("Linha \(number): barra invertida no fim da linha.")) }
        if inToken { tokens.append(current) }
        return tokens
    }
}

/// A profile that passed the allowlist. Its text form is what the app stores and what
/// travels to the helper; the helper parses and checks it again before rendering.
public struct OpenVPNProfile: Equatable, Sendable {
    public var directives: [OpenVPNDirective]
    public var blocks: [OpenVPNBlock]
    public init(directives: [OpenVPNDirective], blocks: [OpenVPNBlock]) {
        self.directives = directives; self.blocks = blocks
    }

    public static let maximumNormalizedSize = 96 * 1024

    /// Strict form: only allowlisted directives and inline blocks, no file references.
    public static func validated(_ text: String) throws -> OpenVPNProfile {
        guard text.utf8.count <= maximumNormalizedSize else { throw RuleViolation(ServiceLanguage.text("Perfil OpenVPN acima de 96 KB.")) }
        let parsed = try OpenVPNConfigText.parse(text)
        let profile = OpenVPNProfile(directives: parsed.lines.map(\.directive), blocks: parsed.blocks)
        try profile.check()
        return profile
    }

    public func check() throws {
        var seenBlocks = Set<String>()
        for block in blocks {
            guard OpenVPNRules.blockTags.contains(block.tag) else {
                throw RuleViolation(ServiceLanguage.text("Bloco <\(block.tag)> não é suportado."))
            }
            guard seenBlocks.insert(block.tag).inserted else { throw RuleViolation("Bloco <\(block.tag)> repetido.") }
            try OpenVPNRules.checkBlock(block)
        }
        guard directives.count <= 512 else { throw RuleViolation(ServiceLanguage.text("Diretivas demais no perfil.")) }
        for directive in directives {
            if OpenVPNRules.blockTags.contains(directive.name) {
                // Key material must be inline; a path would make root open a file.
                throw RuleViolation(ServiceLanguage.text("\(directive.name): referência a arquivo não é aceita; o material precisa estar no próprio perfil."))
            }
            guard let rule = OpenVPNRules.allowed[directive.name] else {
                throw RuleViolation(ServiceLanguage.text("Diretiva não suportada: \(directive.name)."))
            }
            try rule.check(directive)
        }
        guard directives.contains(where: { $0.name == "remote" }) else {
            throw RuleViolation(ServiceLanguage.text("O perfil não tem nenhum servidor (remote)."))
        }
        guard directives.contains(where: { $0.name == "client" })
                || (directives.contains { $0.name == "tls-client" } && directives.contains { $0.name == "pull" }) else {
            throw RuleViolation(ServiceLanguage.text("O perfil não é de cliente (falta client)."))
        }
        if let dev = directives.last(where: { $0.name == "dev" })?.arguments.first, !dev.hasPrefix("tun") && !dev.hasPrefix("utun") {
            throw RuleViolation(ServiceLanguage.text("Somente interfaces tun são suportadas no macOS."))
        }
        // Some check that a certificate of the same CA issued to a client cannot pass as the server.
        let verifiesServer = directives.contains { directive in
            switch directive.name {
            case "remote-cert-tls", "ns-cert-type": return directive.arguments == ["server"]
            case "verify-x509-name": return true
            case "remote-cert-eku": return ["TLS Web Server Authentication", "serverAuth", "1.3.6.1.5.5.7.3.1"].contains(directive.arguments.first ?? "")
            default: return false
            }
        }
        guard verifiesServer else {
            throw RuleViolation(ServiceLanguage.text("O perfil não verifica a identidade do servidor (remote-cert-tls server ou verify-x509-name). Solicite um perfil atualizado ao administrador."))
        }
        for directive in directives {
            if directive.name == "tls-cert-profile", directive.arguments.first == "insecure" {
                throw RuleViolation(ServiceLanguage.text("tls-cert-profile insecure não é aceito; solicite uma política TLS atualizada."))
            }
            if ["tls-version-min", "tls-version-max"].contains(directive.name),
               ["1.0", "1.1"].contains(directive.arguments.first ?? "") {
                throw RuleViolation(ServiceLanguage.text("TLS anterior a 1.2 não é aceito; solicite um perfil atualizado."))
            }
        }
        guard seenBlocks.contains("ca") else { throw RuleViolation(ServiceLanguage.text("O perfil não tem a autoridade certificadora (<ca>).")) }
        if seenBlocks.contains("cert") != seenBlocks.contains("key") {
            throw RuleViolation(ServiceLanguage.text("Certificado e chave do cliente precisam vir juntos."))
        }
        if seenBlocks.contains("key"), let key = blocks.first(where: { $0.tag == "key" }),
           key.content.contains("ENCRYPTED") {
            throw RuleViolation(ServiceLanguage.text("Chave privada protegida por senha ainda não é suportada."))
        }
    }

    public var requiresCredentials: Bool { directives.contains { $0.name == "auth-user-pass" } }

    /// Servers in order, for display ("host:port/proto").
    public var remotes: [OpenVPNRemote] {
        let defaultPort = directives.last { $0.name == "port" || $0.name == "rport" }?.arguments.first.flatMap(Int.init) ?? 1194
        let defaultProto = directives.last { $0.name == "proto" }?.arguments.first ?? "udp"
        return directives.filter { $0.name == "remote" }.map { directive in
            let arguments = directive.arguments
            return OpenVPNRemote(host: arguments[0],
                                 port: arguments.count > 1 ? Int(arguments[1]) ?? defaultPort : defaultPort,
                                 proto: arguments.count > 2 ? arguments[2] : defaultProto)
        }
    }

    /// Canonical text: one directive per line, every argument quoted, then the blocks.
    public var text: String {
        var lines = directives.map(Self.render)
        for block in blocks {
            lines.append("<\(block.tag)>")
            lines.append(block.content)
            lines.append("</\(block.tag)>")
        }
        return lines.joined(separator: "\n") + "\n"
    }

    static func render(_ directive: OpenVPNDirective) -> String {
        ([directive.name] + directive.arguments.map(quote)).joined(separator: " ")
    }

    static func quote(_ argument: String) -> String {
        "\"" + argument.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\""
    }
}

public struct OpenVPNRemote: Codable, Equatable, Sendable {
    public var host: String
    public var port: Int
    public var proto: String
    public init(host: String, port: Int, proto: String) { self.host = host; self.port = port; self.proto = proto }
    public var display: String {
        let shownHost = host.contains(":") ? "[\(host)]" : host
        return "\(shownHost):\(port)/\(proto.hasPrefix("tcp") ? "tcp" : "udp")"
    }
}

/// The configuration the helper hands to openvpn: the checked profile, then directives the
/// helper alone controls (placed last, so they win), then the credentials inline.
public enum OpenVPNConfigRenderer {
    public static func render(profile text: String, username: String?, password: String?, dnsScript: String?) throws -> String {
        let profile = try OpenVPNProfile.validated(text)
        var content = profile.text
        content += "# Diretivas controladas pelo serviço privilegiado.\n"
        if let dnsScript {
            guard dnsScript.hasPrefix("/"), !dnsScript.contains("\""), !dnsScript.contains("\\"),
                  !dnsScript.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
                throw RuleViolation(ServiceLanguage.text("Caminho do script de DNS inválido."))
            }
            // Level 2 is required for a command other than the compiled-in default. The
            // allowlist keeps every other script directive out, so only this one can run.
            content += "script-security 2\ndns-updown \(OpenVPNProfile.quote(dnsScript))\n"
        } else {
            // The compiled-in default lives in the (user-writable) Homebrew prefix.
            content += "script-security 1\ndns-updown disable\n"
        }
        // Never prompt (stdin is /dev/null) and never loop on a refused password.
        content += "auth-retry none\n"
        if !profile.directives.contains(where: { $0.name == "verb" }) { content += "verb 3\n" }
        if profile.requiresCredentials {
            guard let username, let password, !username.isEmpty, !password.isEmpty else {
                throw RuleViolation(ServiceLanguage.text("Este perfil OpenVPN exige usuário e senha."))
            }
            try OpenVPNRules.checkCredential(username, label: ServiceLanguage.text("Usuário"))
            try OpenVPNRules.checkCredential(password, label: ServiceLanguage.text("Senha"))
            content += "<auth-user-pass>\n\(username)\n\(password)\n</auth-user-pass>\n"
        } else if username != nil || password != nil {
            throw RuleViolation(ServiceLanguage.text("Este perfil OpenVPN não usa usuário e senha."))
        }
        return content
    }
}

public enum OpenVPNRules {
    public static let blockTags: Set<String> = ["ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2", "extra-certs", "crl-verify"]
    static let maximumBlock = 64 * 1024

    public struct Rule: Sendable {
        let minimum: Int
        let maximum: Int
        let check: @Sendable ([String]) -> Bool
        func check(_ directive: OpenVPNDirective) throws {
            let arguments = directive.arguments
            guard (minimum...maximum).contains(arguments.count) else {
                throw RuleViolation(ServiceLanguage.text("\(directive.name): número de argumentos inesperado."))
            }
            guard arguments.allSatisfy(OpenVPNRules.safeArgument), check(arguments) else {
                throw RuleViolation(ServiceLanguage.text("\(directive.name): valor não aceito."))
            }
        }
    }

    static func safeArgument(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 256
            && !value.unicodeScalars.contains { CharacterSet.controlCharacters.contains($0) || $0 == "\u{7f}" }
    }
    static func matches(_ value: String, _ pattern: String) -> Bool {
        value.range(of: pattern, options: .regularExpression) != nil
    }
    static func port(_ value: String) -> Bool { Int(value).map { (0...65535).contains($0) } ?? false }
    static let protocols: Set<String> = ["udp", "udp4", "udp6", "tcp", "tcp4", "tcp6", "tcp-client", "tcp4-client", "tcp6-client"]
    static func host(_ value: String) -> Bool { matches(value, #"^[A-Za-z0-9.:_-]{1,253}$"#) && !value.hasPrefix("-") }
    static func word(_ value: String) -> Bool { matches(value, #"^[A-Za-z0-9._:+/!-]{1,128}$"#) }
    static func number(_ value: String) -> Bool { matches(value, #"^[0-9]{1,10}$"#) }

    static func flag() -> Rule { Rule(minimum: 0, maximum: 0) { _ in true } }
    static func numbers(_ minimum: Int, _ maximum: Int) -> Rule { Rule(minimum: minimum, maximum: maximum) { $0.allSatisfy(number) } }
    static func words(_ minimum: Int, _ maximum: Int) -> Rule { Rule(minimum: minimum, maximum: maximum) { $0.allSatisfy(word) } }
    static func oneOf(_ values: Set<String>, optional: Bool = false) -> Rule {
        Rule(minimum: optional ? 0 : 1, maximum: 1) { $0.allSatisfy(values.contains) }
    }

    /// Directives that only describe the tunnel. Anything else is rejected (by the helper)
    /// or dropped with a warning (by the importer, see `dropped`).
    public static let allowed: [String: Rule] = [
        "client": flag(), "tls-client": flag(), "pull": flag(), "nobind": flag(), "float": flag(),
        "persist-tun": flag(), "persist-key": flag(), "persist-remote-ip": flag(), "persist-local-ip": flag(),
        "auth-nocache": flag(), "remote-random": flag(), "remote-random-hostname": flag(),
        "mute-replay-warnings": flag(), "route-nopull": flag(), "block-ipv6": flag(), "fast-io": flag(),
        "allow-pull-fqdn": flag(), "push-peer-info": flag(), "tun-ipv6": flag(), "comp-noadapt": flag(),
        "dev": Rule(minimum: 1, maximum: 1) { matches($0[0], #"^u?tun[0-9]{0,3}$"#) },
        "dev-type": oneOf(["tun"]),
        "proto": oneOf(protocols),
        "remote": Rule(minimum: 1, maximum: 3) { arguments in
            host(arguments[0]) && (arguments.count < 2 || port(arguments[1])) && (arguments.count < 3 || protocols.contains(arguments[2]))
        },
        "port": Rule(minimum: 1, maximum: 1) { port($0[0]) },
        "rport": Rule(minimum: 1, maximum: 1) { port($0[0]) },
        "lport": Rule(minimum: 1, maximum: 1) { port($0[0]) },
        "resolv-retry": Rule(minimum: 1, maximum: 1) { $0[0] == "infinite" || number($0[0]) },
        "connect-retry": numbers(1, 2), "connect-retry-max": numbers(1, 1), "connect-timeout": numbers(1, 1),
        "server-poll-timeout": numbers(1, 1), "hand-window": numbers(1, 1), "tran-window": numbers(1, 1),
        "tls-timeout": numbers(1, 1), "ping": numbers(1, 1), "ping-restart": numbers(1, 1), "ping-exit": numbers(1, 1),
        "keepalive": numbers(2, 2), "inactive": numbers(1, 2), "reneg-sec": numbers(1, 2), "reneg-bytes": numbers(1, 1),
        "reneg-pkts": numbers(1, 1), "tun-mtu": numbers(1, 1), "link-mtu": numbers(1, 1),
        "mssfix": Rule(minimum: 0, maximum: 2) { arguments in
            arguments.isEmpty || (number(arguments[0]) && (arguments.count < 2 || ["mtu", "fixed"].contains(arguments[1])))
        },
        "fragment": Rule(minimum: 1, maximum: 2) { number($0[0]) && ($0.count < 2 || $0[1] == "mtu") },
        "sndbuf": numbers(1, 1), "rcvbuf": numbers(1, 1), "txqueuelen": numbers(1, 1), "mute": numbers(1, 1),
        "replay-window": numbers(1, 2), "route-delay": numbers(0, 2), "route-metric": numbers(1, 1),
        "explicit-exit-notify": numbers(0, 1),
        // verb 4 and above dump the full parameter list; never more than 3.
        "verb": Rule(minimum: 1, maximum: 1) { ["0", "1", "2", "3"].contains($0[0]) },
        "cipher": words(1, 1), "data-ciphers": words(1, 1), "data-ciphers-fallback": words(1, 1), "ncp-ciphers": words(1, 1),
        "auth": words(1, 1), "tls-cipher": words(1, 1), "tls-ciphersuites": words(1, 1), "tls-groups": words(1, 1),
        "ecdh-curve": words(1, 1), "tls-cert-profile": oneOf(["insecure", "legacy", "preferred", "suiteb"]),
        "tls-version-min": Rule(minimum: 1, maximum: 2) { matches($0[0], #"^1\.[0-3]$"#) && ($0.count < 2 || $0[1] == "or-highest") },
        "tls-version-max": Rule(minimum: 1, maximum: 1) { matches($0[0], #"^1\.[0-3]$"#) },
        "remote-cert-tls": oneOf(["server"]),
        "ns-cert-type": oneOf(["server"]),
        "remote-cert-ku": Rule(minimum: 1, maximum: 8) { $0.allSatisfy { matches($0, #"^[0-9a-fA-F]{1,4}$"#) } },
        "remote-cert-eku": Rule(minimum: 1, maximum: 1) { _ in true },
        "verify-x509-name": Rule(minimum: 1, maximum: 2) { $0.count < 2 || ["subject", "name", "name-prefix"].contains($0[1]) },
        "key-direction": oneOf(["0", "1"]),
        "comp-lzo": oneOf(["yes", "no", "adaptive"], optional: true),
        "compress": oneOf(["lzo", "lz4", "lz4-v2", "stub", "stub-v2", "migrate"], optional: true),
        "allow-compression": oneOf(["yes", "no", "asym"]),
        "auth-user-pass": flag(),
        "route": Rule(minimum: 1, maximum: 4) { $0.allSatisfy { matches($0, #"^[A-Za-z0-9.:_-]{1,64}$"#) } },
        "route-ipv6": Rule(minimum: 1, maximum: 3) { $0.allSatisfy { matches($0, #"^[A-Za-z0-9.:/_-]{1,64}$"#) } },
        "redirect-gateway": Rule(minimum: 0, maximum: 7) {
            $0.allSatisfy(["local", "autolocal", "def1", "bypass-dhcp", "bypass-dns", "block-local", "ipv6", "!ipv4"].contains)
        },
        "dhcp-option": Rule(minimum: 1, maximum: 2) { $0.allSatisfy { matches($0, #"^[A-Za-z0-9.:_-]{1,128}$"#) } },
        "dns": Rule(minimum: 2, maximum: 8) { $0.allSatisfy { matches($0, #"^[A-Za-z0-9.:_/\[\]-]{1,128}$"#) } },
        "pull-filter": Rule(minimum: 2, maximum: 2) { ["accept", "ignore", "reject"].contains($0[0]) },
    ]

    /// Directives the importer removes with a warning instead of refusing the profile.
    /// None of them may reach root: they run programs, load modules, touch files, open a
    /// management channel, change identity or only apply to Windows.
    public static let dropped: [String: String] = {
        var reasons: [String: String] = [:]
        for name in ["up", "down", "route-up", "route-pre-down", "ipchange", "tls-verify", "learn-address",
                     "client-connect", "client-disconnect", "auth-user-pass-verify", "plugin", "script-security",
                     "dns-updown", "up-delay", "up-restart", "down-pre", "iproute", "tls-export-cert"] {
            reasons[name] = ServiceLanguage.text("executa programas; o DNS é configurado pelo script dns-updown do OpenVPN aprovado")
        }
        for name in ["setenv", "setenv-safe"] { reasons[name] = ServiceLanguage.text("altera o ambiente dos scripts executados como root") }
        for name in ["log", "log-append", "status", "status-version", "writepid", "replay-persist", "tmp-dir", "cd", "chroot", "daemon", "syslog"] {
            reasons[name] = ServiceLanguage.text("lê ou grava arquivos; o app guarda os logs")
        }
        for name in ["management", "management-client", "management-hold", "management-query-passwords",
                     "management-signal", "management-forget-disconnect", "management-up-down", "management-log-cache",
                     "management-client-user", "management-client-group", "management-external-key",
                     "management-external-cert", "management-query-remote", "management-query-proxy"] {
            reasons[name] = ServiceLanguage.text("abre um canal de controle externo")
        }
        for name in ["providers", "engine"] { reasons[name] = ServiceLanguage.text("carrega módulos de criptografia de fora da cópia aprovada") }
        for name in ["user", "group"] { reasons[name] = ServiceLanguage.text("troca a identidade do processo e impede a limpeza de rotas") }
        for name in ["block-outside-dns", "register-dns", "ip-win32", "route-method", "dhcp-renew", "dhcp-release",
                     "win-sys", "tap-sleep", "dhcp-pre-release", "allow-nonadmin", "windows-driver"] {
            reasons[name] = ServiceLanguage.text("só se aplica ao Windows")
        }
        reasons["auth-retry"] = ServiceLanguage.text("o app controla novas tentativas para não bloquear a conta")
        reasons["ignore-unknown-option"] = ServiceLanguage.text("o app não ignora diretivas desconhecidas")
        reasons["machine-readable-output"] = ServiceLanguage.text("o formato dos logs é controlado pelo app")
        reasons["ncp-disable"] = ServiceLanguage.text("removida no OpenVPN 2.6")
        return reasons
    }()

    static func checkBlock(_ block: OpenVPNBlock) throws {
        guard !block.content.isEmpty, block.content.utf8.count <= maximumBlock else {
            throw RuleViolation(ServiceLanguage.text("Bloco <\(block.tag)> vazio ou acima de 64 KB."))
        }
        for line in block.content.split(separator: "\n", omittingEmptySubsequences: false) {
            let ok = line.unicodeScalars.allSatisfy { ($0.value >= 0x20 && $0.value < 0x7f) || $0 == "\t" }
            guard ok, !line.trimmingCharacters(in: .whitespaces).hasPrefix("<") else {
                throw RuleViolation(ServiceLanguage.text("Bloco <\(block.tag)> com conteúdo inesperado (somente PEM ou chave estática em texto)."))
            }
        }
        let pem = block.content.contains("-----BEGIN ")
        guard pem else { throw RuleViolation(ServiceLanguage.text("Bloco <\(block.tag)> não contém material PEM.")) }
    }

    /// Credentials become two lines of an inline block: no line breaks, no NUL, no markup.
    public static func checkCredential(_ value: String, label: String) throws {
        guard value.utf8.count <= 512,
              !value.unicodeScalars.contains(where: { $0 == "\n" || $0 == "\r" || $0 == "\0" }),
              !value.trimmingCharacters(in: .whitespaces).hasPrefix("<") else {
            throw RuleViolation(ServiceLanguage.text("\(label): quebra de linha, caractere nulo ou início com < não são suportados."))
        }
    }
}

/// Compatibility rules that change a cryptographic parameter. They are never applied
/// silently: the app shows each one and applies it only with the user's consent.
public enum OpenVPNCompatibility {
    public struct DigestFix: Codable, Equatable, Sendable {
        public var from: String
        public var to: String
        public init(from: String, to: String) { self.from = from; self.to = to }
    }

    /// `auth` expects a message digest (HMAC). Some exporters write the signature name
    /// "RSA-SHA256"; OpenVPN 2.7 with OpenSSL 3+ refuses it ("Message hash algorithm
    /// 'RSA-SHA256' not found"). Only the exact RSA-SHA1/224/256/384/512 spellings map.
    public static func digestFix(for profile: OpenVPNProfile) -> DigestFix? {
        guard let value = profile.directives.last(where: { $0.name == "auth" })?.arguments.first else { return nil }
        return digestFix(value)
    }

    public static func digestFix(_ value: String) -> DigestFix? {
        guard let range = value.range(of: #"^(?i)RSA-(SHA(1|224|256|384|512))$"#, options: .regularExpression),
              range == value.startIndex..<value.endIndex else { return nil }
        return DigestFix(from: value, to: String(value.dropFirst(4)).uppercased())
    }

    /// The same mapping, recognized from openvpn's own error line.
    public static func digestFix(fromLog line: String) -> DigestFix? {
        guard let range = line.range(of: #"Message hash algorithm '([A-Za-z0-9-]+)' not found"#, options: .regularExpression) else { return nil }
        let value = line[range].split(separator: "'").dropFirst().first.map(String.init) ?? ""
        return digestFix(value)
    }

    /// Undoes `apply` (the user turned the compatibility option off again).
    public static func revert(_ fix: DigestFix, in profile: OpenVPNProfile) -> OpenVPNProfile {
        apply(DigestFix(from: fix.to, to: fix.from), to: profile)
    }

    /// Whether the profile currently uses the fixed value of `fix`.
    public static func isApplied(_ fix: DigestFix, in profile: OpenVPNProfile) -> Bool {
        profile.directives.last { $0.name == "auth" }?.arguments == [fix.to]
    }

    public static func apply(_ fix: DigestFix, to profile: OpenVPNProfile) -> OpenVPNProfile {
        var updated = profile
        for index in updated.directives.indices where updated.directives[index].name == "auth"
            && updated.directives[index].arguments == [fix.from] {
            updated.directives[index].arguments = [fix.to]
        }
        return updated
    }
}

public extension RuntimeCapabilities {
    /// Minimum surface of OpenVPN 2.7+ the helper relies on (inline credentials, dns-updown).
    static func looksLikeOpenVPN(_ help: String) -> Bool {
        help.contains("OpenVPN") && help.contains("--remote") && help.contains("--auth-user-pass")
            && help.contains("--dns-updown") && help.contains("--script-security")
    }
}
