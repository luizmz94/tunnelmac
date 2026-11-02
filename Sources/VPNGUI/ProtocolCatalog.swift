import SwiftUI

/// What the Nova conexão chooser says about each VPN type: the tile and its quick view read
/// only from here, so a new type needs one entry. Texts are resources, resolved in the locale
/// of the view that shows them.
struct ProtocolCatalog {
    struct Entry: Identifiable, Equatable {
        /// The type's raw value; only distinct for the layout checks, which repeat kinds.
        var id: String
        var kind: VPNProtocol
        /// Under the tile's name, on one line.
        var tileSubtitle: LocalizedStringResource
        /// One or two sentences: what it is.
        var about: LocalizedStringResource
        var authentication: LocalizedStringResource
        /// What the form asks for.
        var requires: LocalizedStringResource
        /// VoiceOver hint of the tile (the quick view is hidden from it).
        var hint: LocalizedStringResource

        var title: String { kind.title }
        /// Shorter name under the tile icon.
        var shortName: String {
            switch kind {
            case .fortinet: return "Fortinet"
            default: return kind.title
            }
        }

        static func == (lhs: Entry, rhs: Entry) -> Bool { lhs.id == rhs.id && lhs.kind == rhs.kind }
    }

    var entries: [Entry]

    static let standard = ProtocolCatalog(entries: VPNProtocol.allCases.map(entry))

    static func entry(_ kind: VPNProtocol) -> Entry {
        switch kind {
        case .fortinet:
            return Entry(id: kind.rawValue, kind: kind, tileSubtitle: "FortiGate",
                         about: "Gateway FortiGate, o mesmo usado pelo FortiClient. Conecta pelo openfortivpn.",
                         authentication: "Usuário e senha, SAML no navegador e certificado do cliente.",
                         requires: "Gateway (host, porta e realm).",
                         hint: "Gateway FortiGate, com usuário e senha, SAML ou certificado. Pede o gateway.")
        case .openvpn:
            return Entry(id: kind.rawValue, kind: kind, tileSubtitle: "Perfil .ovpn",
                         about: "Perfil .ovpn ou pasta .visc do Viscosity (também em .zip), importado com os certificados.",
                         authentication: "O que o perfil define: certificado, usuário e senha.",
                         requires: "Arquivo .ovpn/.conf, pasta .visc ou .zip.",
                         hint: "Perfil OpenVPN, com o que o perfil define. Pede o arquivo .ovpn, a pasta .visc ou o .zip.")
        case .wireguard:
            return Entry(id: kind.rawValue, kind: kind, tileSubtitle: "Arquivo .conf",
                         about: "Arquivo .conf do servidor ou do app WireGuard. Scripts do perfil não são executados.",
                         authentication: "Chave do perfil.",
                         requires: "Arquivo .conf.",
                         hint: "Túnel WireGuard, com a chave do perfil. Pede o arquivo .conf.")
        case .globalProtect:
            return Entry(id: kind.rawValue, kind: kind, tileSubtitle: "Palo Alto",
                         about: "Gateway Palo Alto, com login SAML no navegador ou senha. Conecta pelo OpenConnect.",
                         authentication: "SAML no navegador ou senha.",
                         requires: "Gateway (portal).",
                         hint: "Gateway Palo Alto GlobalProtect, com SAML no navegador ou senha. Pede o gateway.")
        case .checkPoint:
            return Entry(id: kind.rawValue, kind: kind, tileSubtitle: "Remote Access",
                         about: "Gateway Check Point (Remote Access), com usuário e senha. Conecta pelo snx-rs, sem o cliente oficial.",
                         authentication: "Usuário e senha (MFA, SAML e certificado ainda não).",
                         requires: "Gateway (o editor consulta o certificado).",
                         hint: "Gateway Check Point, com usuário e senha. Pede o gateway.")
        }
    }

    /// The entry the quick view describes: under the mouse, else focused, else the first.
    static func shown(hovered: String?, focused: String?, in entries: [Entry]) -> Entry? {
        for id in [hovered, focused] {
            if let id, let entry = entries.first(where: { $0.id == id }) { return entry }
        }
        return entries.first
    }

    /// Columns of the adaptive grid for a given width (same rule as `GridItem.adaptive`).
    static func columns(width: CGFloat, minimum: CGFloat = ProtocolTileButton.minimumWidth,
                        spacing: CGFloat = ProtocolTileButton.spacing) -> Int {
        max(1, Int(((width + spacing) / (minimum + spacing)).rounded(.down)))
    }

    /// Arrow keys in the grid: stop at the edges, never wrap.
    static func move(from index: Int, _ direction: MoveCommandDirection, count: Int, columns: Int) -> Int {
        guard count > 0 else { return 0 }
        let target: Int
        switch direction {
        case .left: target = index % columns == 0 ? index : index - 1
        case .right: target = index % columns == columns - 1 ? index : index + 1
        case .up: target = index - columns
        case .down: target = index + columns
        @unknown default: target = index
        }
        return (0..<count).contains(target) ? target : index
    }
}

/// Client state of a type, from the same service checks as the form and Conectar.
struct ProtocolClientState: Equatable {
    enum Kind: Equatable { case ready, problem, checking }
    var kind: Kind
    /// "openfortivpn 1.24.1 aprovado", the service's reason, or "Verificando o serviço…".
    var text: String
}

/// Choosing a type: a new connection whose client the service cannot run asks first.
enum ProtocolChoice: Equatable {
    case proceed, askService
    static func decide(isNew: Bool, problem: String?) -> ProtocolChoice { isNew && problem != nil ? .askService : .proceed }
}

extension LocalizedStringResource {
    /// Resolved in `locale` when a view overrides it (renders in another language); otherwise
    /// exactly like `String(localized:)`.
    func string(in locale: Locale) -> String {
        guard locale.language.languageCode != Locale.current.language.languageCode else { return String(localized: self) }
        var resource = self
        resource.locale = locale
        return String(localized: resource)
    }
}
