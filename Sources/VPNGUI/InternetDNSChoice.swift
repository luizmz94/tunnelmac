import Foundation
import VPNHelperShared

/// One entry of Configurações › Geral › DNS da internet.
struct InternetDNSOption: Codable, Identifiable, Equatable {
    var id: String
    var name: String
    var servers: [String]
    /// "1.1.1.1 - Cloudflare", as listed in the picker.
    var label: String { "\(servers.first ?? "") - \(name)" }

    static let cloudflare = InternetDNSOption(id: "cloudflare", name: "Cloudflare", servers: ["1.1.1.1", "1.0.0.1"])
    static let google = InternetDNSOption(id: "google", name: "Google", servers: ["8.8.8.8", "8.8.4.4"])
    static let adguard = InternetDNSOption(id: "adguard", name: String(localized: "AdGuard (bloqueia anúncios)"), servers: ["94.140.14.14", "94.140.15.15"])
    static let presets = [cloudflare, google, adguard]
    /// Selection that leaves the system DNS alone.
    static let offID = "off"
    static let defaultID = offID

    /// A custom entry typed by the user: a name and 1 to 4 addresses separated by commas or spaces.
    static func custom(name: String, servers text: String) throws -> InternetDNSOption {
        let name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty, name.count <= 40 else { throw AppFailure(String(localized: "Informe um nome de até 40 caracteres.")) }
        let parts = text.split(whereSeparator: { $0 == "," || $0 == ";" || $0.isWhitespace }).map(String.init)
        do {
            return InternetDNSOption(id: UUID().uuidString, name: name, servers: try ConnectionRules.internetDNS(parts))
        } catch let violation as RuleViolation { throw AppFailure(violation.message) }
    }
}
