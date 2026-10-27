import Foundation

/// Language of the messages written for the app. The app runs in the language chosen in
/// Configurações; the helper runs as root, so the app sends its language in the handshake
/// and the helper's errors and connection logs follow it. Unset, the process language is used.
public enum ServiceLanguage {
    private static let lock = NSLock()
    private static var current: Locale?

    public static var locale: Locale? {
        get { lock.lock(); defer { lock.unlock() }; return current }
        set { lock.lock(); current = newValue; lock.unlock() }
    }

    /// The text in the chosen language, from the app bundle's catalog.
    public static func text(_ resource: LocalizedStringResource) -> String {
        var resource = resource
        if let locale { resource.locale = locale }
        return String(localized: resource)
    }

    /// Accepts only a short language tag (en, pt-BR, zh-Hans); anything else keeps the default.
    public static func apply(_ tag: String?) {
        guard let tag, (2...16).contains(tag.count),
              tag.unicodeScalars.allSatisfy({ CharacterSet.alphanumerics.contains($0) || $0 == "-" }) else { return }
        locale = Locale(identifier: tag)
    }
}
