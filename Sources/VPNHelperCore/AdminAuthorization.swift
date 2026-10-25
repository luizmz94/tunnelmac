import Foundation
import Security
import VPNHelperShared

/// Consent for the distinct, restricted operations (approve/update/remove the runtime).
public protocol AdminAuthorizing: AnyObject {
    /// Blocks while the system asks for administrator credentials in the requester's session;
    /// `prompt` says what this request is for.
    func authorize(_ externalForm: Data, prompt: String) -> Bool
}

/// Authorization Services check on an AuthorizationRef created by the app.
/// The right is (re)defined by the root helper with rule `authenticate-admin`
/// (the system controls credential caching and whether another prompt is needed).
/// Because `config.add.` lets any user create a
/// right, an existing definition is checked and rewritten if it is not exactly that rule.
public final class SystemAdminAuthorizer: AdminAuthorizing {
    public init() {}
    static let rule = "authenticate-admin"
    /// The right's own description, shown only when a request carries no prompt.
    static let description = "TunnelMac quer aprovar ou remover a cópia protegida de um cliente VPN (openfortivpn, OpenVPN ou wireguard-go)."

    public static func approvalPrompt(_ kind: RuntimeKind, path: String) -> String {
        let client: String
        switch kind {
        case .openfortivpn: client = "o openfortivpn (Fortinet)"
        case .openvpn: client = "o OpenVPN"
        case .wireguard: client = "o wireguard-go (WireGuard)"
        }
        return "TunnelMac quer aprovar \(client) para conectar suas VPNs. O serviço vai usar só uma cópia protegida de \(path)."
    }
    public static let removalPrompt = "TunnelMac quer remover as cópias protegidas dos clientes VPN e os arquivos do serviço."

    /// Rights created by older builds keep their first description ("VPN GUI …").
    static func descriptionIsCurrent(_ definition: [String: Any]?) -> Bool {
        (definition?["default-prompt"] as? [String: Any])?[""] as? String == description
    }

    public static func definitionIsExpected(_ definition: [String: Any]?) -> Bool {
        guard let definition, definition["class"] as? String == "rule" else { return false }
        // A matching rule name does not make an `allow` class safe. Likewise, a
        // zero-of-N threshold must not bypass the authenticate-admin subrule.
        if let threshold = definition["kofn"], (threshold as? NSNumber)?.intValue != 1 { return false }
        if let rule = definition["rule"] as? [String] { return rule == [Self.rule] }
        if let rule = definition["rule"] as? String { return rule == Self.rule }
        return false
    }

    private func ensureRight() -> Bool {
        var current: CFDictionary?
        let status = AuthorizationRightGet(HelperConstants.authorizationRight, &current)
        if status == errAuthorizationSuccess, Self.definitionIsExpected(current as? [String: Any]),
           Self.descriptionIsCurrent(current as? [String: Any]) { return true }
        var own: AuthorizationRef?
        guard AuthorizationCreate(nil, nil, [], &own) == errAuthorizationSuccess, let own else { return false }
        defer { AuthorizationFree(own, []) }
        let set = AuthorizationRightSet(own, HelperConstants.authorizationRight, Self.rule as CFString,
                                        Self.description as CFString, nil, nil)
        guard set == errAuthorizationSuccess else { return false }
        var verified: CFDictionary?
        return AuthorizationRightGet(HelperConstants.authorizationRight, &verified) == errAuthorizationSuccess
            && Self.definitionIsExpected(verified as? [String: Any])
    }

    public func authorize(_ externalForm: Data, prompt: String) -> Bool {
        guard externalForm.count == MemoryLayout<AuthorizationExternalForm>.size, ensureRight() else { return false }
        var form = AuthorizationExternalForm()
        withUnsafeMutableBytes(of: &form) { _ = externalForm.copyBytes(to: $0) }
        var reference: AuthorizationRef?
        guard AuthorizationCreateFromExternalForm(&form, &reference) == errAuthorizationSuccess, let reference else { return false }
        defer { AuthorizationFree(reference, []) }
        var text = Array(prompt.utf8CString)
        return HelperConstants.authorizationRight.withCString { name in
            kAuthorizationEnvironmentPrompt.withCString { promptKey in
                text.withUnsafeMutableBufferPointer { buffer in
                    var item = AuthorizationItem(name: name, valueLength: 0, value: nil, flags: 0)
                    // The environment prompt replaces the right's generic description.
                    var promptItem = AuthorizationItem(name: promptKey, valueLength: buffer.count - 1,
                                                       value: UnsafeMutableRawPointer(buffer.baseAddress), flags: 0)
                    return withUnsafeMutablePointer(to: &item) { pointer in
                        withUnsafeMutablePointer(to: &promptItem) { promptPointer in
                            var rights = AuthorizationRights(count: 1, items: pointer)
                            var environment = AuthorizationEnvironment(count: 1, items: promptPointer)
                            return AuthorizationCopyRights(reference, &rights, &environment,
                                                           [.interactionAllowed, .extendRights], nil) == errAuthorizationSuccess
                        }
                    }
                }
            }
        }
    }
}
