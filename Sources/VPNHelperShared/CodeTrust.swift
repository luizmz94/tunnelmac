import Foundation
import Security

/// Code-signing trust policy for the XPC peers and the supervisor.
///
/// The root of trust is the signature of the running process itself: a peer is
/// accepted only if it is signed by an Apple-issued certificate (Apple Development
/// or Developer ID) of the *same Team ID* as this process and carries the expected
/// identifier. Ad hoc builds have no Team ID, so the policy is `.unavailable` and every
/// privileged operation fails closed. PID, UID, process name or bundle identifier alone
/// are never used to authenticate code.
public enum CodeTrust {
    public enum Policy: Equatable {
        case trusted(team: String)
        case unavailable(reason: String)
    }

    public static func isValidTeam(_ team: String) -> Bool {
        team.count == 10 && team.unicodeScalars.allSatisfy { CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789").contains($0) }
    }

    /// Designated-style requirement for a peer of the same team.
    public static func requirement(identifier: String, team: String) -> String {
        precondition(isValidTeam(team) && identifier.unicodeScalars.allSatisfy {
            CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-").contains($0)
        }, "invalid requirement input")
        return "identifier \"\(identifier)\" and anchor apple generic and certificate leaf[subject.OU] = \"\(team)\""
    }

    /// Team of the running process, only if its own signature really chains to Apple
    /// with that OU. A self-signed certificate with a fake OU yields `.unavailable`.
    public static func localPolicy() -> Policy {
        var code: SecCode?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code else {
            return .unavailable(reason: ServiceLanguage.text("Não foi possível ler a assinatura deste processo."))
        }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else {
            return .unavailable(reason: ServiceLanguage.text("Não foi possível ler a assinatura deste processo."))
        }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let values = info as? [String: Any] else {
            return .unavailable(reason: ServiceLanguage.text("Não foi possível ler a assinatura deste processo."))
        }
        guard let team = values[kSecCodeInfoTeamIdentifier as String] as? String, isValidTeam(team) else {
            return .unavailable(reason: ServiceLanguage.text("Build sem Team ID (assinatura ad hoc). O serviço privilegiado exige assinatura Apple Development ou Developer ID; operações root ficam desabilitadas."))
        }
        var requirement: SecRequirement?
        let text = "anchor apple generic and certificate leaf[subject.OU] = \"\(team)\""
        guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess, let requirement,
              SecCodeCheckValidity(code, [], requirement) == errSecSuccess else {
            return .unavailable(reason: ServiceLanguage.text("A assinatura deste processo não é emitida pela Apple para o Team \(team)."))
        }
        return .trusted(team: team)
    }

    /// Validates a code file on disk (all architectures, strict) against a requirement.
    /// Callers must only use this on files nobody else can modify afterwards.
    public static func validate(file: URL, requirement text: String?) -> Bool {
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(file as CFURL, [], &staticCode) == errSecSuccess, let staticCode else { return false }
        var requirement: SecRequirement?
        if let text {
            guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess else { return false }
        }
        let flags = SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures | kSecCSCheckNestedCode)
        return SecStaticCodeCheckValidity(staticCode, flags, requirement) == errSecSuccess
    }

    /// True when the requirement text compiles (malformed text would throw in NSXPC).
    public static func compiles(_ text: String) -> Bool {
        var requirement: SecRequirement?
        return SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess
    }
}
