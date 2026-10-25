@testable import VPNApp
import Foundation

/// Local checks only: the Seatbelt profile Homebrew 7 applies to cask `run` steps,
/// rendered from the installed Homebrew or, without Homebrew, from a fixed copy.
enum HomebrewSandbox {
    static let sources = ["/opt/homebrew", "/usr/local/Homebrew"].map { $0 + "/Library/Homebrew/extend/os/mac/sandbox.rb" }

    /// Copy of `SEATBELT_ERB` from Homebrew 7.0 (Library/Homebrew/extend/os/mac/sandbox.rb).
    static let fixedTemplate = #"""
(version 1)
(debug deny) ; log all denied operations to /var/log/system.log
(deny network-outbound (to unix-socket))
<% if network_access_allowed %>
(allow network-outbound (to unix-socket (path-literal "/private/var/run/mDNSResponder")))
<% end %>
<%= rules.join("\n") %>
(allow file-write*
    (literal "/dev/ptmx")
    (literal "/dev/dtracehelper")
    (literal "/dev/null")
    (literal "/dev/random")
    (literal "/dev/zero")
    (regex #"^/dev/fd/[0-9]+$")
    (regex #"^/dev/tty[a-z0-9]*$")
    )
(deny file-write*) ; deny non-allowlist file write operations
(deny file-write-setugid) ; deny non-allowlist file write SUID/SGID operations
(deny file-write-mode) ; deny non-allowlist file write mode operations
(deny mach-lookup)
(allow mach-lookup
    (xpc-service-name "com.apple.MTLCompilerService")
    (global-name "com.apple.mobileassetd.v2")
    (global-name "com.apple.sysmond")
    (global-name "com.apple.lsd.mapdb")
    (global-name "com.apple.bsd.dirhelper")
    (global-name "com.apple.system.opendirectoryd.libinfo")
    (global-name "com.apple.system.opendirectoryd.membership")
    (global-name "com.apple.PowerManagement.control")
    (global-name "com.apple.SecurityServer")
    (global-name "com.apple.networkd")
    (global-name "com.apple.ocspd")
    (global-name "com.apple.trustd.agent")
<% if network_access_allowed %>
    (global-name "com.apple.trustd")
    (global-name "com.apple.TrustEvaluationAgent")
<% end %>
    (global-name "com.apple.SystemConfiguration.DNSConfiguration")
    (global-name "com.apple.SystemConfiguration.configd")
    )
(deny lsopen)
(deny appleevent-send)
(allow process-exec
    (literal "/bin/ps")
    (with no-sandbox)
    ) ; allow certain processes running without sandbox
(allow default) ; allow everything else
"""#

    /// Template from the installed Homebrew, else the fixed copy, and where it came from.
    static func template() throws -> (text: String, origin: String) {
        for path in sources {
            guard let ruby = try? String(contentsOfFile: path, encoding: .utf8) else { continue }
            let pattern = #"SEATBELT_ERB = <<~ERB\n(.*?)\n[ ]*ERB\n"#
            let expression = try NSRegularExpression(pattern: pattern, options: [.dotMatchesLineSeparators])
            guard let match = expression.firstMatch(in: ruby, range: NSRange(ruby.startIndex..., in: ruby)),
                  let range = Range(match.range(at: 1), in: ruby) else {
                throw TestSupport.Failure("SEATBELT_ERB not found in \(path)")
            }
            let lines = ruby[range].split(separator: "\n", omittingEmptySubsequences: false)
            let indent = lines.filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty }
                .map { $0.prefix { $0 == " " }.count }.min() ?? 0
            return (lines.map { String($0.dropFirst(min(indent, $0.prefix { $0 == " " }.count))) }.joined(separator: "\n"), path)
        }
        return (fixedTemplate, "fixed copy")
    }

    /// Same values as a cask step: no network, writable system temp. Any ERB the
    /// renderer does not know fails, so a changed profile is noticed.
    static func profile(_ template: String) throws -> String {
        let rules = [
            #"(deny network*)"#,
            #"(allow file-write* (subpath "/private/tmp"))"#,
            #"(allow file-write* (subpath "/private/var/tmp"))"#,
            #"(allow file-write* (regex #"^/private/var/folders/[^/]+/[^/]+/[C,T]/"))"#,
        ]
        let blocks = try NSRegularExpression(pattern: #"<% if network_access_allowed %>.*?<% end %>"#, options: [.dotMatchesLineSeparators])
        var text = blocks.stringByReplacingMatches(in: template, range: NSRange(template.startIndex..., in: template), withTemplate: "")
        text = text.replacingOccurrences(of: #"<%= rules.join("\n") %>"#, with: rules.joined(separator: "\n"))
        guard !text.contains("<%"), text.contains("(deny mach-lookup)") else { throw TestSupport.Failure("Unknown Homebrew sandbox profile") }
        return text
    }
}
