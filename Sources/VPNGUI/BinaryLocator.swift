import Foundation
import Security
import Darwin
import VPNHelperShared

enum BinaryLocator {
    /// Apple Silicon Homebrew uses /opt/homebrew, Intel /usr/local; openvpn installs in sbin.
    static func candidates(environment: [String: String] = ProcessInfo.processInfo.environment, name: String = "openfortivpn") -> [String] {
        let standard = ["/opt/homebrew/bin", "/usr/local/bin", "/opt/local/bin", "/usr/bin",
                        "/opt/homebrew/sbin", "/usr/local/sbin", "/opt/pkg/bin"]
        let inherited = (environment["PATH"] ?? "").split(separator: ":").map(String.init).filter { $0.hasPrefix("/") }
        let user = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".local/bin").path
        var seen = Set<String>()
        return (standard + inherited + [user]).map {
            URL(fileURLWithPath: $0).appendingPathComponent(name).path
        }.filter { seen.insert($0).inserted }
    }
    static var defaultPath: String { defaultPath(for: .openfortivpn) }
    static func defaultPath(for kind: RuntimeKind) -> String {
        candidates(name: kind.executableName).first {
            FileManager.default.isExecutableFile(atPath: $0)
        } ?? {
            switch kind {
            case .openfortivpn: return "/opt/homebrew/bin/openfortivpn"
            case .openvpn: return "/opt/homebrew/sbin/openvpn"
            case .wireguard: return "/opt/homebrew/bin/wireguard-go"
            }
        }()
    }
}

