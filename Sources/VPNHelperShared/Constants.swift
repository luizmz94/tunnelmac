import Foundation

/// Identifiers shared by the app, the LaunchDaemon plist and the helper.
/// The plist in `Contents/Library/LaunchDaemons` must use the same values.
public enum HelperConstants {
    public static let appIdentifier = "com.luiz.vpngui"
    public static let helperIdentifier = "com.luiz.vpngui.helper"
    public static let supervisorIdentifier = "com.luiz.vpngui.supervisor"
    public static let machServiceName = "com.luiz.vpngui.helper"
    public static let plistName = "com.luiz.vpngui.helper.plist"
    /// Single source of the product version; scripts/build.sh writes it into Info.plist.
    public static let version = "0.5.0"
    public static let releaseVersion = "0.5.0-rc.2"
    public static let build = "26"
    public static var fullVersion: String { "\(version) (\(build))" }
    /// Bumped whenever a request, response or event changes shape or meaning.
    public static let protocolVersion = 7
    /// Gateways commonly return to a fixed localhost:8020. Never random, never configurable by the client.
    public static let samlPort = 8020
    /// OpenVPN profiles carry inline certificates and keys (normalized profile ≤ 96 KB).
    public static let maximumRequestSize = 128 * 1024
    public static let maximumBatchSize = 1024 * 1024
    /// Root-owned state: approved runtime, supervisor copy, session registry, private work files.
    /// Every component from "/" down is root:wheel and not group/other writable on macOS.
    public static let stateDirectory = "/private/var/db/com.luiz.vpngui.helper"
    /// Authorization right (rule authenticate-admin) required to approve or remove the runtime.
    public static let authorizationRight = "com.luiz.vpngui.helper.manage-runtime"
    /// Sessions of one client that may run at the same time.
    public static let maximumSessionsPerClient = 16
}
