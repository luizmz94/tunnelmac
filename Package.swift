// swift-tools-version: 5.9
import PackageDescription
let package = Package(
    name: "VPNGUI",
    platforms: [.macOS(.v13)],
    products: [.executable(name: "VPNGUI", targets: ["VPNGUI"]),
               .executable(name: "VPNHelper", targets: ["VPNHelper"]),
               .executable(name: "VPNSupervisor", targets: ["VPNSupervisor"]),
               .library(name: "VPNApp", targets: ["VPNApp"]),
               .library(name: "VPNHelperCore", targets: ["VPNHelperCore"]),
               .library(name: "VPNHelperShared", targets: ["VPNHelperShared"]),
               .library(name: "ProcessBridge", targets: ["ProcessBridge"])],
    // In-app updates of the app bundle only (EdDSA-signed archives from the GitHub releases).
    dependencies: [.package(url: "https://github.com/sparkle-project/Sparkle", exact: "2.9.6")],
    targets: [
        // Per-connection C supervisor (fd-only inputs), executed by the helper.
        .executableTarget(name: "VPNSupervisor"),
        // posix_spawn/probe/process-identity primitives. No authorization APIs.
        .target(name: "ProcessBridge", publicHeadersPath: "include"),
        // Contracts shared by app and helper: XPC protocol, typed messages, validation, trust policy.
        .target(name: "VPNHelperShared", linkerSettings: [.linkedFramework("Security")]),
        // Helper policy/state, independent of the XPC transport (also driven by local checks).
        .target(name: "VPNHelperCore", dependencies: ["VPNHelperShared", "ProcessBridge"],
                linkerSettings: [.linkedFramework("Security"), .linkedFramework("SystemConfiguration")]),
        // LaunchDaemon registered with SMAppService.daemon(plistName:).
        .executableTarget(name: "VPNHelper", dependencies: ["VPNHelperCore", "VPNHelperShared"]),
        .target(name: "VPNApp", dependencies: ["VPNHelperShared", "ProcessBridge",
                                              .product(name: "Sparkle", package: "Sparkle")], path: "Sources/VPNGUI",
                linkerSettings: [.linkedFramework("Security"), .linkedFramework("AppKit"),
                                 .linkedFramework("ServiceManagement")]),
        .executableTarget(name: "VPNGUI", dependencies: ["VPNApp"], path: "Sources/VPNGUIEntry"),
        .testTarget(name: "ReviewTests", dependencies: ["VPNApp", "VPNHelperCore", "VPNHelperShared", "ProcessBridge"])
    ]
)
