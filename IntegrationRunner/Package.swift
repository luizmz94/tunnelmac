// swift-tools-version: 5.9
import PackageDescription

// Debug-only local tooling is intentionally outside the distribution package.
let package = Package(
    name: "VPNIntegrationRunner",
    platforms: [.macOS(.v13)],
    dependencies: [.package(name: "VPNSource", path: "..")],
    targets: [.executableTarget(name: "VPNIntegrationRunner", dependencies: [
        .product(name: "VPNApp", package: "VPNSource"),
        .product(name: "VPNHelperCore", package: "VPNSource"),
        .product(name: "VPNHelperShared", package: "VPNSource"),
        .product(name: "ProcessBridge", package: "VPNSource")
    ], path: ".", exclude: ["Package.swift"])]
)
