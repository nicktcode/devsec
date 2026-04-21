// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "damit",
    platforms: [
        .macOS(.v14)
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser", from: "1.5.0"),
        .package(url: "https://github.com/sindresorhus/LaunchAtLogin-Modern", from: "1.1.0"),
    ],
    targets: [
        .target(
            name: "DevsecCore",
            dependencies: []
        ),
        .executableTarget(
            name: "damit-cli",
            dependencies: [
                "DevsecCore",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ]
        ),
        .executableTarget(
            name: "DevsecApp",
            dependencies: [
                "DevsecCore",
                .product(name: "LaunchAtLogin", package: "LaunchAtLogin-Modern"),
            ],
            resources: [
                // Bundles the menubar silhouette (loaded as template
                // image for automatic system tinting) and the six
                // color state beaver variants used inside the popover
                // and Full Report window.
                .process("Resources"),
            ]
        ),
        .testTarget(
            name: "DevsecCoreTests",
            dependencies: ["DevsecCore"]
        ),
    ]
)
