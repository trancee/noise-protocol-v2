// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "NoiseProtocol",
    platforms: [.iOS(.v16), .macOS(.v13)],
    products: [
        .library(name: "NoiseProtocol", targets: ["NoiseProtocol"]),
    ],
    targets: [
        .target(name: "NoiseProtocol"),
        .testTarget(
            name: "NoiseProtocolTests",
            dependencies: ["NoiseProtocol"],
            resources: [.copy("Resources")]
        ),
    ]
)
