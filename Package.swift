// swift-tools-version:5.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "LetsMeetCrypto",
    platforms: [
        .macOS(.v10_13), .iOS(.v12),
    ],
    products: [
        .library(
            name: "LetsMeetCrypto",
            targets: ["LetsMeetCrypto"]),
    ],
    dependencies: [
        .package(url: "git@github.com:AnbionApps/letsmeet-models.git", from: "2.0.0")
    ],
    targets: [
        .target(
            name: "LetsMeetCrypto",
            dependencies: ["LetsMeetModels"],
            path: "Sources"),
        .testTarget(
            name: "LetsMeetCryptoTests",
            dependencies: ["LetsMeetCrypto"]),
    ]
)
