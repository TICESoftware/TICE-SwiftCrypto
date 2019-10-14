// swift-tools-version:5.1
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "LetsMeetCrypto",
    platforms: [
        .macOS(.v10_14), .iOS(.v12),
    ],
    products: [
        .library(
            name: "LetsMeetCrypto",
            targets: ["LetsMeetCrypto"]),
    ],
    dependencies: [
        .package(url: "git@github.com:AnbionApps/letsmeet-models.git", Version(19,0,0)...Version(27,0,0)),
        .package(url: "https://github.com/IBM-Swift/Swift-JWT.git", from: "3.4.1"),
        .package(url: "https://github.com/IBM-Swift/BlueECC.git", from: "1.2.1"),
        .package(url: "git@github.com:AnbionApps/X3DH.git", from: "1.0.0"),
        .package(url: "git@github.com:AnbionApps/DoubleRatchet.git", from: "1.0.0")
    ],
    targets: [
        .target(
            name: "LetsMeetCrypto",
            dependencies: ["LetsMeetModels", "SwiftJWT", "CryptorECC", "X3DH", "DoubleRatchet"],
            path: "Sources"),
        .testTarget(
            name: "LetsMeetCryptoTests",
            dependencies: ["LetsMeetCrypto", "LetsMeetModels", "SwiftJWT", "CryptorECC", "DoubleRatchet", "X3DH"]),
    ]
)
