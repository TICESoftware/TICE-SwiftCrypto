// swift-tools-version:5.1
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "TICECrypto",
    platforms: [
        .macOS(.v10_14), .iOS(.v12),
    ],
    products: [
        .library(
            name: "TICECrypto",
            targets: ["TICECrypto"]),
    ],
    dependencies: [
        .package(url: "https://github.com/TICESoftware/TICE-SwiftModels.git", Version(19,0,0)..<Version(49,0,0)),
        .package(url: "https://github.com/TICESoftware/Swift-JWT.git", from: "3.6.2"),
        .package(url: "https://github.com/TICESoftware/BlueECC.git", from: "1.2.6"),
        .package(url: "https://github.com/TICESoftware/X3DH.git", from: "2.0.0"),
        .package(url: "https://github.com/TICESoftware/DoubleRatchet.git", from: "1.2.0"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.0.0"),
    ],
    targets: [
        .target(
            name: "TICECrypto",
            dependencies: ["TICEModels", "SwiftJWT", "CryptorECC", "X3DH", "DoubleRatchet", "Logging"],
            path: "Sources"),
        .testTarget(
            name: "TICECryptoTests",
            dependencies: ["TICECrypto", "TICEModels", "SwiftJWT", "CryptorECC", "DoubleRatchet", "X3DH"]),
    ]
)
