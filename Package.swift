// swift-tools-version:5.3
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
        .package(name: "TICEModels", url: "https://github.com/TICESoftware/TICE-SwiftModels.git", from: "49.0.0"),
        .package(name: "SwiftJWT", url: "https://github.com/TICESoftware/Swift-JWT.git", from: "3.6.2"),
        .package(name: "CryptorECC", url: "https://github.com/TICESoftware/BlueECC.git", from: "1.2.6"),
        .package(url: "https://github.com/TICESoftware/X3DH.git", from: "2.0.9"),
        .package(url: "https://github.com/TICESoftware/DoubleRatchet.git", from: "2.0.2"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.0.0"),
    ],
    targets: [
        .target(
            name: "TICECrypto",
            dependencies: ["SwiftJWT", "CryptorECC", "X3DH", "DoubleRatchet", .product(name: "Logging", package: "swift-log")],
            path: "Sources"),
        .testTarget(
            name: "TICECryptoTests",
            dependencies: ["SwiftJWT", "CryptorECC", "X3DH", "DoubleRatchet", "TICECrypto", "TICEModels"]),
    ]
)
