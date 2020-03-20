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
        .package(url: "git@github.com:TICESoftware/tice-models.git", Version(19,0,0)..<Version(47,0,0)),
        .package(url: "https://github.com/TICESoftware/Swift-JWT.git", from: "3.6.0"),
        .package(url: "https://github.com/IBM-Swift/BlueECC.git", from: "1.2.1"),
        .package(url: "git@github.com:TICESoftware/X3DH.git", from: "2.0.0"),
        .package(url: "git@github.com:TICESoftware/DoubleRatchet.git", from: "1.0.0")
    ],
    targets: [
        .target(
            name: "TICECrypto",
            dependencies: ["TICEModels", "SwiftJWT", "CryptorECC", "X3DH", "DoubleRatchet"],
            path: "Sources"),
        .testTarget(
            name: "TICECryptoTests",
            dependencies: ["TICECrypto", "TICEModels", "SwiftJWT", "CryptorECC", "DoubleRatchet", "X3DH"]),
    ]
)
