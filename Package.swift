// swift-tools-version:5.1

import PackageDescription

let package = Package(
    name: "TICECrypto",
    platforms: [
        .macOS(.v10_15), .iOS(.v13),
    ],
    products: [
        .library(
            name: "TICECrypto",
            targets: ["TICECrypto"]),
    ],
    dependencies: [
        .package(url: "https://github.com/TICESoftware/TICE-SwiftModels.git", Version(19,0,0)..<Version(49,0,0)),
        .package(url: "https://github.com/TICESoftware/X3DH.git", from: "2.0.8"),
        .package(url: "https://github.com/TICESoftware/DoubleRatchet.git", from: "2.0.1"),
        
        .package(url: "https://github.com/vapor/jwt-kit.git", from: "4.0.0"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.0.0"),
        
        .package(url: "https://github.com/TICESoftware/Swift-JWT.git", from: "3.6.2"),
        .package(url: "https://github.com/TICESoftware/BlueECC.git", from: "1.2.6"),
    ],
    targets: [
        .target(
            name: "TICECrypto",
            dependencies: [
                .product(name: "TICEModels", package: "TICEModels"),
                .product(name: "X3DH", package: "X3DH"),
                .product(name: "DoubleRatchet", package: "DoubleRatchet"),
                
                .product(name: "JWTKit", package: "jwt-kit"),
                .product(name: "Logging", package: "swift-log"),

                .product(name: "CryptorECC", package: "CryptorECC"),
            ],
            path: "Sources"),
        .testTarget(
            name: "TICECryptoTests",
            dependencies: ["TICECrypto", "TICEModels", "SwiftJWT", "CryptorECC", "DoubleRatchet", "X3DH"]),
    ]
)
