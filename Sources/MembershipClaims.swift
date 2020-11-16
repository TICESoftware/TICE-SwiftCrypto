//
//  Copyright © 2019 Anbion. All rights reserved.
//

import Foundation
import TICEModels
import JWTKit

public typealias JWTId = UUID

public struct MembershipClaims: JWTPayload {
    public let jti: JWTId
    public let iss: Issuer
    public let sub: UserId
    public let iat: IssuedAtClaim?
    public let exp: ExpirationClaim?
    public let groupId: GroupId
    public let admin: Bool
    
    public init(jti: JWTId, iss: Issuer, sub: UserId, iat: Date?, exp: Date?, groupId: GroupId, admin: Bool) {
        self.jti = jti
        self.iss = iss
        self.sub = sub
        self.iat = iat.map { IssuedAtClaim(value: $0) }
        self.exp = exp.map { ExpirationClaim(value: $0) }
        self.groupId = groupId
        self.admin = admin
    }
    
    public func verify(using signer: JWTSigner) throws {
        try exp?.verifyNotExpired(currentDate: Date().addingTimeInterval(CryptoManager.jwtValidationLeeway))
        try iat?.verifyIssuedInPast(currentDate: Date().addingTimeInterval(CryptoManager.jwtValidationLeeway))
    }

    public enum Issuer: Codable, Equatable, CustomStringConvertible {
        case server
        case user(UserId)

        public var description: String {
            switch self {
            case .server:
                return "server"
            case .user(let userId):
                return userId.uuidString
            }
        }

        public enum CodingKeys: String, CodingKey {
            case server
            case user
        }

        public init(from decoder: Decoder) throws {
            do {
                let rawString = try decoder.singleValueContainer().decode(String.self)

                if rawString == "server" {
                    self = .server
                } else {
                    guard let userId = UserId(uuidString: rawString) else {
                        throw CertificateValidationError.invalidClaims
                    }
                    self = .user(userId)
                }
            } catch is DecodingError {
                let container = try decoder.container(keyedBy: CodingKeys.self)
                if let userId = try container.decodeIfPresent(UUID.self, forKey: .user) {
                    self = .user(userId)
                } else {
                    let server = try container.decode(String.self, forKey: .server)
                    guard server == "server" else {
                        throw CertificateValidationError.invalidClaims
                    }

                    self = .server
                }
            }
        }

        public func encode(to encoder: Encoder) throws {
            var container = encoder.singleValueContainer()
            try container.encode(description)
        }
    }
}
