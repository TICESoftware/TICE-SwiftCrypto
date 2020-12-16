//
//  Copyright © 2019 Anbion. All rights reserved.
//

import Foundation
import SwiftJWT

public typealias JWTId = UUID

public struct MembershipClaims: Claims {
    public let jti: JWTId
    public let iss: Issuer
    public let sub: UserId
    public let iat: Date?
    public let exp: Date?
    public let groupId: GroupId
    public let admin: Bool

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
                if let userId = try container.decodeIfPresent(UserId.self, forKey: .user) {
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
