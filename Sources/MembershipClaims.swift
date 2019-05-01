//
//  Copyright © 2018 Anbion. All rights reserved.
//

import Foundation
import LetsMeetModels
import SwiftJWT

struct MembershipClaims: Claims {
    let iss: Issuer
    let sub: UserId
    let iat: Date?
    let exp: Date?
    let groupId: GroupId
    let admin: Bool

    enum Issuer: Codable {
        case server
        case user(UserId)

        enum CodingKeys: String, CodingKey {
            case server
            case user
        }

        init(from decoder: Decoder) throws {
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

        func encode(to encoder: Encoder) throws {
            var container = encoder.container(keyedBy: CodingKeys.self)
            switch self {
            case .server:
                try container.encode("server", forKey: .server)
            case .user(let userId):
                try container.encode(userId, forKey: .user)
            }
        }
    }
}
