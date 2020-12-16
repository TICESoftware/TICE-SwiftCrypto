//
//  Copyright © 2019 Anbion. All rights reserved.
//

import Foundation
import SwiftJWT

public struct AuthHeaderClaims: Claims {
    public let iss: UserId
    public let iat: Date?
    public let exp: Date?
    public let nonce: Data
}
