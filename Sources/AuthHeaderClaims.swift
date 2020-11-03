//
//  Copyright © 2019 Anbion. All rights reserved.
//

import Foundation
import TICEModels
import JWTKit

public struct AuthHeaderClaims: JWTPayload {
    public var iss: UserId
    public var iat: IssuedAtClaim?
    public var exp: ExpirationClaim?
    public var nonce: Data
    
    public init(iss: UserId, iat: IssuedAtClaim?, exp: ExpirationClaim?, nonce: Data) {
        self.iss = iss
        self.iat = iat
        self.exp = exp
        self.nonce = nonce
    }
    
    public func verify() throws {
        try exp?.verifyNotExpired(currentDate: Date().addingTimeInterval(CryptoManager.jwtValidationLeeway))
        try iat?.verifyIssuedInPast(currentDate: Date().addingTimeInterval(CryptoManager.jwtValidationLeeway))
    }
    
    public func verify(using signer: JWTSigner) throws {
        try verify()
    }
}
