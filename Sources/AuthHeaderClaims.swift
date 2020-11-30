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
    
    public init(iss: UserId, iat: Date?, exp: Date?, nonce: Data) {
        self.iss = iss
        self.iat = iat.map { IssuedAtClaim(value: $0) }
        self.exp = exp.map { ExpirationClaim(value: $0) }
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
