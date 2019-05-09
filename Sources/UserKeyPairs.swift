//
//  Copyright © 2018 Anbion. All rights reserved.
//

import LetsMeetModels
import CryptorECC

public struct UserKeyPairs {
    public let signingKeys: (privateKey: ECPrivateKey, publicKey: ECPublicKey)

    public var publicKeys: UserPublicKeys {
        return UserPublicKeys(signingKey: signingKeys.publicKey.pemString)
    }
    
    public init(signingKeys: (privateKey: ECPrivateKey, publicKey: ECPublicKey)) {
        self.signingKeys = signingKeys
    }
}
