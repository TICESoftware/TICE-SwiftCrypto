//
//  Copyright © 2018 Anbion. All rights reserved.
//

import CryptorECC
import LetsMeetModels

public protocol Signer: User {
    var privateSigningKey: PrivateKey { get }
}

extension SignedInUser: Signer {
    public var privateSigningKey: PrivateKey {
        return keyPairs.signingKeyPair.privateKey
    }
}
