//
//  Copyright © 2018 Anbion. All rights reserved.
//

import CryptorECC
import TICEModels

public protocol Signer {
    var privateSigningKey: PrivateKey { get }
}

extension SignedInUser: Signer {
    public var privateSigningKey: PrivateKey {
        return signingKeyPair.privateKey
    }
}
