//
//  Copyright © 2018 Anbion. All rights reserved.
//

import CryptorECC

public protocol Signer {
    var privateSigningKey: PrivateKey { get }
}
