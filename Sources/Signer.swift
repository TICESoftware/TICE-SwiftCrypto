//
//  Copyright © 2018 Anbion. All rights reserved.
//

import CryptorECC
import LetsMeetModels

public protocol Signer: User {
    var certificatePrivateKey: ECPrivateKey { get }
}
