//
//  Copyright © 2019 Anbion. All rights reserved.
//

import X3DH

public struct ConversationInvitation: Codable {
    public let identityKey: PublicKey
    public let ephemeralKey: PublicKey
    public let usedOneTimePrekey: PublicKey?

    public init(identityKey: PublicKey, ephemeralKey: PublicKey, usedOneTimePrekey: PublicKey?) {
        self.identityKey = identityKey
        self.ephemeralKey = ephemeralKey
        self.usedOneTimePrekey = usedOneTimePrekey
    }
}
