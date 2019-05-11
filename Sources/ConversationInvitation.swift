//
//  Copyright © 2019 Anbion. All rights reserved.
//

import X3DH

public struct ConversationInvitation: Codable {
    let identityKey: PublicKey
    let ephemeralKey: PublicKey
    let usedOneTimePrekey: PublicKey?
}
