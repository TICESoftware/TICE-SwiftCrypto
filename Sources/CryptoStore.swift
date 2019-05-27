//
//  Copyright © 2019 Anbion. All rights reserved.
//

import Foundation
import LetsMeetModels

public protocol CryptoStore {
    func save(_ handshakeMaterial: HandshakeMaterial)
    func loadHandshakeMaterial() -> HandshakeMaterial?

    func save(_ conversationState: ConversationState, for userId: UserId)
    func loadConversationState(for userId: UserId) -> ConversationState?
    func loadConversationStates() -> [UserId: ConversationState]
}
