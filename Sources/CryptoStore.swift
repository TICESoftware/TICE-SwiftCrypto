//
//  Copyright © 2019 Anbion. All rights reserved.
//

import Foundation
import TICEModels

public protocol CryptoStore {
    func save(_ handshakeMaterial: HandshakeMaterial) throws
    func loadHandshakeMaterial() throws -> HandshakeMaterial?

    func save(_ conversationState: ConversationState) throws
    func loadConversationState(userId: UserId, conversationId: ConversationId) throws -> ConversationState?
    func loadConversationStates() throws -> [ConversationState]
}
