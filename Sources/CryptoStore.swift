//
//  Copyright © 2019 Anbion. All rights reserved.
//

import Foundation
import TICEModels

public protocol CryptoStore {
    func save(_ handshakeMaterial: HandshakeMaterial) throws
    func loadHandshakeMaterial() throws -> HandshakeMaterial?

    func save(_ conversationState: ConversationState, for conversation: Conversation) throws
    func loadConversationState(for conversation: Conversation) -> ConversationState?
    func loadConversationStates() throws -> [Conversation: ConversationState]?
}
