//
//  Copyright © 2019 Anbion. All rights reserved.
//

import Foundation
import TICEModels

public protocol CryptoStore {
    func save(_ handshakeMaterial: HandshakeMaterial) throws
    func loadHandshakeMaterial() throws -> HandshakeMaterial?

    func save(_ conversationState: ConversationState, for userId: UserId) throws
    func loadConversationState(for userId: UserId) -> ConversationState?
    func loadConversationStates() throws -> [UserId: ConversationState]?
}
