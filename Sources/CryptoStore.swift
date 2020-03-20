//
//  Copyright © 2019 Anbion. All rights reserved.
//

import Foundation
import TICEModels

public protocol CryptoStore {
    func saveIdentityKeyPair(_ keyPair: KeyPair) throws
    func savePrekeyPair(_ keyPair: KeyPair, signature: Signature) throws
    func saveOneTimePrekeyPairs(_ keyPairs: [KeyPair]) throws
    func loadIdentityKeyPair() throws -> KeyPair
    func loadPrekeyPair() throws -> KeyPair
    func loadPrekeySignature() throws -> Signature
    func loadPrivateOneTimePrekey(publicKey: PublicKey) throws -> PrivateKey
    func deleteOneTimePrekeyPair(publicKey: PublicKey) throws

    func save(_ conversationState: ConversationState) throws
    func loadConversationState(userId: UserId, conversationId: ConversationId) throws -> ConversationState?
    func loadConversationStates() throws -> [ConversationState]
}
