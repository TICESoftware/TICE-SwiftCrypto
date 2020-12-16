//
//  File.swift
//  
//
//  Created by Andreas Ganske on 25.11.20.
//

import Foundation

public struct KeyPair: Codable {
    public let privateKey: PrivateKey
    public let publicKey: PublicKey

    public init(privateKey: PrivateKey, publicKey: PublicKey) {
        self.privateKey = privateKey
        self.publicKey = publicKey
    }
}

public struct HandshakeKeyMaterial: Codable, Hashable {
    public let signingKey: PublicKey
    public let identityKey: PublicKey
    public let signedPrekey: PublicKey
    public let prekeySignature: Signature
    public let oneTimePrekeys: [PublicKey]

    public init(signingKey: PublicKey, identityKey: PublicKey, signedPrekey: PublicKey, prekeySignature: Signature, oneTimePrekeys: [PublicKey]) {
        self.signingKey = signingKey
        self.identityKey = identityKey
        self.signedPrekey = signedPrekey
        self.prekeySignature = prekeySignature
        self.oneTimePrekeys = oneTimePrekeys
    }
}

// TODO: Move to TICE-iOS
public struct ConversationState: Codable {
    public let userId: UserId
    public let conversationId: ConversationId

    public let rootKey: SecretKey
    public let rootChainPublicKey: PublicKey
    public let rootChainPrivateKey: PrivateKey
    public var rootChainKeyPair: KeyPair { KeyPair(privateKey: rootChainPrivateKey, publicKey: rootChainPublicKey) }
    public let rootChainRemotePublicKey: PublicKey?
    public let sendingChainKey: SecretKey?
    public let receivingChainKey: SecretKey?

    public let sendMessageNumber: Int
    public let receivedMessageNumber: Int
    public let previousSendingChainLength: Int
    public let messageKeyCache: Data

    public init(userId: UserId, conversationId: ConversationId, rootKey: SecretKey, rootChainKeyPair: KeyPair, rootChainRemotePublicKey: PublicKey?, sendingChainKey: SecretKey?, receivingChainKey: SecretKey?, sendMessageNumber: Int, receivedMessageNumber: Int, previousSendingChainLength: Int, messageKeyCache: Data) {
        self.userId = userId
        self.conversationId = conversationId
        self.rootKey = rootKey
        self.rootChainPublicKey = rootChainKeyPair.publicKey
        self.rootChainPrivateKey = rootChainKeyPair.privateKey
        self.rootChainRemotePublicKey = rootChainRemotePublicKey
        self.sendingChainKey = sendingChainKey
        self.receivingChainKey = receivingChainKey
        self.sendMessageNumber = sendMessageNumber
        self.receivedMessageNumber = receivedMessageNumber
        self.previousSendingChainLength = previousSendingChainLength
        self.messageKeyCache = messageKeyCache
    }
}
