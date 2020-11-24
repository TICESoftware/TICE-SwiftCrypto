//
//  File.swift
//  
//
//  Created by Andreas Ganske on 24.11.20.
//

import Foundation
import DoubleRatchet

public class TestMessageKeyCache: MessageKeyCache {
    public struct MessageIndex: Hashable {
        let publicKey: PublicKey
        let messageNumber: Int
    }

    private var messageKeyCache: [MessageIndex: MessageKey]

    init(keys: [MessageIndex: MessageKey] = [:]) {
        self.messageKeyCache = keys
    }

    public func add(messageKey: MessageKey, messageNumber: Int, publicKey: PublicKey) {
        let messageIndex = MessageIndex(publicKey: publicKey, messageNumber: messageNumber)
        messageKeyCache[messageIndex] = messageKey
    }

    public func getMessageKey(messageNumber: Int, publicKey: PublicKey) -> MessageKey? {
        let messageIndex = MessageIndex(publicKey: publicKey, messageNumber: messageNumber)
        return messageKeyCache[messageIndex]
    }
    
    public func remove(publicKey: PublicKey, messageNumber: Int) {
        let messageIndex = MessageIndex(publicKey: publicKey, messageNumber: messageNumber)
        messageKeyCache[messageIndex] = nil
    }
}
