//
//  Copyright © 2018 Anbion. All rights reserved.
//

import Foundation
import LetsMeetModels
import SwiftJWT
import CryptorECC
import X3DH
import DoubleRatchet
import Sodium
import HKDF

public enum CryptoManagerError: LocalizedError {
    case invalidMessageSignature
    case couldNotAccessSignedInUser
    case missingMembershipCertificate(member: Member)
    case encryptionError
    case decryptionError
    case hashingError
    case conversationNotInitialized
    case tokenGenerationFailed
    case invalidKey
    case serializationError(Error)
    case certificateValidationFailed(Error)

    public var errorDescription: String? {
        switch self {
        case .invalidMessageSignature: return "Invalid message signature"
        case .couldNotAccessSignedInUser: return "could not access signed in user"
        case .missingMembershipCertificate(let member): return "Missing membership certificate for \(member)"
        case .encryptionError: return "Encryption failed"
        case .decryptionError: return "Decryption failed"
        case .hashingError: return "Hashing failed"
        case .conversationNotInitialized: return "Conversation with user not initialized yet."
        case .tokenGenerationFailed: return "Could not generate token."
        case .invalidKey: return "Invalid key"
        case .serializationError(let error): return error.localizedDescription
        case .certificateValidationFailed(let error): return "Certificate validation failed. Reason: \(error.localizedDescription)"
        }
    }
}

public enum CertificateValidationError: LocalizedError {
    case invalidSignature
    case invalidMembership
    case invalidClaims
    case expired(ValidateClaimsResult)

    public var errorDescription: String? {
        switch self {
        case .invalidSignature: return "Invalid signature"
        case .invalidMembership: return "Invalid membership"
        case .invalidClaims: return "Invalid claims"
        case .expired(let validateClaimsResult): return "Certificate not valid anymore/yet. \(validateClaimsResult.description)"
        }
    }
}

public class CryptoManager {

    let sodium = Sodium()

    let info = "Let's Meet"
    let maxSkip = 100
    let maxCache = 100

    let handshake: X3DH
    var doubleRatchets: [UserId: DoubleRatchet]
    let doubleRatchetsQueue = DispatchQueue(label: "de.anbion.letsmeet.doubleRatchets", attributes: .concurrent)

    let cryptoStore: CryptoStore?
    let encoder: JSONEncoder
    let decoder: JSONDecoder

    public init(cryptoStore: CryptoStore?, encoder: JSONEncoder, decoder: JSONDecoder) throws {
        self.cryptoStore = cryptoStore
        self.encoder = encoder
        self.decoder = decoder

        if let handshakeMaterial = cryptoStore?.loadHandshakeMaterial() {
            let identityKeyPair = KeyExchange.KeyPair(publicKey: Bytes(handshakeMaterial.identityKeyPair.publicKey), secretKey: Bytes(handshakeMaterial.identityKeyPair.privateKey))
            let signedPrekeyPair = KeyExchange.KeyPair(publicKey: Bytes(handshakeMaterial.signedPrekeyPair.publicKey), secretKey: Bytes(handshakeMaterial.signedPrekeyPair.privateKey))
            let oneTimePrekeyPairs = handshakeMaterial.oneTimePrekeyPairs.map { KeyExchange.KeyPair(publicKey: Bytes($0.publicKey), secretKey: Bytes($0.privateKey)) }

            self.handshake = X3DH(identityKeyPair: identityKeyPair, signedPrekeyPair: signedPrekeyPair, oneTimePrekeyPairs: oneTimePrekeyPairs)
        } else {
            self.handshake = try X3DH()
        }

        if let conversationStates = cryptoStore?.loadConversationStates() {
            self.doubleRatchets = [:]
            for (userId, conversationState) in conversationStates {
                let rootChainKeyPair = KeyExchange.KeyPair(publicKey: Bytes(conversationState.rootChainKeyPair.publicKey), secretKey: Bytes(conversationState.rootChainKeyPair.privateKey))
                let messageKeyCacheState = try decoder.decode(MessageKeyCacheState.self, from: conversationState.messageKeyCache)
                let sessionState = SessionState(rootKey: Bytes(conversationState.rootKey), rootChainKeyPair: rootChainKeyPair, rootChainRemotePublicKey: conversationState.rootChainRemotePublicKey.map { Bytes($0) }, sendingChainKey: conversationState.sendingChainKey.map { Bytes($0) }, receivingChainKey: conversationState.receivingChainKey.map { Bytes($0) }, sendMessageNumber: conversationState.sendMessageNumber, receivedMessageNumber: conversationState.receivedMessageNumber, previousSendingChainLength: conversationState.previousSendingChainLength, messageKeyCacheState: messageKeyCacheState, info: info, maxSkip: maxSkip, maxCache: maxCache)
                self.set(DoubleRatchet(sessionState: sessionState), for: userId)
            }
        } else {
            self.doubleRatchets = [:]
        }
    }

    // MARK: Helper

    private func set(_ doubleRatchet: DoubleRatchet, for userId: UserId) {
        doubleRatchetsQueue.async(flags: .barrier) {
            self.doubleRatchets[userId] = doubleRatchet
        }
    }

    private func doubleRatchet(for userId: UserId) -> DoubleRatchet? {
        return doubleRatchetsQueue.sync { self.doubleRatchets[userId] }
    }

    // MARK: Persistence

    func saveHandshakeKeyMaterial() {
        let identityKeyPair = LetsMeetModels.KeyPair(privateKey: Data(handshake.keyMaterial.identityKeyPair.secretKey), publicKey: Data(handshake.keyMaterial.identityKeyPair.publicKey))
        let signedPrekeyPair = LetsMeetModels.KeyPair(privateKey: Data(handshake.keyMaterial.signedPrekeyPair.secretKey), publicKey: Data(handshake.keyMaterial.signedPrekeyPair.publicKey))
        let oneTimePrekeyPairs = handshake.keyMaterial.oneTimePrekeyPairs.map { LetsMeetModels.KeyPair(privateKey: Data($0.secretKey), publicKey: Data($0.publicKey)) }
        let handshakeMaterial = HandshakeMaterial(identityKeyPair: identityKeyPair, signedPrekeyPair: signedPrekeyPair, oneTimePrekeyPairs: oneTimePrekeyPairs)
        cryptoStore?.save(handshakeMaterial)
    }

    func saveConversationState(for userId: UserId) throws {
        guard let doubleRatchet = doubleRatchet(for: userId) else { return }
        let sessionState = doubleRatchet.sessionState

        let rootChainKeyPair = LetsMeetModels.KeyPair(privateKey: Data(sessionState.rootChainKeyPair.secretKey), publicKey: Data(sessionState.rootChainKeyPair.publicKey))
        let messageKeyCache = try encoder.encode(sessionState.messageKeyCacheState)
        let conversationState = ConversationState(rootKey: Data(sessionState.rootKey), rootChainKeyPair: rootChainKeyPair, rootChainRemotePublicKey: sessionState.rootChainRemotePublicKey.map { Data($0) }, sendingChainKey: sessionState.sendingChainKey.map { Data($0) }, receivingChainKey: sessionState.receivingChainKey.map { Data($0) }, sendMessageNumber: sessionState.sendMessageNumber, receivedMessageNumber: sessionState.receivedMessageNumber, previousSendingChainLength: sessionState.previousSendingChainLength, messageKeyCache: messageKeyCache)
        cryptoStore?.save(conversationState, for: userId)
    }

    // MARK: Key generation

    public func generateSigningKeyPair() throws -> LetsMeetModels.KeyPair {
        let privateSigningKey = try ECPrivateKey.make(for: .secp521r1)
        let publicSigningKey = try privateSigningKey.extractPublicKey()

        return LetsMeetModels.KeyPair(privateKey: signingKey(from: privateSigningKey.pemString), publicKey: signingKey(from: publicSigningKey.pemString))
    }

    public func signingKeyString(from key: Data) throws -> String {
        guard let keyString = Bytes(key).utf8String else {
            throw CryptoManagerError.invalidKey
        }
        return keyString
    }

    public func signingKey(from pemString: String) -> Data {
        return Data(pemString.bytes)
    }

    public func generateGroupKey() -> SecretKey {
        return Data(sodium.aead.xchacha20poly1305ietf.key())
    }

    // MARK: Membership certificates

    public func createUserSignedMembershipCertificate(userId: UserId, groupId: GroupId, admin: Bool, signerUserId: UserId, signer: Signer) throws -> Certificate {
        return try createMembershipCertificate(userId: userId, groupId: groupId, admin: admin, issuer: .user(signerUserId), signingKey: signer.privateSigningKey)
    }

    public func createServerSignedMembershipCertificate(userId: UserId, groupId: GroupId, admin: Bool, signingKey: PrivateKey) throws -> Certificate {
        return try createMembershipCertificate(userId: userId, groupId: groupId, admin: admin, issuer: .server, signingKey: signingKey)
    }

    private func createMembershipCertificate(userId: UserId, groupId: GroupId, admin: Bool, issuer: MembershipClaims.Issuer, signingKey: PrivateKey) throws -> Certificate {
        let issueDate = Date()

        let claims = MembershipClaims(iss: issuer, sub: userId, iat: issueDate, exp: issueDate.addingTimeInterval(3600), groupId: groupId, admin: admin)
        var jwt = JWT(claims: claims)

        let jwtSigner = JWTSigner.es512(privateKey: signingKey)

        return try jwt.sign(using: jwtSigner)
    }

    public func validateUserSignedMembershipCertificate(certificate: Certificate, membership: Membership, issuer: User) throws {
        try validate(certificate: certificate, membership: membership, issuer: .user(issuer.userId), publicKey: issuer.publicSigningKey)
    }

    public func validateServerSignedMembershipCertificate(certificate: Certificate, membership: Membership, publicKey: LetsMeetModels.PublicKey) throws {
        try validate(certificate: certificate, membership: membership, issuer: .server, publicKey: publicKey)
    }

    private func validate(certificate: Certificate, membership: Membership, issuer: MembershipClaims.Issuer, publicKey: LetsMeetModels.PublicKey) throws {
        let jwtVerifier = JWTVerifier.es512(publicKey: publicKey)

        let jwt = try JWT<MembershipClaims>(jwtString: certificate)

        guard jwt.claims.groupId == membership.groupId,
            jwt.claims.sub == membership.userId,
            (!membership.admin || jwt.claims.admin) else {
            throw CryptoManagerError.certificateValidationFailed(CertificateValidationError.invalidMembership)
        }

        guard JWT<MembershipClaims>.verify(certificate, using: jwtVerifier) else {
            throw CryptoManagerError.certificateValidationFailed(CertificateValidationError.invalidSignature)
        }

        let validateClaimsResult = jwt.validateClaims()
        guard validateClaimsResult == .success else {
            throw CryptoManagerError.certificateValidationFailed(CertificateValidationError.expired(validateClaimsResult))
        }
    }

    public func tokenKeyForGroupWith(groupKey: SecretKey, user: UserProtocol) throws -> SecretKey {
        var inputKeyingMaterial = Bytes()
        inputKeyingMaterial.append(contentsOf: groupKey)
        inputKeyingMaterial.append(contentsOf: user.publicSigningKey)

        let key = try deriveHKDFKey(ikm: inputKeyingMaterial, L: 32)
        return Data(key)
    }

    // MARK: Handshake

    public func generatePublicHandshakeInfo(signer: Signer, renewSignedPrekey: Bool = false) throws -> UserPublicKeys {
        let publicKeyMaterial = try handshake.createPrekeyBundle(oneTimePrekeysCount: 100, renewSignedPrekey: renewSignedPrekey, prekeySigner: { try sign(prekey: Data($0), with: signer) })
        let privateSigningKeyString = try signingKeyString(from: signer.privateSigningKey)
        let privateSigningKey = try ECPrivateKey(key: privateSigningKeyString)
        let publicSigningKey = try privateSigningKey.extractPublicKey()

        saveHandshakeKeyMaterial()

        return UserPublicKeys(signingKey: signingKey(from: publicSigningKey.pemString), identityKey: Data(publicKeyMaterial.identityKey), signedPrekey: Data(publicKeyMaterial.signedPrekey), prekeySignature: publicKeyMaterial.prekeySignature, oneTimePrekeys: publicKeyMaterial.oneTimePrekeys.map { Data($0) })
    }

    public func initConversation(with userId: UserId, remoteIdentityKey: LetsMeetModels.PublicKey, remoteSignedPrekey: LetsMeetModels.PublicKey, remotePrekeySignature: Signature, remoteOneTimePrekey: LetsMeetModels.PublicKey?, remoteSigningKey: LetsMeetModels.PublicKey) throws -> ConversationInvitation {
        let prekeyBundle = PrekeyBundle(identityKey: Bytes(remoteIdentityKey), signedPrekey: Bytes(remoteSignedPrekey), prekeySignature: remotePrekeySignature, oneTimePrekey: remoteOneTimePrekey.map { Bytes($0) })
        guard let remoteSigningKeyPemString = Bytes(remoteSigningKey).utf8String,
            let remoteSigningKey = try? ECPublicKey(key: remoteSigningKeyPemString) else {
                throw CryptoManagerError.invalidKey
        }

        let keyAgreementInitiation = try handshake.initiateKeyAgreement(remotePrekeyBundle: prekeyBundle, prekeySignatureVerifier: { verify(prekeySignature: $0, prekey: Data(prekeyBundle.signedPrekey), verificationPublicKey: remoteSigningKey) }, info: info)

        let doubleRatchet = try DoubleRatchet(keyPair: nil, remotePublicKey: prekeyBundle.signedPrekey, sharedSecret: keyAgreementInitiation.sharedSecret, maxSkip: maxSkip, maxCache: maxCache, info: info)
        set(doubleRatchet, for: userId)
        try saveConversationState(for: userId)

        return ConversationInvitation(identityKey: Data(keyAgreementInitiation.identityPublicKey), ephemeralKey: Data(keyAgreementInitiation.ephemeralPublicKey), usedOneTimePrekey: keyAgreementInitiation.usedOneTimePrekey.map { Data($0) })
    }

    public func processConversationInvitation(_ conversationInvitation: ConversationInvitation, from userId: UserId) throws {
        let sharedSecret = try handshake.sharedSecretFromKeyAgreement(remoteIdentityPublicKey: Bytes(conversationInvitation.identityKey), remoteEphemeralPublicKey: Bytes(conversationInvitation.ephemeralKey), usedOneTimePrekey: conversationInvitation.usedOneTimePrekey.map { Bytes($0) }, info: info)

        let doubleRatchet = try DoubleRatchet(keyPair: handshake.signedPrekeyPair, remotePublicKey: nil, sharedSecret: sharedSecret, maxSkip: maxSkip, maxCache: maxCache, info: info)
        set(doubleRatchet, for: userId)
        try saveConversationState(for: userId)
    }

    // MARK: Encryption / Decryption

    public func encrypt(_ data: Data) throws -> (ciphertext: Ciphertext, secretKey: SecretKey) {
        let secretKey = Data(sodium.aead.xchacha20poly1305ietf.key())
        let ciphertext = try encrypt(data, secretKey: secretKey)
        return (ciphertext: ciphertext, secretKey: secretKey)
    }

    public func encrypt(_ data: Data, secretKey: SecretKey) throws -> Ciphertext {
        guard let cipher: Bytes = sodium.aead.xchacha20poly1305ietf.encrypt(message: Bytes(data), secretKey: Bytes(secretKey)) else {
            throw CryptoManagerError.encryptionError
        }
        return Data(cipher)
    }

    public func decrypt(encryptedData: Ciphertext, secretKey: SecretKey) throws -> Data {
        guard let plaintext = sodium.aead.xchacha20poly1305ietf.decrypt(nonceAndAuthenticatedCipherText: Bytes(encryptedData), secretKey: Bytes(secretKey)) else {
            throw CryptoManagerError.decryptionError
        }
        return Data(plaintext)
    }

    public func encrypt(_ data: Data, for userId: UserId) throws -> Ciphertext {
        guard let doubleRatchet = doubleRatchet(for: userId) else {
            throw CryptoManagerError.conversationNotInitialized
        }

        let message = try doubleRatchet.encrypt(plaintext: Bytes(data))
        try saveConversationState(for: userId)

        return try encoder.encode(message)
    }

    private func decrypt(encryptedSecretKey: Ciphertext, from userId: UserId) throws -> SecretKey {
        let messageKeyData = try decrypt(encryptedMessage: encryptedSecretKey, from: userId)
        return SecretKey(messageKeyData)
    }

    public func decrypt(encryptedMessage: Ciphertext, from userId: UserId) throws -> Data {
        let encryptedMessage = try decoder.decode(Message.self, from: encryptedMessage)
        guard let doubleRatchet = doubleRatchet(for: userId) else {
            throw CryptoManagerError.conversationNotInitialized
        }

        let plaintext = try doubleRatchet.decrypt(message: encryptedMessage)
        try saveConversationState(for: userId)

        return Data(plaintext)
    }

    public func decrypt(encryptedData: Ciphertext, encryptedSecretKey: Ciphertext, from userId: UserId) throws -> Data {
        let secretKey = try decrypt(encryptedSecretKey: encryptedSecretKey, from: userId)
        let plaintext = try decrypt(encryptedData: encryptedData, secretKey: secretKey)

        return plaintext
    }

    // MARK: Sign / verify

    private func sign(prekey: LetsMeetModels.PublicKey, with signer: Signer) throws -> Signature {
        guard let privateKeyString = Bytes(signer.privateSigningKey).utf8String else {
            throw CryptoManagerError.invalidKey
        }
        let signingKey = try ECPrivateKey(key: privateKeyString)
        let sig = try prekey.sign(with: signingKey)
        return sig.asn1
    }

    private func verify(prekeySignature: Signature, prekey: LetsMeetModels.PublicKey, verificationPublicKey: ECPublicKey) -> Bool {
        guard let sig = try? ECSignature(asn1: prekeySignature) else { return false }
        return sig.verify(plaintext: Data(prekey), using: verificationPublicKey)
    }
    
    // MARK: Auth signature
    
    public func generateAuthHeader(signingKey: PrivateKey, userId: UserId) throws -> Certificate {
        let issueDate = Date()
        guard let randomBytes = sodium.randomBytes.buf(length: 16) else { throw CryptoManagerError.tokenGenerationFailed }
        let claims = AuthHeaderClaims(iss: userId, iat: issueDate, exp: issueDate.addingTimeInterval(120), nonce: Data(randomBytes))
        var jwt = JWT(claims: claims)
        
        let jwtSigner = JWTSigner.es512(privateKey: signingKey)
        return try jwt.sign(using: jwtSigner)
    }
    
    public func parseAuthHeaderClaims(_ authHeader: Certificate) throws -> UserId {
        let jwt = try JWT<AuthHeaderClaims>(jwtString: authHeader)
    
        let validateClaimsResult = jwt.validateClaims()
        guard validateClaimsResult == .success else {
            throw CryptoManagerError.certificateValidationFailed(CertificateValidationError.expired(validateClaimsResult))
        }
        return jwt.claims.iss
    }
    
    public func verify(authHeader: Certificate, publicKey: LetsMeetModels.PublicKey) -> Bool {
        let jwtVerifier = JWTVerifier.es512(publicKey: publicKey)
        return JWT<AuthHeaderClaims>.verify(authHeader, using: jwtVerifier)
    }
}
