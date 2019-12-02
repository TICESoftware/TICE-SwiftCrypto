//
//  Copyright © 2018 Anbion. All rights reserved.
//

import Foundation
import TICEModels
import SwiftJWT
import CryptorECC
import X3DH
import DoubleRatchet
import Sodium
import HKDF

public typealias ConversationFingerprint = String
public typealias ConversationId = UUID

public enum CryptoManagerError: LocalizedError {
    case initializationFailed(Error)
    case invalidMessageSignature
    case couldNotAccessSignedInUser
    case missingMembershipCertificate(member: Member)
    case encryptionError
    case decryptionError(Error?)
    case hashingError
    case conversationNotInitialized
    case maxSkipExceeded
    case tokenGenerationFailed
    case invalidKey
    case serializationError(Error)
    case certificateValidationFailed(Error)

    public var errorDescription: String? {
        switch self {
        case .initializationFailed(let error): return "Initialization failed. Reason: \(error)"
        case .invalidMessageSignature: return "Invalid message signature"
        case .couldNotAccessSignedInUser: return "could not access signed in user"
        case .missingMembershipCertificate(let member): return "Missing membership certificate for \(member)"
        case .encryptionError: return "Encryption failed"
        case .decryptionError(let error): return "Decryption failed. Reason: \(error?.localizedDescription ?? "None")"
        case .hashingError: return "Hashing failed"
        case .conversationNotInitialized: return "Conversation with user not initialized yet."
        case .maxSkipExceeded: return "Skipped too many messages. Ratchet step required."
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
    case revoked
    case expired(ValidateClaimsResult)

    public var errorDescription: String? {
        switch self {
        case .invalidSignature: return "Invalid signature"
        case .invalidMembership: return "Invalid membership"
        case .invalidClaims: return "Invalid claims"
        case .revoked: return "Certificate is revoked"
        case .expired(let validateClaimsResult): return "Certificate not valid anymore/yet. \(validateClaimsResult.description)"
        }
    }
}

public struct Conversation: Hashable, Codable {
    public let userId: UserId
    public let conversationId: ConversationId

    public init(userId: UserId, conversationId: ConversationId) {
        self.userId = userId
        self.conversationId = conversationId
    }
}

public class CryptoManager {

    let sodium = Sodium()

    let info = "TICE"
    let maxSkip = 100
    let maxCache = 100
    let certificatesValidFor: TimeInterval = 60*60*24*30*6
    let certificatesMaxValidInHistory: TimeInterval = 60*60*24*30*6

    var handshake: X3DH
    @SynchronizedProperty var doubleRatchets: [Conversation: DoubleRatchet]

    let cryptoStore: CryptoStore?
    let encoder: JSONEncoder
    let decoder: JSONDecoder

    public init(restoreFrom cryptoStore: CryptoStore, encoder: JSONEncoder, decoder: JSONDecoder) throws {
        self.cryptoStore = cryptoStore
        self.encoder = encoder
        self.decoder = decoder

        if let handshakeMaterial = try cryptoStore.loadHandshakeMaterial() {
            let identityKeyPair = KeyExchange.KeyPair(publicKey: Bytes(handshakeMaterial.identityKeyPair.publicKey), secretKey: Bytes(handshakeMaterial.identityKeyPair.privateKey))
            let signedPrekeyPair = KeyExchange.KeyPair(publicKey: Bytes(handshakeMaterial.signedPrekeyPair.publicKey), secretKey: Bytes(handshakeMaterial.signedPrekeyPair.privateKey))
            let oneTimePrekeyPairs = handshakeMaterial.oneTimePrekeyPairs.map { KeyExchange.KeyPair(publicKey: Bytes($0.publicKey), secretKey: Bytes($0.privateKey)) }

            handshake = X3DH(identityKeyPair: identityKeyPair, signedPrekeyPair: signedPrekeyPair, oneTimePrekeyPairs: oneTimePrekeyPairs)
        } else {
            do {
                self.handshake = try X3DH()
            } catch {
                throw CryptoManagerError.initializationFailed(error)
            }
        }

        self.doubleRatchets = [:]
        try reloadConversationStates()
    }

    public init(cryptoStore: CryptoStore?, encoder: JSONEncoder, decoder: JSONDecoder) throws {
        self.cryptoStore = cryptoStore
        self.encoder = encoder
        self.decoder = decoder
        self.handshake = try X3DH()
        self.doubleRatchets = [:]
    }

    // MARK: Persistence

    private func saveHandshakeKeyMaterial() throws {
        let identityKeyPair = TICEModels.KeyPair(privateKey: Data(handshake.keyMaterial.identityKeyPair.secretKey), publicKey: Data(handshake.keyMaterial.identityKeyPair.publicKey))
        let signedPrekeyPair = TICEModels.KeyPair(privateKey: Data(handshake.keyMaterial.signedPrekeyPair.secretKey), publicKey: Data(handshake.keyMaterial.signedPrekeyPair.publicKey))
        let oneTimePrekeyPairs = handshake.keyMaterial.oneTimePrekeyPairs.map { TICEModels.KeyPair(privateKey: Data($0.secretKey), publicKey: Data($0.publicKey)) }
        let handshakeMaterial = HandshakeMaterial(identityKeyPair: identityKeyPair, signedPrekeyPair: signedPrekeyPair, oneTimePrekeyPairs: oneTimePrekeyPairs)
        try cryptoStore?.save(handshakeMaterial)
    }

    private func saveConversationState(for conversation: Conversation) throws {
        guard let doubleRatchet = doubleRatchets[conversation] else { return }
        let sessionState = doubleRatchet.sessionState

        let rootChainKeyPair = TICEModels.KeyPair(privateKey: Data(sessionState.rootChainKeyPair.secretKey), publicKey: Data(sessionState.rootChainKeyPair.publicKey))
        let messageKeyCache = try encoder.encode(sessionState.messageKeyCacheState)
        let conversationState = ConversationState(rootKey: Data(sessionState.rootKey), rootChainKeyPair: rootChainKeyPair, rootChainRemotePublicKey: sessionState.rootChainRemotePublicKey.map { Data($0) }, sendingChainKey: sessionState.sendingChainKey.map { Data($0) }, receivingChainKey: sessionState.receivingChainKey.map { Data($0) }, sendMessageNumber: sessionState.sendMessageNumber, receivedMessageNumber: sessionState.receivedMessageNumber, previousSendingChainLength: sessionState.previousSendingChainLength, messageKeyCache: messageKeyCache)
        try cryptoStore?.save(conversationState, for: conversation)
    }

    public func reloadConversationStates() throws {
        var doubleRatchets: [Conversation: DoubleRatchet] = [:]
        if let conversationStates = try cryptoStore?.loadConversationStates() {
            let loadedDoubleRatchets = try conversationStates.mapValues { conversationState -> DoubleRatchet in
                let rootChainKeyPair = KeyExchange.KeyPair(publicKey: Bytes(conversationState.rootChainKeyPair.publicKey), secretKey: Bytes(conversationState.rootChainKeyPair.privateKey))
                let messageKeyCacheState = try decoder.decode(MessageKeyCacheState.self, from: conversationState.messageKeyCache)
                let sessionState = SessionState(rootKey: Bytes(conversationState.rootKey), rootChainKeyPair: rootChainKeyPair, rootChainRemotePublicKey: conversationState.rootChainRemotePublicKey.map { Bytes($0) }, sendingChainKey: conversationState.sendingChainKey.map { Bytes($0) }, receivingChainKey: conversationState.receivingChainKey.map { Bytes($0) }, sendMessageNumber: conversationState.sendMessageNumber, receivedMessageNumber: conversationState.receivedMessageNumber, previousSendingChainLength: conversationState.previousSendingChainLength, messageKeyCacheState: messageKeyCacheState, info: info, maxSkip: maxSkip, maxCache: maxCache)
                return DoubleRatchet(sessionState: sessionState)
            }
            doubleRatchets.merge(loadedDoubleRatchets, uniquingKeysWith: { (_, new) in new })
        }
        self.doubleRatchets = doubleRatchets
    }

    // MARK: Key generation

    public func generateSigningKeyPair() throws -> TICEModels.KeyPair {
        let privateSigningKey = try ECPrivateKey.make(for: .secp521r1)
        let publicSigningKey = try privateSigningKey.extractPublicKey()

        return TICEModels.KeyPair(privateKey: signingKey(from: privateSigningKey.pemString), publicKey: signingKey(from: publicSigningKey.pemString))
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
        return try createMembershipCertificate(jwtId: UUID(), userId: userId, groupId: groupId, admin: admin, issuer: .user(signerUserId), signingKey: signer.privateSigningKey)
    }

    public func createServerSignedMembershipCertificate(jwtId: JWTId = UUID(), userId: UserId, groupId: GroupId, admin: Bool, signingKey: PrivateKey) throws -> Certificate {
        return try createMembershipCertificate(jwtId: jwtId, userId: userId, groupId: groupId, admin: admin, issuer: .server, signingKey: signingKey)
    }

    private func createMembershipCertificate(jwtId: JWTId, userId: UserId, groupId: GroupId, admin: Bool, issuer: MembershipClaims.Issuer, signingKey: PrivateKey) throws -> Certificate {
        let issueDate = Date()

        let claims = MembershipClaims(jti: jwtId, iss: issuer, sub: userId, iat: issueDate, exp: issueDate.addingTimeInterval(certificatesValidFor), groupId: groupId, admin: admin)
        var jwt = JWT(claims: claims)

        let jwtSigner = JWTSigner.es512(privateKey: signingKey, signatureType: .asn1)

        return try jwt.sign(using: jwtSigner)
    }

    public func validateUserSignedMembershipCertificate(certificate: Certificate, membership: Membership, issuer: User) throws {
        try validate(certificate: certificate, membership: membership, issuer: .user(issuer.userId), publicKey: issuer.publicSigningKey)
    }

    public func validateServerSignedMembershipCertificate(certificate: Certificate, membership: Membership, publicKey: TICEModels.PublicKey) throws {
        try validate(certificate: certificate, membership: membership, issuer: .server, publicKey: publicKey)
    }

    private func validate(certificate: Certificate, membership: Membership, issuer: MembershipClaims.Issuer, publicKey: TICEModels.PublicKey) throws {
        let jwtVerifier = JWTVerifier.es512(publicKey: publicKey, signatureType: signatureType(of: certificate))

        let jwt = try JWT<MembershipClaims>(jwtString: certificate)

        guard jwt.claims.groupId == membership.groupId,
            jwt.claims.sub == membership.userId,
            (!membership.admin || jwt.claims.admin) else {
            throw CryptoManagerError.certificateValidationFailed(CertificateValidationError.invalidMembership)
        }

        guard jwt.claims.iss == issuer else {
            throw CryptoManagerError.certificateValidationFailed(CertificateValidationError.invalidClaims)
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

        try saveHandshakeKeyMaterial()

        return UserPublicKeys(signingKey: signingKey(from: publicSigningKey.pemString), identityKey: Data(publicKeyMaterial.identityKey), signedPrekey: Data(publicKeyMaterial.signedPrekey), prekeySignature: publicKeyMaterial.prekeySignature, oneTimePrekeys: publicKeyMaterial.oneTimePrekeys.map { Data($0) })
    }

    public func initConversation(with userId: UserId, conversationId: ConversationId, remoteIdentityKey: TICEModels.PublicKey, remoteSignedPrekey: TICEModels.PublicKey, remotePrekeySignature: Signature, remoteOneTimePrekey: TICEModels.PublicKey?, remoteSigningKey: TICEModels.PublicKey) throws -> ConversationInvitation {
        let prekeyBundle = PrekeyBundle(identityKey: Bytes(remoteIdentityKey), signedPrekey: Bytes(remoteSignedPrekey), prekeySignature: remotePrekeySignature, oneTimePrekey: remoteOneTimePrekey.map { Bytes($0) })
        guard let remoteSigningKeyPemString = Bytes(remoteSigningKey).utf8String else {
            throw CryptoManagerError.invalidKey
        }
        let remoteSigningKey = try ECPublicKey(key: remoteSigningKeyPemString)

        let verifier: PrekeySignatureVerifier = { signature throws in
            try self.verify(prekeySignature: signature, prekey: Data(prekeyBundle.signedPrekey), verificationPublicKey: remoteSigningKey)
        }
        let keyAgreementInitiation = try handshake.initiateKeyAgreement(remotePrekeyBundle: prekeyBundle, prekeySignatureVerifier: verifier, info: info)
        try saveHandshakeKeyMaterial()

        let doubleRatchet = try DoubleRatchet(keyPair: nil, remotePublicKey: prekeyBundle.signedPrekey, sharedSecret: keyAgreementInitiation.sharedSecret, maxSkip: maxSkip, maxCache: maxCache, info: info)
        let conversation = Conversation(userId: userId, conversationId: conversationId)
        doubleRatchets[conversation] = doubleRatchet
        try saveConversationState(for: conversation)

        return ConversationInvitation(identityKey: Data(keyAgreementInitiation.identityPublicKey), ephemeralKey: Data(keyAgreementInitiation.ephemeralPublicKey), usedOneTimePrekey: keyAgreementInitiation.usedOneTimePrekey.map { Data($0) })
    }

    public func processConversationInvitation(_ conversationInvitation: ConversationInvitation, from userId: UserId, conversationId: ConversationId) throws {
        let sharedSecret = try handshake.sharedSecretFromKeyAgreement(remoteIdentityPublicKey: Bytes(conversationInvitation.identityKey), remoteEphemeralPublicKey: Bytes(conversationInvitation.ephemeralKey), usedOneTimePrekey: conversationInvitation.usedOneTimePrekey.map { Bytes($0) }, info: info)

        let doubleRatchet = try DoubleRatchet(keyPair: handshake.signedPrekeyPair, remotePublicKey: nil, sharedSecret: sharedSecret, maxSkip: maxSkip, maxCache: maxCache, info: info)
        let conversation = Conversation(userId: userId, conversationId: conversationId)
        doubleRatchets[conversation] = doubleRatchet
        try saveConversationState(for: conversation)
    }

    public func conversationExisting(userId: UserId, conversationId: ConversationId) -> Bool {
        let conversation = Conversation(userId: userId, conversationId: conversationId)
        return doubleRatchets.keys.contains(conversation)
    }

    public func conversationFingerprint(ciphertext: Ciphertext) throws -> ConversationFingerprint {
        let encryptedMessage = try decoder.decode(Message.self, from: ciphertext)
        return Data(encryptedMessage.header.publicKey).base64EncodedString()
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
            throw CryptoManagerError.decryptionError(nil)
        }
        return Data(plaintext)
    }

    public func encrypt(_ data: Data, for userId: UserId, conversationId: ConversationId) throws -> Ciphertext {
        let conversation = Conversation(userId: userId, conversationId: conversationId)
        guard let doubleRatchet = doubleRatchets[conversation] else {
            throw CryptoManagerError.conversationNotInitialized
        }

        let message = try doubleRatchet.encrypt(plaintext: Bytes(data))
        try saveConversationState(for: conversation)

        return try encoder.encode(message)
    }

    private func decrypt(encryptedSecretKey: Ciphertext, from userId: UserId, conversationId: ConversationId) throws -> SecretKey {
        let messageKeyData = try decrypt(encryptedMessage: encryptedSecretKey, from: userId, conversationId: conversationId)
        return SecretKey(messageKeyData)
    }

    public func decrypt(encryptedMessage: Ciphertext, from userId: UserId, conversationId: ConversationId) throws -> Data {
        let encryptedMessage = try decoder.decode(Message.self, from: encryptedMessage)
        let conversation = Conversation(userId: userId, conversationId: conversationId)
        guard let doubleRatchet = doubleRatchets[conversation] else {
            throw CryptoManagerError.conversationNotInitialized
        }

        let plaintext: Bytes
        do {
            plaintext = try doubleRatchet.decrypt(message: encryptedMessage)
        } catch DRError.exceedMaxSkip {
            throw CryptoManagerError.maxSkipExceeded
        } catch {
            throw CryptoManagerError.decryptionError(error)
        }

        try saveConversationState(for: conversation)

        return Data(plaintext)
    }

    public func decrypt(encryptedData: Ciphertext, encryptedSecretKey: Ciphertext, from userId: UserId, conversationId: ConversationId) throws -> Data {
        let secretKey = try decrypt(encryptedSecretKey: encryptedSecretKey, from: userId, conversationId: conversationId)
        let plaintext = try decrypt(encryptedData: encryptedData, secretKey: secretKey)

        return plaintext
    }

    // MARK: Sign / verify

    private func sign(prekey: TICEModels.PublicKey, with signer: Signer) throws -> Signature {
        guard let privateKeyString = Bytes(signer.privateSigningKey).utf8String else {
            throw CryptoManagerError.invalidKey
        }
        let signingKey = try ECPrivateKey(key: privateKeyString)
        let sig = try prekey.sign(with: signingKey)
        return sig.asn1
    }

    private func verify(prekeySignature: Signature, prekey: TICEModels.PublicKey, verificationPublicKey: ECPublicKey) throws -> Bool {
        let sig = try ECSignature(asn1: prekeySignature)
        return sig.verify(plaintext: Data(prekey), using: verificationPublicKey)
    }

    // MARK: Auth signature

    public func generateAuthHeader(signingKey: PrivateKey, userId: UserId) throws -> Certificate {
        let issueDate = Date()
        guard let randomBytes = sodium.randomBytes.buf(length: 16) else { throw CryptoManagerError.tokenGenerationFailed }
        let claims = AuthHeaderClaims(iss: userId, iat: issueDate, exp: issueDate.addingTimeInterval(120), nonce: Data(randomBytes))
        var jwt = JWT(claims: claims)

        let jwtSigner = JWTSigner.es512(privateKey: signingKey, signatureType: .asn1)
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

    public func verify(authHeader: Certificate, publicKey: TICEModels.PublicKey) -> Bool {
        let jwtVerifier = JWTVerifier.es512(publicKey: publicKey, signatureType: signatureType(of: authHeader))
        return JWT<AuthHeaderClaims>.verify(authHeader, using: jwtVerifier)
    }
}

public func signatureType(of jwt: Certificate) -> ECSignatureType {
    if let signature = jwt.components(separatedBy: ".").last, signature.count > 178 {
        return .asn1
    } else {
        return .rs
    }
}
