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
    var doubleRatchets: [UserId: DoubleRatchet] = [:]

    let encoder: JSONEncoder
    let decoder: JSONDecoder

    public init(handshake: X3DH?, encoder: JSONEncoder, decoder: JSONDecoder) throws {
        self.handshake = try handshake ?? X3DH()
        self.encoder = encoder
        self.decoder = decoder
    }

    public func generateSigningKeyPair() throws -> SigningKeyPair {
        let privateSigningKey = try ECPrivateKey.make(for: .secp521r1)
        let publicSigningKey = try privateSigningKey.extractPublicKey()

        let privateKeyBytes = privateSigningKey.pemString.bytes
        let publicKeyBytes = publicSigningKey.pemString.bytes

        return SigningKeyPair(privateKey: Data(privateKeyBytes), publicKey: Data(publicKeyBytes))
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

    public func generatePublicHandshakeInfo(signer: Signer) throws -> UserPublicKeys {
        let publicKeyMaterial = try handshake.createPrekeyBundle(oneTimePrekeysCount: 10, renewSignedPrekey: false, prekeySigner: { try sign(prekey: Data($0), with: signer) })
        return UserPublicKeys(signingKey: signer.privateSigningKey, identityKey: Data(publicKeyMaterial.identityKey), signedPrekey: Data(publicKeyMaterial.signedPrekey), prekeySignature: publicKeyMaterial.prekeySignature, oneTimePrekeys: publicKeyMaterial.oneTimePrekeys.map { Data($0) })
    }

    public func initConversation(with userId: UserId, remotePrekeyBundle: PrekeyBundle, remoteSigningKey: LetsMeetModels.PublicKey) throws -> ConversationInvitation {
        guard let remoteSigningKeyPemString = Bytes(remoteSigningKey).utf8String,
            let remoteSigningKey = try? ECPublicKey(key: remoteSigningKeyPemString) else {
                throw CryptoManagerError.invalidKey
        }

        let keyAgreementInitiation = try handshake.initiateKeyAgreement(remotePrekeyBundle: remotePrekeyBundle, prekeySignatureVerifier: { verify(prekeySignature: $0, prekey: Data(remotePrekeyBundle.signedPrekey), verificationPublicKey: remoteSigningKey) }, info: info)

        doubleRatchets[userId] = try DoubleRatchet(keyPair: nil, remotePublicKey: remotePrekeyBundle.signedPrekey, sharedSecret: keyAgreementInitiation.sharedSecret, maxSkip: maxSkip, maxCache: maxCache, info: info)

        return ConversationInvitation(identityKey: Data(keyAgreementInitiation.identityPublicKey), ephemeralKey: Data(keyAgreementInitiation.ephemeralPublicKey), usedOneTimePrekey: keyAgreementInitiation.usedOneTimePrekey.map { Data($0) })
    }

    public func processConversationInvitation(_ conversationInvitation: ConversationInvitation, from userId: UserId) throws {
        let sharedSecret = try handshake.sharedSecretFromKeyAgreement(remoteIdentityPublicKey: Bytes(conversationInvitation.identityKey), remoteEphemeralPublicKey: Bytes(conversationInvitation.ephemeralKey), usedOneTimePrekey: conversationInvitation.usedOneTimePrekey.map { Bytes($0) }, info: info)

        doubleRatchets[userId] = try DoubleRatchet(keyPair: handshake.signedPrekeyPair, remotePublicKey: nil, sharedSecret: sharedSecret, maxSkip: maxSkip, maxCache: maxCache, info: info)
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

    public func encrypt(_ data: Data, for userId: UserId) throws -> Message {
        guard let doubleRatchet = doubleRatchets[userId] else {
            throw CryptoManagerError.conversationNotInitialized
        }

        return try doubleRatchet.encrypt(plaintext: Bytes(data))
    }

    private func decrypt(encryptedSecretKey: Ciphertext, from userId: UserId, with signer: Signer) throws -> SecretKey {
        let encryptedMessageKey = try decoder.decode(Message.self, from: encryptedSecretKey)
        let messageKeyData = try decrypt(encryptedMessage: encryptedMessageKey, from: userId, with: signer)
        return SecretKey(messageKeyData)
    }

    public func decrypt(encryptedMessage: Message, from userId: UserId, with signer: Signer) throws -> Data {
        guard let doubleRatchet = doubleRatchets[userId] else {
            throw CryptoManagerError.conversationNotInitialized
        }

        let plaintext = try doubleRatchet.decrypt(message: encryptedMessage)
        return Data(plaintext)
    }

    public func decrypt(encryptedData: Ciphertext, encryptedSecretKey: Ciphertext, from userId: UserId, signer: Signer) throws -> Data {
        let secretKey = try decrypt(encryptedSecretKey: encryptedSecretKey, from: userId, with: signer)
        let plaintext = try decrypt(encryptedData: encryptedData, secretKey: secretKey)

        return plaintext
    }

    // MARK: Sign / verify

    private func sign(prekey: LetsMeetModels.PublicKey, with signer: Signer) throws -> Signatur {
        guard let privateKeyString = Bytes(signer.privateSigningKey).utf8String else {
            throw CryptoManagerError.invalidKey
        }
        let signingKey = try ECPrivateKey(key: privateKeyString)
        let sig = try prekey.sign(with: signingKey)
        return sig.asn1
    }

    private func verify(prekeySignature: Signatur, prekey: LetsMeetModels.PublicKey, verificationPublicKey: ECPublicKey) -> Bool {
        guard let sig = try? ECSignature(asn1: prekeySignature) else { return false }
        return sig.verify(plaintext: Data(prekey), using: verificationPublicKey)
    }
}
