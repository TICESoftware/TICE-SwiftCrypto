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

public typealias SecretKey = Bytes
public typealias Certificate = String
public typealias Ciphertext = Bytes

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

    public func generateSigningKeyPair() throws -> (privateKey: PrivateKey, publicKey: PublicKey) {
        let privateSigningKey = try ECPrivateKey.make(for: .secp521r1)
        let publicSigningKey = try privateSigningKey.extractPublicKey()

        let privateKeyBytes = privateSigningKey.pemString.bytes
        let publicKeyBytes = publicSigningKey.pemString.bytes

        return (privateKey: privateKeyBytes, publicKey: publicKeyBytes)
    }

    public func generateGroupKey() -> SecretKey {
        return sodium.aead.xchacha20poly1305ietf.key()
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

        let privateKeyData = Data(signingKey)
        let jwtSigner = JWTSigner.es512(privateKey: privateKeyData)

        return try jwt.sign(using: jwtSigner)
    }

    public func validateUserSignedMembershipCertificate(certificate: Certificate, membership: Membership, issuer: User) throws {
        try validate(certificate: certificate, membership: membership, issuer: .user(issuer.userId), publicKey: issuer.publicSigningKey)
    }

    public func validateServerSignedMembershipCertificate(certificate: Certificate, membership: Membership, publicKey: PublicKey) throws {
        try validate(certificate: certificate, membership: membership, issuer: .server, publicKey: publicKey)
    }

    private func validate(certificate: Certificate, membership: Membership, issuer: MembershipClaims.Issuer, publicKey: PublicKey) throws {
        let publicKeyData = Data(publicKey)
        let jwtVerifier = JWTVerifier.es512(publicKey: publicKeyData)

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

        return try deriveHKDFKey(ikm: inputKeyingMaterial, L: 32)
    }

    // MARK: Handshake

    public func generatePublicHandshakeInfo(signer: Signer) throws -> PublicKeyMaterial {
        return try handshake.createPrekeyBundle(oneTimePrekeysCount: 10, renewSignedPrekey: false, prekeySigner: { try sign(prekey: $0, with: signer) })
    }

    public func initConversation(with userId: UserId, remotePrekeyBundle: PrekeyBundle, remoteSigningKey: PublicKey) throws -> ConversationInvitation {
        guard let remoteSigningKeyPemString = remoteSigningKey.utf8String,
            let remoteSigningKey = try? ECPublicKey(key: remoteSigningKeyPemString) else {
                throw CryptoManagerError.invalidKey
        }

        let keyAgreementInitiation = try handshake.initiateKeyAgreement(remotePrekeyBundle: remotePrekeyBundle, prekeySignatureVerifier: { verify(prekeySignature: $0, prekey: remotePrekeyBundle.signedPrekey, verificationPublicKey: remoteSigningKey) }, info: info)

        doubleRatchets[userId] = try DoubleRatchet(keyPair: nil, remotePublicKey: remotePrekeyBundle.signedPrekey, sharedSecret: keyAgreementInitiation.sharedSecret, maxSkip: maxSkip, maxCache: maxCache, info: info)

        return ConversationInvitation(identityKey: keyAgreementInitiation.identityPublicKey, ephemeralKey: keyAgreementInitiation.ephemeralPublicKey, usedOneTimePrekey: keyAgreementInitiation.usedOneTimePrekey)
    }

    public func processConversationInvitation(_ conversationInvitation: ConversationInvitation, from userId: UserId) throws {
        let sharedSecret = try handshake.sharedSecretFromKeyAgreement(remoteIdentityPublicKey: conversationInvitation.identityKey, remoteEphemeralPublicKey: conversationInvitation.ephemeralKey, usedOneTimePrekey: conversationInvitation.usedOneTimePrekey, info: info)

        doubleRatchets[userId] = try DoubleRatchet(keyPair: handshake.signedPrekeyPair, remotePublicKey: nil, sharedSecret: sharedSecret, maxSkip: maxSkip, maxCache: maxCache, info: info)
    }

    // MARK: Encryption / Decryption

    public func encrypt(_ data: Data, secretKey: SecretKey) throws -> Ciphertext {
        guard let cipher: Ciphertext = sodium.aead.xchacha20poly1305ietf.encrypt(message: Bytes(data), secretKey: secretKey) else {
            throw CryptoManagerError.encryptionError
        }
        return cipher
    }

    public func decrypt(encryptedData: Data, secretKey: SecretKey) throws -> Data {
        guard let plaintext = sodium.aead.xchacha20poly1305ietf.decrypt(nonceAndAuthenticatedCipherText: Bytes(encryptedData), secretKey: secretKey) else {
            throw CryptoManagerError.decryptionError
        }
        return Data(plaintext)
    }

    public func encrypt(_ data: Data, for user: User) throws -> Message {
        guard let doubleRatchet = doubleRatchets[user.userId] else {
            throw CryptoManagerError.conversationNotInitialized
        }

        return try doubleRatchet.encrypt(plaintext: Bytes(data))
    }

    public func encrypt(_ payloadData: Data, for members: Set<Member>) throws -> (ciphertext: Data, recipients: Set<Recipient>) {
        let secretKey = sodium.aead.xchacha20poly1305ietf.key()
        let encryptedMessage = try encrypt(payloadData, secretKey: secretKey)

        var recipients = Set<Recipient>()
        let operationQueue = OperationQueue()
        let insertRecipientQueue = DispatchQueue(label: "de.anbion.cryptoManager.encrypt")

        for member in members {
            guard let serverSignedMembershipCertificate = member.membership.serverSignedMembershipCertificate else {
                throw CryptoManagerError.missingMembershipCertificate(member: member)
            }

            operationQueue.addOperation {
                guard let encryptedMessageKey = try? self.encrypt(Data(secretKey), for: member.user),
                    let encryptedMessageKeyData = try? self.encoder.encode(encryptedMessageKey) else {
                    return
                }
                let recipient = Recipient(userId: member.user.userId, serverSignedMembershipCertificate: serverSignedMembershipCertificate, encryptedMessageKey: encryptedMessageKeyData)

                _ = insertRecipientQueue.sync {
                    recipients.insert(recipient)
                }
            }
        }

        operationQueue.waitUntilAllOperationsAreFinished()

        guard recipients.count == members.count else {
            throw CryptoManagerError.encryptionError
        }

        return (ciphertext: Data(encryptedMessage), recipients: recipients)
    }

    private func decrypt(encryptedSecretKey: Data, from userId: UserId, with signer: Signer) throws -> SecretKey {
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

    public func decrypt(encryptedData: Data, encryptedSecretKey: Data, from userId: UserId, signer: Signer) throws -> Data {
        let secretKey = try decrypt(encryptedSecretKey: encryptedSecretKey, from: userId, with: signer)
        let plaintext = try decrypt(encryptedData: encryptedData, secretKey: secretKey)

        return plaintext
    }

    // MARK: Sign / verify

    private func sign(prekey: PublicKey, with signer: Signer) throws -> Signatur {
        let publicKeyData = Data(prekey)
        guard let privateKeyString = signer.privateSigningKey.utf8String else {
            throw CryptoManagerError.invalidKey
        }
        let signingKey = try ECPrivateKey(key: privateKeyString)
        let sig = try publicKeyData.sign(with: signingKey)
        return sig.asn1
    }

    private func verify(prekeySignature: Signatur, prekey: PublicKey, verificationPublicKey: ECPublicKey) -> Bool {
        guard let sig = try? ECSignature(asn1: prekeySignature) else { return false }
        return sig.verify(plaintext: Data(prekey), using: verificationPublicKey)
    }
}
