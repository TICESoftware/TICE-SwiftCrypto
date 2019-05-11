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

public enum CryptoManagerError: LocalizedError {
    case invalidMessageSignature
    case couldNotAccessSignedInUser
    case missingMembershipCertificate(member: Member)
    case decryptionError
    case conversationNotInitialized
    case serializationError(Error)
    case certificateValidationFailed(Error)

    public var errorDescription: String? {
        switch self {
        case .invalidMessageSignature: return "Invalid message signature"
        case .couldNotAccessSignedInUser: return "could not access signed in user"
        case .missingMembershipCertificate(let member): return "Missing membership certificate for \(member)"
        case .decryptionError: return "Decryption error"
        case .conversationNotInitialized: return "Conversation with user not initialized yet."
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

public typealias Certificate = String

public class CryptoManager {

    let info = "Let's Meet"
    let maxSkip = 100
    let maxCache = 100

    let handshake: X3DH

    let encoder: JSONEncoder
    let decoder: JSONDecoder

    var doubleRatchets: [UserId: DoubleRatchet] = [:]

    public init(handshake: X3DH?, encoder: JSONEncoder, decoder: JSONDecoder) throws {
        self.handshake = try handshake ?? X3DH()
        self.encoder = encoder
        self.decoder = decoder
    }

    public func generateKeys() throws -> UserKeyPairs {

        let privateSigningKey = try ECPrivateKey.make(for: .secp521r1)
        let publicSigningKey = try privateSigningKey.extractPublicKey()

        return UserKeyPairs(signingKeys: (privateKey: privateSigningKey, publicKey: publicSigningKey))
    }

    public func generateGroupKey() -> String {
        return "groupKey"
    }

    // MARK: Hashing

    public func hash(_ group: Team) -> String {
        return String(group.groupId.hashValue &+ group.members.hashValue &+ group.meetups.hashValue &+ group.settings.hashValue)
    }

    // MARK: Membership certificates

    public func createUserSignedMembershipCertificate(userId: UserId, groupId: GroupId, admin: Bool, signer: Signer) throws -> Certificate {
        return try createMembershipCertificate(userId: userId, groupId: groupId, admin: admin, issuer: .user(signer.userId), signingKey: signer.signingPrivateKey)
    }

    public func createServerSignedMembershipCertificate(userId: UserId, groupId: GroupId, admin: Bool, signingKey: ECPrivateKey) throws -> Certificate {
        return try createMembershipCertificate(userId: userId, groupId: groupId, admin: admin, issuer: .server, signingKey: signingKey)
    }

    private func createMembershipCertificate(userId: UserId, groupId: GroupId, admin: Bool, issuer: MembershipClaims.Issuer, signingKey: ECPrivateKey) throws -> Certificate {
        let issueDate = Date()

        let claims = MembershipClaims(iss: issuer, sub: userId, iat: issueDate, exp: issueDate.addingTimeInterval(3600), groupId: groupId, admin: admin)
        var jwt = JWT(claims: claims)

        let privateKeyData = signingKey.pemString.data(using: .utf8)!
        let jwtSigner = JWTSigner.es512(privateKey: privateKeyData)

        return try jwt.sign(using: jwtSigner)
    }

    public func validateUserSignedMembershipCertificate(certificate: Certificate, membership: Membership, issuer: User) throws {
        try validate(certificate: certificate, membership: membership, issuer: .user(issuer.userId), publicKey: issuer.publicKeys.signingKey)
    }

    public func validateServerSignedMembershipCertificate(certificate: Certificate, membership: Membership, publicKey: String) throws {
        try validate(certificate: certificate, membership: membership, issuer: .server, publicKey: publicKey)
    }

    private func validate(certificate: Certificate, membership: Membership, issuer: MembershipClaims.Issuer, publicKey: String) throws {
        let publicKeyData = publicKey.data(using: .utf8)!
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

    public func tokenKeyForGroupWith(groupKey: String, user: UserProtocol) -> String {
        return "tokenKey\(groupKey.hashValue)\(user.publicKeys.hashValue)"
    }

    // MARK: Encryption / Decryption

    public func createPublicKeyMaterial(signer: Signer) throws -> PublicKeyMaterial {
        return try handshake.createPrekeyBundle(oneTimePrekeysCount: 10, renewSignedPrekey: false, prekeySigner: { try sign(prekey: $0, with: signer) })
    }

    public func initConversation(with userId: UserId, remotePrekeyBundle: PrekeyBundle, remoteVerificationKey: ECPublicKey) throws -> ConversationInvitation {
        let keyAgreementInitiation = try handshake.initiateKeyAgreement(remotePrekeyBundle: remotePrekeyBundle, prekeySignatureVerifier: { verify(prekeySignature: $0, prekey: remotePrekeyBundle.signedPrekey, verificationPublicKey: remoteVerificationKey) }, info: info)

        doubleRatchets[userId] = try DoubleRatchet(keyPair: nil, remotePublicKey: remotePrekeyBundle.signedPrekey, sharedSecret: keyAgreementInitiation.sharedSecret, maxSkip: maxSkip, maxCache: maxCache, info: info)

        return ConversationInvitation(identityKey: keyAgreementInitiation.identityPublicKey, ephemeralKey: keyAgreementInitiation.ephemeralPublicKey, usedOneTimePrekey: keyAgreementInitiation.usedOneTimePrekey)
    }

    public func processConversationInvitation(_ conversationInvitation: ConversationInvitation, from userId: UserId) throws {
        let sharedSecret = try handshake.sharedSecretFromKeyAgreement(remoteIdentityPublicKey: conversationInvitation.identityKey, remoteEphemeralPublicKey: conversationInvitation.ephemeralKey, usedOneTimePrekey: conversationInvitation.usedOneTimePrekey, info: info)

        doubleRatchets[userId] = try DoubleRatchet(keyPair: handshake.signedPrekeyPair, remotePublicKey: nil, sharedSecret: sharedSecret, maxSkip: maxSkip, maxCache: maxCache, info: info)
    }

    public func encrypt<SettingsType: Encodable>(_ groupSettings: SettingsType) -> String {
        // swiftlint:disable:next force_try
        let encoded = try! encoder.encode(groupSettings)
        return String(data: encoded, encoding: .utf8)!
    }

    public func decrypt<SettingsType: Decodable>(encryptedSettings: Data, using groupKey: String) throws -> SettingsType {
        return try decoder.decode(SettingsType.self, from: encryptedSettings)
    }

    public func encrypt(membership: Membership, using groupKey: String) -> Membership {
        return membership
    }

    public func decrypt(encryptedMemberships: [Membership], using groupKey: String) -> Set<Membership> {
        return Set<Membership>(encryptedMemberships)
    }

    public func encrypt(groupKey: String, withParentGroupKey: String) -> String {
        return groupKey
    }

    public func decrypt(parentEncryptedGroupKey: String, using groupKey: String) throws -> String {
        return parentEncryptedGroupKey
    }

    private func generateEncryptionKey() -> String {
        return "encryptionKey"
    }

    private func encrypt(_ data: Data, encryptionKey: String) -> Data {
        return data
    }

    public func encrypt(message: String, for member: Member) throws -> Message {
        guard let doubleRatchet = doubleRatchets[member.user.userId] else {
            throw CryptoManagerError.conversationNotInitialized
        }

        return try doubleRatchet.encrypt(plaintext: message.bytes)
    }

    public func encrypt(_ payloadData: Data, for members: Set<Member>) throws -> (ciphertext: Data, recipients: Set<Recipient>) {
        let encryptionKey = generateEncryptionKey()
        let encryptedMessage = encrypt(payloadData, encryptionKey: encryptionKey)

        var recipients = Set<Recipient>()
        let operationQueue = OperationQueue()
        let insertRecipientQueue = DispatchQueue(label: "de.anbion.cryptoManager.encrypt")

        for member in members {
            guard let serverSignedMembershipCertificate = member.membership.serverSignedMembershipCertificate else {
                throw CryptoManagerError.missingMembershipCertificate(member: member)
            }

            operationQueue.addOperation {
                guard let encryptedMessageKey = try? self.encrypt(message: encryptionKey, for: member) else {
                    return
                }
                let recipient = Recipient(userId: member.user.userId, serverSignedMembershipCertificate: serverSignedMembershipCertificate, encryptedMessageKey: encryptedMessageKey as! String)

                _ = insertRecipientQueue.sync {
                    recipients.insert(recipient)
                }
            }
        }

        operationQueue.waitUntilAllOperationsAreFinished()

        return (ciphertext: encryptedMessage, recipients: recipients)
    }

    public func decrypt(encryptedMessageKey: Message, from userId: UserId, with signer: Signer) throws -> Bytes {
        guard let doubleRatchet = doubleRatchets[userId] else {
            throw CryptoManagerError.conversationNotInitialized
        }

        return try doubleRatchet.decrypt(message: encryptedMessageKey)
    }

    public func decrypt(encryptedPayload: Data, using key: String) throws -> PayloadContainer {
        return try decoder.decode(PayloadContainer.self, from: encryptedPayload)
    }

    // MARK: Sign / verify

    private func sign(prekey: PublicKey, with signer: Signer) throws -> Signatur {
        let publicKeyData = Data(prekey)
        let sig = try publicKeyData.sign(with: signer.signingPrivateKey)
        return sig.asn1
    }

    private func verify(prekeySignature: Signatur, prekey: PublicKey, verificationPublicKey: ECPublicKey) -> Bool {
        guard let sig = try? ECSignature(asn1: prekeySignature) else { return false }
        return sig.verify(plaintext: Data(prekey), using: verificationPublicKey)
    }

    public func sign(_ data: Data, with signer: Signer) -> String {
        return "SIGNED(\(data.base64EncodedString()))"
    }

    public func sign<T: Encodable>(object: T, with signer: Signer) throws -> String {
        let data = try encoder.encode(object)
        return sign(data, with: signer)
    }

    public func verify(_ signature: String) -> Bool {
        return true
    }

    public func verify(_ signature: String, with member: Member) -> Bool {
        return true
    }
}
