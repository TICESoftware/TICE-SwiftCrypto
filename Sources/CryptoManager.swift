//
//  Copyright © 2018 Anbion. All rights reserved.
//

import Foundation
import LetsMeetModels
import SwiftJWT
import CryptorECC

public enum CryptoManagerError: LocalizedError {
    case invalidMessageSignature
    case couldNotAccessSignedInUser
    case missingMembershipCertificate(member: Member)
    case decryptionError
    case serializationError(Error)
    case certificateValidationFailed(Error)

    public var errorDescription: String? {
        switch self {
        case .invalidMessageSignature: return "Invalid message signature"
        case .couldNotAccessSignedInUser: return "could not access signed in user"
        case .missingMembershipCertificate(let member): return "Missing membership certificate for \(member)"
        case .decryptionError: return "Decryption error"
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

public typealias Message = String
public typealias Certificate = String

public class CryptoManager {

    let encoder: JSONEncoder
    let decoder: JSONDecoder

    public init(encoder: JSONEncoder, decoder: JSONDecoder) {
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
        return try createMembershipCertificate(userId: userId, groupId: groupId, admin: admin, issuer: .user(signer.userId), signingKey: signer.certificatePrivateKey)
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

    public func encrypt(message: Message, for member: Member) -> String {
        return message
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
                let encryptedMessageKey = self.encrypt(message: encryptionKey, for: member)
                let recipient = Recipient(userId: member.user.userId, serverSignedMembershipCertificate: serverSignedMembershipCertificate, encryptedMessageKey: encryptedMessageKey)

                _ = insertRecipientQueue.sync {
                    recipients.insert(recipient)
                }
            }
        }

        operationQueue.waitUntilAllOperationsAreFinished()

        return (ciphertext: encryptedMessage, recipients: recipients)
    }

    public func decrypt(encryptedMessageKey: String, with signer: Signer) -> String {
        return encryptedMessageKey
    }

    public func decrypt(encryptedPayload: Data, using key: String) throws -> PayloadContainer {
        return try decoder.decode(PayloadContainer.self, from: encryptedPayload)
    }

    // MARK: Sign / verify

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
