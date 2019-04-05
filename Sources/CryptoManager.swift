//
//  Copyright © 2018 Anbion. All rights reserved.
//

import Foundation
import LetsMeetModels

public enum CryptoManagerError: Error {
    case invalidMessageSignature
    case couldNotAccessSignedInUser
    case missingMembershipCertificate(member: Member)
    case decryptionError
    case serializationError(Error)
}

extension CryptoManagerError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .invalidMessageSignature: return "Invalid message signature"
        case .couldNotAccessSignedInUser: return "could not access signed in user"
        case .missingMembershipCertificate(let member): return "Missing membership certificate for \(member)"
        case .decryptionError: return "Decryption error"
        case .serializationError(let error): return error.localizedDescription
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

    public func generateKeys() -> (UserPublicKeys, PrivateKeys) {
        let publicKeys = UserPublicKeys(identityKey: "identityKey", ephemeralKey: "ephemeralKey", signedPreKey: "signedPreKey", preKeys: ["preKey1", "preKey2"])
        let privateKeys = "privateKeys"

        return (publicKeys, privateKeys)
    }

    public func generateGroupKey() -> String {
        return "groupKey"
    }

    // MARK: Hashing

    public func hash(_ group: Team) -> String {
        return String(group.groupId.hashValue &+ group.members.hashValue &+ group.meetups.hashValue &+ group.settings.hashValue)
    }

    // MARK: Membership certificates

    public func createSelfSignedMembershipCertificate(for groupId: GroupId, with signer: Signer, userId: UserId) -> Membership {
        return Membership(userId: userId, groupId: groupId)
    }

    public func createSelfSignedAdminCertificate(for groupId: GroupId, with signer: Signer, userId: UserId) -> Membership {
        return Membership(userId: userId, groupId: groupId, admin: true)
    }

    public func validate(certificate: Certificate, for groupId: GroupId) -> Bool {
        return true
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
            guard let serverSignedMembershipCertificate = member.serverSignedMembershipCertificate else {
                throw CryptoManagerError.missingMembershipCertificate(member: member)
            }

            operationQueue.addOperation {
                let encryptedMessageKey = self.encrypt(message: encryptionKey, for: member)
                let recipient = Recipient(userId: member.userId, identityKey: member.user.publicKeys.identityKey, serverSignedMembershipCertificate: serverSignedMembershipCertificate, encryptedMessageKey: encryptedMessageKey)

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
