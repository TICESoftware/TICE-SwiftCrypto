import XCTest
import SwiftJWT
import CryptorECC
import Sodium
import DoubleRatchet
import X3DH
@testable import LetsMeetModels
@testable import LetsMeetCrypto

final class CryptoTests: XCTestCase {

    let cryptoManager = try! CryptoManager(handshake: nil, encoder: JSONEncoder(), decoder: JSONDecoder())
    let groupId = UUID(uuidString: "E621E1F8-C36C-495A-93FC-0C247A3E6E5F")!
    let userId = UUID(uuidString: "F621E1F8-C36C-495A-93FC-0C247A3E6E5F")!

    lazy var user: TestUser = { TestUser(userId: userId) }()
    lazy var membership: Membership = { Membership(userId: self.userId, groupId: self.groupId, admin: true) }()

    func testUserSignedMembershipCertificate() {
        guard let certificate = try? cryptoManager.createUserSignedMembershipCertificate(userId: userId, groupId: groupId, admin: true, signerUserId: userId, signer: user) else {
            XCTFail("Could not create certificate.")
            return
        }

        do {
            try cryptoManager.validateUserSignedMembershipCertificate(certificate: certificate, membership: membership, issuer: user)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    func testServerSignedMembershipCertificate() {
        let signingPrivateKey = try! ECPrivateKey.make(for: .secp521r1)
        let signingPrivateKeyBytes = signingPrivateKey.pemString.bytes

        let signingPublicKey = try! signingPrivateKey.extractPublicKey()
        let signingPublicKeyBytes = signingPublicKey.pemString.bytes

        guard let certificate = try? cryptoManager.createServerSignedMembershipCertificate(userId: userId, groupId: groupId, admin: true, signingKey: Data(signingPrivateKeyBytes)) else {
            XCTFail("Could not create certificate.")
            return
        }

        do {
            try cryptoManager.validateServerSignedMembershipCertificate(certificate: certificate, membership: membership, publicKey: Data(signingPublicKeyBytes))
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    func testValidateMembershipCertificateInvalidMembership() {
        let fakeId = UUID(uuidString: "A621E1F8-C36C-495A-93FC-0C247A3E6E5F")!

        guard let certificateInvalidGroupId = try? cryptoManager.createUserSignedMembershipCertificate(userId: userId, groupId: fakeId, admin: true, signerUserId: userId, signer: user),
            let certificateInvalidUserId = try? cryptoManager.createUserSignedMembershipCertificate(userId: fakeId, groupId: groupId, admin: true, signerUserId: fakeId, signer: user),
            let certificateInvalidAdminFlag = try? cryptoManager.createUserSignedMembershipCertificate(userId: userId, groupId: groupId, admin: false, signerUserId: userId, signer: user) else {
            XCTFail("Could not create certificate.")
            return
        }

        do {
            try cryptoManager.validateUserSignedMembershipCertificate(certificate: certificateInvalidGroupId, membership: membership, issuer: user)
            XCTFail("Validation should not have succeeded.")
        } catch {
            guard case CryptoManagerError.certificateValidationFailed(let certificateValidationError) = error,
                case CertificateValidationError.invalidMembership = certificateValidationError else {
                XCTFail("Invalid error type (expected invalid membership): \(error.localizedDescription)")
                return
            }
        }

        do {
            try cryptoManager.validateUserSignedMembershipCertificate(certificate: certificateInvalidUserId, membership: membership, issuer: user)
            XCTFail("Validation should not have succeeded.")
        } catch {
            guard case CryptoManagerError.certificateValidationFailed(let certificateValidationError) = error,
                case CertificateValidationError.invalidMembership = certificateValidationError else {
                    XCTFail("Invalid error type (expected invalid membership): \(error.localizedDescription)")
                    return
            }
        }

        do {
            try cryptoManager.validateUserSignedMembershipCertificate(certificate: certificateInvalidAdminFlag, membership: membership, issuer: user)
            XCTFail("Validation should not have succeeded.")
        } catch {
            guard case CryptoManagerError.certificateValidationFailed(let certificateValidationError) = error,
                case CertificateValidationError.invalidMembership = certificateValidationError else {
                    XCTFail("Invalid error type (expected invalid membership): \(error.localizedDescription)")
                    return
            }
        }
    }

    func testValidateExpiredCertificate() {
        let claims = MembershipClaims(iss: .user(userId), sub: userId, iat: Date().addingTimeInterval(-20), exp: Date().addingTimeInterval(-10), groupId: groupId, admin: true)
        var jwt = JWT(claims: claims)

        let privateKeyData = Data(user.privateSigningKey)
        let jwtSigner = JWTSigner.es512(privateKey: privateKeyData)

        guard let certificate = try? jwt.sign(using: jwtSigner) else {
            XCTFail("Could not create certificate.")
            return
        }

        do {
            try cryptoManager.validateUserSignedMembershipCertificate(certificate: certificate, membership: membership, issuer: user)
            XCTFail("Validation should not have succeeded.")
        } catch {
            guard case CryptoManagerError.certificateValidationFailed(let certificateValidationError) = error,
                case CertificateValidationError.expired(let validateClaimsResult) = certificateValidationError,
                validateClaimsResult == .expired else {
                    XCTFail("Invalid error type (expected invalid claims): \(error.localizedDescription)")
                    return
            }
        }
    }

    func testValidateCertificateIssuedInFuture() {
        let claims = MembershipClaims(iss: .user(userId), sub: userId, iat: Date().addingTimeInterval(60), exp: Date().addingTimeInterval(3600), groupId: groupId, admin: true)
        var jwt = JWT(claims: claims)

        let privateKeyData = Data(user.privateSigningKey)
        let jwtSigner = JWTSigner.es512(privateKey: privateKeyData)

        guard let certificate = try? jwt.sign(using: jwtSigner) else {
            XCTFail("Could not create certificate.")
            return
        }

        do {
            try cryptoManager.validateUserSignedMembershipCertificate(certificate: certificate, membership: membership, issuer: user)
            XCTFail("Validation should not have succeeded.")
        } catch {
            guard case CryptoManagerError.certificateValidationFailed(let certificateValidationError) = error,
                case CertificateValidationError.expired(let validateClaimsResult) = certificateValidationError,
                validateClaimsResult == .issuedAt else {
                    XCTFail("Invalid error type (expected invalid claims): \(error.localizedDescription)")
                    return
            }
        }
    }

    func testValidateCertificateInvalidSignature() {
        let claims = MembershipClaims(iss: .user(userId), sub: userId, iat: Date().addingTimeInterval(60), exp: Date().addingTimeInterval(3600), groupId: groupId, admin: true)
        var jwt = JWT(claims: claims)

        guard let privateKeyData = try? ECPrivateKey.make(for: .secp521r1).pemString.data(using: .utf8) else {
            XCTFail("Could not create private key")
            return
        }

        let jwtSigner = JWTSigner.es512(privateKey: privateKeyData)

        guard let certificate = try? jwt.sign(using: jwtSigner) else {
            XCTFail("Could not create certificate.")
            return
        }

        do {
            try cryptoManager.validateUserSignedMembershipCertificate(certificate: certificate, membership: membership, issuer: user)
            XCTFail("Validation should not have succeeded.")
        } catch {
            guard case CryptoManagerError.certificateValidationFailed(let certificateValidationError) = error,
                case CertificateValidationError.invalidSignature = certificateValidationError else {
                XCTFail("Invalid error type (expected invalid signature): \(error.localizedDescription)")
                return
            }
        }
    }

    func testInitializeConversation() {
        do {
            let publicKeyMaterial = try cryptoManager.generatePublicHandshakeInfo(signer: user)

            // Publish public key material...

            let bob = TestUser(userId: UserId())
            let bobsCryptoManager = try CryptoManager(handshake: nil, encoder: JSONEncoder(), decoder: JSONDecoder())

            // Bob gets prekey bundle and remote verification key from server
            let prekeyBundle = PrekeyBundle(identityKey: Bytes(publicKeyMaterial.identityKey), signedPrekey: Bytes(publicKeyMaterial.signedPrekey), prekeySignature: publicKeyMaterial.prekeySignature, oneTimePrekey: Bytes(publicKeyMaterial.oneTimePrekeys.last!))
            let invitation = try bobsCryptoManager.initConversation(with: userId, remotePrekeyBundle: prekeyBundle, remoteSigningKey: user.publicSigningKey)

            // Invitation is transmitted...

            try cryptoManager.processConversationInvitation(invitation, from: bob.userId)

            let firstMessagePayload = "Hello!".data(using: .utf8)!
            let firstMessage = try bobsCryptoManager.encrypt(firstMessagePayload, for: user)

            let plaintextData = try cryptoManager.decrypt(encryptedMessage: firstMessage, from: bob.userId, with: user)

            XCTAssertEqual(firstMessagePayload, plaintextData, "Invalid decrypted plaintext")
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    func testGroupMessageCrypto() {
        let bob = TestUser(userId: UserId())
        let bobServerSignedMembershipCertificate = "Certificate"
        let bobMembership = Membership(userId: bob.userId, groupId: GroupId(), admin: false, serverSignedMembershipCertificate: bobServerSignedMembershipCertificate)
        let bobMember = Member(user: bob, membership: bobMembership)

        let sharedSecret = Bytes(repeating: 0, count: 32)
        let info = "testGroupMessageCrypto"
        do {
            let bobDoubleRatchet = try DoubleRatchet(keyPair: nil, remotePublicKey: nil, sharedSecret: sharedSecret, maxSkip: 2, maxCache: 2, info: info)
            let doubleRatchetWithBob = try DoubleRatchet(keyPair: nil, remotePublicKey: bobDoubleRatchet.publicKey, sharedSecret: sharedSecret, maxSkip: 2, maxCache: 2, info: info)
            cryptoManager.doubleRatchets[bob.userId] = doubleRatchetWithBob

            let payloadData = "Hello!".data(using: .utf8)!
            let (ciphertext, recipients) = try cryptoManager.encrypt(payloadData, for: Set([bobMember]))

            XCTAssertEqual(recipients.count, 1, "Invalid recipients")
            XCTAssertEqual(recipients.first!.userId, bob.userId)

            let bobsCryptoManager = try CryptoManager(handshake: nil, encoder: JSONEncoder(), decoder: JSONDecoder())
            bobsCryptoManager.doubleRatchets[userId] = bobDoubleRatchet
            let plaintext = try bobsCryptoManager.decrypt(encryptedData: ciphertext, encryptedSecretKey: recipients.first!.encryptedMessageKey, from: userId, signer: bob)

            XCTAssertEqual(payloadData, plaintext, "Invalid decrypted plaintext")
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    static var allTests = [
        ("testUserSignedMembershipCertificate", testUserSignedMembershipCertificate),
        ("testServerSignedMembershipCertificate", testServerSignedMembershipCertificate),
        ("testValidateMembershipCertificateInvalidMembership", testValidateMembershipCertificateInvalidMembership),
        ("testValidateExpiredCertificate", testValidateExpiredCertificate),
        ("testValidateCertificateIssuedInFuture", testValidateCertificateIssuedInFuture),
        ("testValidateCertificateInvalidSignature", testValidateCertificateInvalidSignature),
        ("testInitializeConversation", testInitializeConversation),
    ]
}

class TestUser: User, Signer {
    let privateSigningKey: PrivateKey

    init(userId: UserId) {
        let signingKey = try! ECPrivateKey.make(for: .secp521r1)
        self.privateSigningKey = Data(signingKey.pemString.bytes)

        let publicSigningKey = try! signingKey.extractPublicKey().pemString.bytes
        super.init(userId: userId, publicSigningKey: Data(publicSigningKey))
    }
}
