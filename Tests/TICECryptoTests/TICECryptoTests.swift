import XCTest
import SwiftJWT
import CryptorECC
import Sodium
import DoubleRatchet
import X3DH
@testable import TICEModels
@testable import TICECrypto

final class CryptoTests: XCTestCase {

    let cryptoManager = try! CryptoManager(cryptoStore: nil, encoder: JSONEncoder(), decoder: JSONDecoder())
    let groupId = UUID(uuidString: "E621E1F8-C36C-495A-93FC-0C247A3E6E5F")!
    let userId = UUID(uuidString: "F621E1F8-C36C-495A-93FC-0C247A3E6E5F")!

    lazy var user: TestUser = { TestUser(userId: userId) }()
    lazy var membership: Membership = { Membership(userId: self.userId, groupId: self.groupId, admin: true) }()

    func testUserSignedMembershipCertificate() throws {
        let certificate = try cryptoManager.createUserSignedMembershipCertificate(userId: userId, groupId: groupId, admin: true, signerUserId: userId, signer: user)
        try cryptoManager.validateUserSignedMembershipCertificate(certificate: certificate, membership: membership, issuer: user)
    }

    func testServerSignedMembershipCertificate() throws {
        let signingPrivateKey = try ECPrivateKey.make(for: .secp521r1)
        let signingPrivateKeyBytes = signingPrivateKey.pemString.bytes

        let signingPublicKey = try signingPrivateKey.extractPublicKey()
        let signingPublicKeyBytes = signingPublicKey.pemString.bytes

        let certificate = try cryptoManager.createServerSignedMembershipCertificate(userId: userId, groupId: groupId, admin: true, signingKey: Data(signingPrivateKeyBytes))

        try cryptoManager.validateServerSignedMembershipCertificate(certificate: certificate, membership: membership, publicKey: Data(signingPublicKeyBytes))
    }

    func testValidateMembershipCertificateInvalidMembership() throws {
        let fakeId = UUID(uuidString: "A621E1F8-C36C-495A-93FC-0C247A3E6E5F")!

        let certificateInvalidGroupId = try cryptoManager.createUserSignedMembershipCertificate(userId: userId, groupId: fakeId, admin: true, signerUserId: userId, signer: user)
        let certificateInvalidUserId = try cryptoManager.createUserSignedMembershipCertificate(userId: fakeId, groupId: groupId, admin: true, signerUserId: fakeId, signer: user)
        let certificateInvalidAdminFlag = try cryptoManager.createUserSignedMembershipCertificate(userId: userId, groupId: groupId, admin: false, signerUserId: userId, signer: user)

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

    func testValidateExpiredCertificate() throws {
        let claims = MembershipClaims(jti: JWTId(), iss: .user(userId), sub: userId, iat: Date().addingTimeInterval(-20), exp: Date().addingTimeInterval(-10), groupId: groupId, admin: true)
        var jwt = JWT(claims: claims)

        let privateKeyData = Data(user.privateSigningKey)
        let jwtSigner = JWTSigner.es512(privateKey: privateKeyData)
        let certificate = try jwt.sign(using: jwtSigner)

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

    func testValidateCertificateIssuedInFuture() throws {
        let claims = MembershipClaims(jti: JWTId(), iss: .user(userId), sub: userId, iat: Date().addingTimeInterval(60), exp: Date().addingTimeInterval(3600), groupId: groupId, admin: true)
        var jwt = JWT(claims: claims)

        let privateKeyData = Data(user.privateSigningKey)
        let jwtSigner = JWTSigner.es512(privateKey: privateKeyData)
        let certificate = try jwt.sign(using: jwtSigner)

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

    func testValidateCertificateInvalidSignature() throws {
        let claims = MembershipClaims(jti: JWTId(), iss: .user(userId), sub: userId, iat: Date().addingTimeInterval(60), exp: Date().addingTimeInterval(3600), groupId: groupId, admin: true)
        var jwt = JWT(claims: claims)

        guard let privateKeyData = try ECPrivateKey.make(for: .secp521r1).pemString.data(using: .utf8) else {
            XCTFail("Could not create private key")
            return
        }

        let jwtSigner = JWTSigner.es512(privateKey: privateKeyData)
        let certificate = try jwt.sign(using: jwtSigner)

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

    func testInitializeConversation() throws {
        let publicKeyMaterial = try cryptoManager.generatePublicHandshakeInfo(signer: user)

        // Publish public key material...

        let bob = TestUser(userId: UserId())
        let bobsCryptoManager = try CryptoManager(cryptoStore: nil, encoder: JSONEncoder(), decoder: JSONDecoder())

        // Bob gets prekey bundle and remote verification key from server
        let prekeyBundle = PrekeyBundle(identityKey: Bytes(publicKeyMaterial.identityKey), signedPrekey: Bytes(publicKeyMaterial.signedPrekey), prekeySignature: publicKeyMaterial.prekeySignature, oneTimePrekey: Bytes(publicKeyMaterial.oneTimePrekeys.last!))
        let invitation = try bobsCryptoManager.initConversation(with: userId, remoteIdentityKey: Data(prekeyBundle.identityKey), remoteSignedPrekey: Data(prekeyBundle.signedPrekey), remotePrekeySignature: prekeyBundle.prekeySignature, remoteOneTimePrekey: prekeyBundle.oneTimePrekey.map { Data($0) }, remoteSigningKey: user.publicSigningKey)

        // Invitation is transmitted...

        try cryptoManager.processConversationInvitation(invitation, from: bob.userId)

        let firstMessagePayload = "Hello!".data(using: .utf8)!
        let firstMessage = try bobsCryptoManager.encrypt(firstMessagePayload, for: userId)

        let plaintextData = try cryptoManager.decrypt(encryptedMessage: firstMessage, from: bob.userId)

        XCTAssertEqual(firstMessagePayload, plaintextData, "Invalid decrypted plaintext")
    }

    func testMaxSkipExceeded() throws {
        let bob = TestUser(userId: UserId())
        let bobsCryptoManager = try CryptoManager(cryptoStore: nil, encoder: JSONEncoder(), decoder: JSONDecoder())

        let handshakeInfo = try cryptoManager.generatePublicHandshakeInfo(signer: user)
        let invitation = try bobsCryptoManager.initConversation(with: user.userId, remoteIdentityKey: handshakeInfo.identityKey, remoteSignedPrekey: handshakeInfo.signedPrekey, remotePrekeySignature: handshakeInfo.prekeySignature, remoteOneTimePrekey: handshakeInfo.oneTimePrekeys.last!, remoteSigningKey: user.publicSigningKey)

        try cryptoManager.processConversationInvitation(invitation, from: bob.userId)

        // Produce maxSkip messages that will get lost
        for _ in 0...100 {
            _ = try bobsCryptoManager.encrypt(Data(), for: userId)
        }

        // Produce another message that is going to be delivered successfully
        var encryptedMessage = try bobsCryptoManager.encrypt(Data(), for: userId)

        let exp1 = expectation(description: "maxSkipExceeded error raised")
        do {
            _ = try cryptoManager.decrypt(encryptedMessage: encryptedMessage, from: bob.userId)
        } catch CryptoManagerError.maxSkipExceeded {
            exp1.fulfill()
        }

        wait(for: [exp1], timeout: 1.0)

        //
        // BEGIN: Show that ratchet step isn't going to resolve the problem
        //
        let exp2 = expectation(description: "maxSkipExceeded error raised second time")
        encryptedMessage = try cryptoManager.encrypt(Data(), for: bob.userId)
        _ = try bobsCryptoManager.decrypt(encryptedMessage: encryptedMessage, from: user.userId)

        encryptedMessage = try bobsCryptoManager.encrypt(Data(), for: userId)
        do {
            _ = try cryptoManager.decrypt(encryptedMessage: encryptedMessage, from: bob.userId)
        } catch CryptoManagerError.maxSkipExceeded {
            exp2.fulfill()
        }
        wait(for: [exp2], timeout: 1.0)
        //
        // END
        //

        // Recover by reinitializing conversation
        let newHandshakeInfo = try bobsCryptoManager.generatePublicHandshakeInfo(signer: bob)
        let newInvitation = try cryptoManager.initConversation(with: bob.userId, remoteIdentityKey: newHandshakeInfo.identityKey, remoteSignedPrekey: newHandshakeInfo.signedPrekey, remotePrekeySignature: newHandshakeInfo.prekeySignature, remoteOneTimePrekey: newHandshakeInfo.oneTimePrekeys.last!, remoteSigningKey: bob.publicSigningKey)

        try bobsCryptoManager.processConversationInvitation(newInvitation, from: user.userId)
        encryptedMessage = try cryptoManager.encrypt(Data(), for: bob.userId)
        _ = try bobsCryptoManager.decrypt(encryptedMessage: encryptedMessage, from: user.userId)

        encryptedMessage = try bobsCryptoManager.encrypt(Data(), for: user.userId)
        _ = try cryptoManager.decrypt(encryptedMessage: encryptedMessage, from: bob.userId)
    }

    static var allTests = [
        ("testUserSignedMembershipCertificate", testUserSignedMembershipCertificate),
        ("testServerSignedMembershipCertificate", testServerSignedMembershipCertificate),
        ("testValidateMembershipCertificateInvalidMembership", testValidateMembershipCertificateInvalidMembership),
        ("testValidateExpiredCertificate", testValidateExpiredCertificate),
        ("testValidateCertificateIssuedInFuture", testValidateCertificateIssuedInFuture),
        ("testValidateCertificateInvalidSignature", testValidateCertificateInvalidSignature),
        ("testInitializeConversation", testInitializeConversation),
        ("testMaxSkipExceeded", testMaxSkipExceeded),
    ]
}

class TestUser: User, Signer {
    let privateSigningKey: PrivateKey

    init(userId: UserId) {
        let signingKey = try! ECPrivateKey.make(for: .secp521r1)
        self.privateSigningKey = Data(signingKey.pemString.bytes)

        let publicSigningKey = try! signingKey.extractPublicKey().pemString.bytes
        super.init(userId: userId, publicSigningKey: Data(publicSigningKey), publicName: nil)
    }
}
