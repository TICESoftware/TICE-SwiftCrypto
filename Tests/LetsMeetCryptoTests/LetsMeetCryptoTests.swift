import XCTest
import SwiftJWT
import CryptorECC
@testable import LetsMeetModels
@testable import LetsMeetCrypto

final class CryptoTests: XCTestCase {

    let cryptoManager = CryptoManager(encoder: JSONEncoder(), decoder: JSONDecoder())
    let groupId = UUID(uuidString: "E621E1F8-C36C-495A-93FC-0C247A3E6E5F")!
    let userId = UUID(uuidString: "F621E1F8-C36C-495A-93FC-0C247A3E6E5F")!

    lazy var user: TestUser = { TestUser(userId: userId) }()
    lazy var membership: Membership = { Membership(userId: self.userId, groupId: self.groupId, admin: true) }()

    func testUserSignedMembershipCertificate() {
        guard let certificate = try? cryptoManager.createUserSignedMembershipCertificate(userId: userId, groupId: groupId, admin: true, signer: user) else {
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
        let signingPublicKey = try! signingPrivateKey.extractPublicKey()

        guard let certificate = try? cryptoManager.createServerSignedMembershipCertificate(userId: userId, groupId: groupId, admin: true, signingKey: signingPrivateKey) else {
            XCTFail("Could not create certificate.")
            return
        }

        do {
            try cryptoManager.validateServerSignedMembershipCertificate(certificate: certificate, membership: membership, publicKey: signingPublicKey.pemString)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    func testValidateMembershipCertificateInvalidMembership() {
        let fakeId = UUID(uuidString: "A621E1F8-C36C-495A-93FC-0C247A3E6E5F")!

        guard let certificateInvalidGroupId = try? cryptoManager.createUserSignedMembershipCertificate(userId: userId, groupId: fakeId, admin: true, signer: user),
            let certificateInvalidUserId = try? cryptoManager.createUserSignedMembershipCertificate(userId: fakeId, groupId: groupId, admin: true, signer: user),
            let certificateInvalidAdminFlag = try? cryptoManager.createUserSignedMembershipCertificate(userId: userId, groupId: groupId, admin: false, signer: user) else {
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

        let privateKeyData = user.signingPrivateKey.pemString.data(using: .utf8)!
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

        let privateKeyData = user.signingPrivateKey.pemString.data(using: .utf8)!
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

    static var allTests = [
        ("testUserSignedMembershipCertificate", testUserSignedMembershipCertificate),
        ("testServerSignedMembershipCertificate", testServerSignedMembershipCertificate),
        ("testValidateMembershipCertificateInvalidMembership", testValidateMembershipCertificateInvalidMembership),
        ("testValidateExpiredCertificate", testValidateExpiredCertificate),
        ("testValidateCertificateIssuedInFuture", testValidateCertificateIssuedInFuture),
        ("testValidateCertificateInvalidSignature", testValidateCertificateInvalidSignature),
    ]
}

class TestUser: User, Signer {
    let signingPrivateKey: ECPrivateKey

    init(userId: UserId) {
        self.signingPrivateKey = try! ECPrivateKey.make(for: .secp521r1)

        let publicSigningKey = try! self.signingPrivateKey.extractPublicKey()
        super.init(userId: userId, publicKeys: UserPublicKeys(signingKey: publicSigningKey.pemString))
    }
}
