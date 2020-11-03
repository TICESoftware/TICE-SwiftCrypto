//
//  Copyright © 2020 Anbion. All rights reserved.
//

import Foundation
import JWTKit

func jwtRSTojwtAsn1(_ jwt: String) throws -> String {
    let jwtComponents = jwt.components(separatedBy: ".")
    guard jwtComponents.count == 3 else { throw CryptoManagerError.tokenGenerationFailed }

    let signatureData = data(base64urlEncoded: jwtComponents[2])!
    let asn1SignatureData = try rsSigToASN1(signatureData)
    let asn1Signature = base64urlEncodedString(data: asn1SignatureData)
    return "\(jwtComponents[0]).\(jwtComponents[1]).\(asn1Signature)"
}

func jwtAsn1TojwtRS(_ jwt: String) throws -> String {
    let jwtComponents = jwt.components(separatedBy: ".")
    guard jwtComponents.count == 3 else { throw CryptoManagerError.tokenGenerationFailed }
    let signatureData = data(base64urlEncoded: jwtComponents[2])!
    let rsSignatureData = try asn1ToRSSig(asn1: signatureData)
    let rsSignature = base64urlEncodedString(data: rsSignatureData)
    return "\(jwtComponents[0]).\(jwtComponents[1]).\(rsSignature)"
}

func base64urlEncodedString(data: Data) -> String {
    let result = data.base64EncodedString()
    return result.replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

func data(base64urlEncoded: String) -> Data? {
    let paddingLength = 4 - base64urlEncoded.count % 4
    let padding = (paddingLength < 4) ? String(repeating: "=", count: paddingLength) : ""
    let base64EncodedString = base64urlEncoded
        .replacingOccurrences(of: "-", with: "+")
        .replacingOccurrences(of: "_", with: "/")
        + padding
    return Data(base64Encoded: base64EncodedString)
}

func jwtPayload<Payload>(_ jwt: String, as payload: Payload.Type) throws -> Payload where Payload: JWTPayload {
    let jwtComponents = jwt.components(separatedBy: ".")
    guard jwtComponents.count == 3, let payloadData = data(base64urlEncoded: jwtComponents[1]) else {
        throw JWTError.malformedToken
    }
    
    let jsonDecoder = JSONDecoder()
    jsonDecoder.dateDecodingStrategy = .secondsSince1970
    
    return try jsonDecoder.decode(Payload.self, from: payloadData)
}
