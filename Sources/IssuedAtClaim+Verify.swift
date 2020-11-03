//
//  Copyright © 2020 Anbion. All rights reserved.
//

import Foundation
import JWTKit

extension IssuedAtClaim {
    public func verifyIssuedInPast(currentDate: Date = .init()) throws {
        switch self.value.compare(currentDate) {
        case .orderedAscending:
            break
        case .orderedDescending, .orderedSame:
            throw JWTError.claimVerificationFailure(name: "iat", reason: "issued in future")
        }
    }
}
