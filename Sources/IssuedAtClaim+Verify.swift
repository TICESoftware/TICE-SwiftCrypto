//
//  Copyright © 2020 Anbion. All rights reserved.
//

import Foundation
import JWTKit

extension IssuedAtClaim {
    public func verifyIssuedInPast(currentDate: Date = .init()) throws {
        guard self.value < currentDate else {
            throw JWTError.claimVerificationFailure(name: "iat", reason: "issued in future")
        }
    }
}
