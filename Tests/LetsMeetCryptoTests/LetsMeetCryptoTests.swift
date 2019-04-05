import XCTest
@testable import Crypto

final class CryptoTests: XCTestCase {
    func testExample() {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct
        // results.
        XCTAssertEqual(Crypto().text, "Hello, World!")
    }

    static var allTests = [
        ("testExample", testExample),
    ]
}
