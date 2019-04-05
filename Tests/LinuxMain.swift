import XCTest

import CryptoTests

var tests = [XCTestCaseEntry]()
tests += CryptoTests.allTests()
XCTMain(tests)
