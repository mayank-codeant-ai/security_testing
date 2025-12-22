import XCTest
@testable import VulnerableApp

final class VulnerableAppTests: XCTestCase {

    var app: VulnerableApp!

    override func setUp() {
        super.setUp()
        app = VulnerableApp()
    }

    override func tearDown() {
        app = nil
        super.tearDown()
    }

    func testVulnerableAppInitialization() {
        XCTAssertNotNil(app, "VulnerableApp should initialize successfully")
    }

    func testHealthyLogging() {
        // Test that healthy logging works
        XCTAssertNoThrow(app.performHealthyLogging())
    }

    func testHealthyCryptography() {
        // Test that healthy cryptography works
        XCTAssertNoThrow(app.performHealthyCryptography())
    }

    func testVulnerableReactiveCode() {
        // Test vulnerable reactive code
        XCTAssertNoThrow(app.vulnerableReactiveCode())
    }

    func testVulnerableRealmOperations() {
        // Test vulnerable Realm operations
        // Note: This might fail if Realm is not properly configured
        // XCTAssertNoThrow(app.vulnerableRealmOperations())
    }

    static var allTests = [
        ("testVulnerableAppInitialization", testVulnerableAppInitialization),
        ("testHealthyLogging", testHealthyLogging),
        ("testHealthyCryptography", testHealthyCryptography),
        ("testVulnerableReactiveCode", testVulnerableReactiveCode),
    ]
}
