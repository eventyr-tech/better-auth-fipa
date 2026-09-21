import XCTest
@testable import AppAttestStorage

final class SimulatorEligibilityTests: XCTestCase {
  func testNonSimulatorRejectsSoftwareKeyOperations() throws {
#if !targetEnvironment(simulator)
    XCTAssertThrowsError(try FirstPartySimulatorKey.requireSimulator())
    XCTAssertThrowsError(try FirstPartySimulatorKey.keyId(prefix: "test", scope: "scope"))
    XCTAssertThrowsError(try FirstPartySimulatorKey.prepare("test"))
    XCTAssertThrowsError(try FirstPartySimulatorKey.existing("test"))
    XCTAssertThrowsError(try FirstPartySimulatorKey.remove("test"))
    XCTAssertThrowsError(try FirstPartySimulatorKey.evidence(keyId: "test", clientData: "test", operation: "assert"))
#endif
  }
}
