import XCTest
@testable import AppAttestStorage

private actor GenerationGate {
  private var waiters: [CheckedContinuation<String, Never>] = []
  private var finished = false
  private(set) var calls = 0
  func generate() async -> String {
    calls += 1
    if finished { return "retained-key" }
    return await withCheckedContinuation { waiters.append($0) }
  }
  func finish() { finished = true; for waiter in waiters { waiter.resume(returning: "retained-key") }; waiters = [] }
}

final class AppAttestKeyCoordinatorTests: XCTestCase {
  func testRetirementRemovesOnlyTheExpectedReferenceAndIsIdempotent() async throws {
    let suite = "AppAttestCoordinatorTests.\(UUID().uuidString)"
    let defaults = UserDefaults(suiteName: suite)!
    defer { defaults.removePersistentDomain(forName: suite) }
    let coordinator = AppAttestKeyCoordinator(defaults: defaults)
    _ = try await coordinator.prepare(prefix: "prefix", scope: "slot") { "retained-key" }
    _ = try await coordinator.prepare(prefix: "prefix", scope: "other") { "other-key" }
    do {
      try await coordinator.remove(prefix: "prefix", scope: "slot", expectedKeyId: "wrong-key")
      XCTFail("must preserve a different key")
    } catch { XCTAssertEqual(error as? FirstPartyKeyError, .mismatch) }
    let store = AppAttestKeyStore(storagePrefix: "prefix", defaults: defaults)
    XCTAssertEqual(store.keyId(for: "slot"), "retained-key")
    try await coordinator.remove(prefix: "prefix", scope: "slot", expectedKeyId: "retained-key")
    try await coordinator.remove(prefix: "prefix", scope: "slot", expectedKeyId: "retained-key")
    XCTAssertNil(store.keyId(for: "slot"))
    XCTAssertEqual(store.keyId(for: "other"), "other-key")
  }
  func testConcurrentCallersAndCancelledBridgeJoinOneNativeGeneration() async throws {
    let suite = "AppAttestCoordinatorTests.\(UUID().uuidString)"
    let defaults = UserDefaults(suiteName: suite)!
    defer { defaults.removePersistentDomain(forName: suite) }
    let coordinator = AppAttestKeyCoordinator(defaults: defaults)
    let gate = GenerationGate()
    let started = expectation(description: "generation started")
    let first = Task {
      try await coordinator.prepare(prefix: "prefix", scope: "slot") {
        started.fulfill()
        return await gate.generate()
      }
    }
    await fulfillment(of: [started], timeout: 2)
    first.cancel()
    let joined = (0..<16).map { _ in Task {
      try await coordinator.prepare(prefix: "prefix", scope: "slot") { await gate.generate() }
    } }
    await gate.finish()
    let initial = try await first.value
    XCTAssertEqual(initial.keyId, "retained-key")
    for task in joined { let key = try await task.value; XCTAssertEqual(key.keyId, "retained-key") }
    let calls = await gate.calls
    XCTAssertEqual(calls, 1)
    let reopened = try await AppAttestKeyCoordinator(defaults: defaults).prepare(prefix: "prefix", scope: "slot") {
      XCTFail("must retain the stored key")
      return "replacement"
    }
    XCTAssertEqual(reopened.keyId, "retained-key")
    XCTAssertFalse(reopened.created)
  }

  func testFailedGenerationCanRetryAndResetDoesNotDeleteAnotherScope() async throws {
    enum Failure: Error { case unavailable }
    let suite = "AppAttestCoordinatorTests.\(UUID().uuidString)"
    let defaults = UserDefaults(suiteName: suite)!
    defer { defaults.removePersistentDomain(forName: suite) }
    let coordinator = AppAttestKeyCoordinator(defaults: defaults)
    do {
      _ = try await coordinator.prepare(prefix: "prefix", scope: "slot") { throw Failure.unavailable }
      XCTFail("must propagate generation failure")
    } catch { XCTAssertTrue(error is Failure) }
    let key = try await coordinator.prepare(prefix: "prefix", scope: "slot") { "first-key" }
    XCTAssertTrue(key.created)
    _ = try await coordinator.prepare(prefix: "prefix", scope: "other") { "other-key" }
    await coordinator.reset(prefix: "prefix", scope: "slot")
    let store = AppAttestKeyStore(storagePrefix: "prefix", defaults: defaults)
    XCTAssertNil(store.keyId(for: "slot"))
    XCTAssertEqual(store.keyId(for: "other"), "other-key")
    let replacement = try await coordinator.prepare(prefix: "prefix", scope: "slot") { "replacement" }
    XCTAssertEqual(replacement.keyId, "replacement")
    XCTAssertTrue(replacement.created)
  }
}
