import Foundation
import XCTest
@testable import AppAttestStorage

// Tests the native coordinator against an atomic, fault-injectable store. These
// are not evidence of Keychain accessibility on a locked or restored device.
private final class VaultTestStorage: SessionVaultStorage {
  var values: [String: Data] = [:]
  var policies: [String: VaultAccessibility] = [:]
  var readError: SessionVaultError?
  var writeError: SessionVaultError?
  var writes = 0

  func read(account: String) throws -> Data? {
    if let readError { throw readError }
    return values[account]
  }
  func write(account: String, data: Data, accessibility: VaultAccessibility) throws {
    if let writeError { throw writeError }
    values[account] = data
    policies[account] = accessibility
    writes += 1
  }
}

final class SessionVaultTests: XCTestCase {
  private var storage: VaultTestStorage!
  private var time: Double = 1000
  private let identity = "{\"keyAlias\":\"retained-key\"}"
  private let session = "{\"refreshToken\":\"secret-refresh\"}"

  override func setUp() {
    storage = VaultTestStorage()
    time = 1000
  }
  private func vault() -> SessionVault {
    SessionVault(storage: storage, now: { self.time })
  }
  private func acquire(_ vault: SessionVault, slot: String = "account-a",
                       policy: VaultAccessibility = .whenUnlocked) throws -> VaultSnapshot {
    try vault.acquire(namespace: "https://issuer.example/auth|native", slot: slot,
                      accessibility: policy, leaseMilliseconds: 30_000)
  }
  private func commit(_ vault: SessionVault, _ snapshot: VaultSnapshot,
                      slot: String = "account-a") throws -> Int64 {
    try vault.commit(namespace: "https://issuer.example/auth|native", slot: slot,
                     leaseId: snapshot.leaseId, generation: Double(snapshot.generation),
                     identityJSON: identity, sessionJSON: session)
  }
  private func assertError<T>(_ expected: SessionVaultError, file: StaticString = #filePath,
                              line: UInt = #line, _ operation: () throws -> T) {
    XCTAssertThrowsError(try operation(), file: file, line: line) { error in
      XCTAssertEqual(error as? SessionVaultError, expected, file: file, line: line)
    }
  }
  private func renew(_ vault: SessionVault, _ snapshot: VaultSnapshot) throws {
    try vault.renew(namespace: "https://issuer.example/auth|native", slot: "account-a",
                    leaseId: snapshot.leaseId, generation: Double(snapshot.generation),
                    leaseMilliseconds: 30_000)
  }
  private func abandon(_ vault: SessionVault, _ snapshot: VaultSnapshot) throws -> Int64 {
    try vault.abandon(namespace: "https://issuer.example/auth|native", slot: "account-a",
                      leaseId: snapshot.leaseId, generation: Double(snapshot.generation))
  }

  private func seedRecoverable(_ instance: SessionVault) throws {
    let initial = try acquire(instance)
    _ = try instance.commit(namespace: "https://issuer.example/auth|native", slot: "account-a",
      leaseId: initial.leaseId, generation: Double(initial.generation),
      identityJSON: identity, sessionJSON: session, recoverySessionJSON: session)
  }
  private func interaction(_ instance: SessionVault) throws -> VaultSnapshot {
    try instance.acquire(namespace: "https://issuer.example/auth|native", slot: "account-a",
      accessibility: .whenUnlocked, leaseMilliseconds: 30_000, preserveSession: true)
  }
  private func cancelInteraction(_ instance: SessionVault) throws -> (sessionJSON: String?, cancelled: Bool) {
    try instance.cancelInteraction(namespace: "https://issuer.example/auth|native", slot: "account-a", accessibility: .whenUnlocked)
  }

  func testInteractionFailureAndExpiredLeaseRecoverIndependentSession() throws {
    for expired in [false, true] {
      storage = VaultTestStorage()
      let instance = vault()
      try seedRecoverable(instance)
      let held = try interaction(instance)
      if expired { time += 31 } else { _ = try abandon(instance, held) }
      let recovered = try acquire(vault())
      XCTAssertEqual(recovered.sessionJSON, session)
      XCTAssertEqual(recovered.identityJSON, identity)
      XCTAssertTrue(recovered.recoveryRequired)
      assertError(.lostLease) { try self.commit(instance, held) }
    }
  }

  func testRefreshFailureAndExpiredLeaseNeverRecoverConsumedToken() throws {
    for expired in [false, true] {
      storage = VaultTestStorage()
      let instance = vault()
      try seedRecoverable(instance)
      let held = try acquire(instance)
      if expired { time += 31 } else { _ = try abandon(instance, held) }
      let recovered = try acquire(vault())
      XCTAssertNil(recovered.sessionJSON)
      XCTAssertEqual(recovered.identityJSON, identity)
      XCTAssertTrue(recovered.recoveryRequired)
    }
  }

  func testCancelCommittedInteractionReturnsOldStepAndRetainsIndependentSession() throws {
    let instance = vault()
    try seedRecoverable(instance)
    XCTAssertFalse(try cancelInteraction(instance).cancelled)
    let held = try interaction(instance)
    let pending = "{\"step\":\"pending\"}"
    _ = try instance.commit(namespace: "https://issuer.example/auth|native", slot: "account-a",
      leaseId: held.leaseId, generation: Double(held.generation),
      identityJSON: identity, sessionJSON: pending, recoverySessionJSON: session, hasInteraction: true)
    let result = try cancelInteraction(vault())
    XCTAssertTrue(result.cancelled)
    XCTAssertEqual(result.sessionJSON, pending)
    XCTAssertFalse(try cancelInteraction(instance).cancelled)
    XCTAssertEqual(try acquire(instance).sessionJSON, session)
  }

  func testInteractionCancellationFencesLateCommitButDoesNotPreemptRefresh() throws {
    let instance = vault()
    try seedRecoverable(instance)
    let held = try interaction(instance)
    XCTAssertTrue(try cancelInteraction(instance).cancelled)
    assertError(.lostLease) { try self.commit(instance, held) }
    let refresh = try acquire(instance)
    assertError(.busy) { try self.cancelInteraction(instance) }
    try renew(instance, refresh)
    // Expired refresh is cancelled destructively, never restored.
    time += 31
    XCTAssertTrue(try cancelInteraction(instance).cancelled)
    XCTAssertNil(try acquire(instance).sessionJSON)
  }

  func testCancelledCommitRollsBackOnlyInteractionAndCannotEraseNewerCommit() throws {
    for preserving in [false, true] {
      storage = VaultTestStorage()
      let instance = vault()
      try seedRecoverable(instance)
      let held = try preserving ? interaction(instance) : acquire(instance)
      let generation = try instance.commit(namespace: "https://issuer.example/auth|native", slot: "account-a",
        leaseId: held.leaseId, generation: Double(held.generation), identityJSON: identity,
        sessionJSON: "{\"refreshToken\":\"new-token\"}", recoverySessionJSON: "{\"refreshToken\":\"new-token\"}")
      XCTAssertTrue(try instance.discard(namespace: "https://issuer.example/auth|native", slot: "account-a", generation: Double(generation)))
      let recovered = try acquire(instance)
      XCTAssertEqual(recovered.sessionJSON, preserving ? session : nil)
      _ = try commit(instance, recovered)
      XCTAssertFalse(try instance.discard(namespace: "https://issuer.example/auth|native", slot: "account-a", generation: Double(generation)))
      XCTAssertEqual(try acquire(instance).sessionJSON, session)
    }
  }

  func testFailedCancellationWritePreservesPendingRecord() throws {
    let instance = vault()
    try seedRecoverable(instance)
    let held = try interaction(instance)
    storage.writeError = .locked
    assertError(.locked) { try self.cancelInteraction(instance) }
    storage.writeError = nil
    try renew(instance, held)
    _ = try abandon(instance, held)
    XCTAssertEqual(try acquire(instance).sessionJSON, session)
  }

  func testAtomicCommitSurvivesCoordinatorReplacementAndConsumesLease() throws {
    let first = vault()
    let initial = try acquire(first)
    XCTAssertNil(initial.identityJSON)
    XCTAssertNil(initial.sessionJSON)
    XCTAssertFalse(initial.recoveryRequired)
    XCTAssertEqual(initial.leaseId.count, 43)
    XCTAssertEqual(try commit(first, initial), 1)
    assertError(.lostLease) { try self.commit(first, initial) }
    let reopened = try acquire(vault())
    XCTAssertEqual(reopened.identityJSON, identity)
    XCTAssertEqual(reopened.sessionJSON, session)
    XCTAssertEqual(reopened.generation, 1)
    XCTAssertNotEqual(reopened.leaseId, initial.leaseId)
    XCTAssertFalse(reopened.recoveryRequired)
  }

  func testIndependentNativeCoordinatorsCannotAcquireSameSlotConcurrently() throws {
    let coordinators = (0..<16).map { _ in vault() }
    let resultLock = NSLock()
    var winners = 0
    var busy = 0
    var unexpected: [Error] = []
    DispatchQueue.concurrentPerform(iterations: coordinators.count) { index in
      do {
        _ = try acquire(coordinators[index])
        resultLock.lock(); winners += 1; resultLock.unlock()
      } catch {
        resultLock.lock()
        if error as? SessionVaultError == .busy { busy += 1 }
        else { unexpected.append(error) }
        resultLock.unlock()
      }
    }
    XCTAssertEqual(winners, 1)
    XCTAssertEqual(busy, 15)
    XCTAssertTrue(unexpected.isEmpty)
    XCTAssertEqual(storage.writes, 1)
  }

  func testNamespacesAndAccountsRemainIndependentWithoutPlaintextIdentifiers() throws {
    let first = try SessionVault.account(namespace: "issuer-a", slot: "account-a")
    XCTAssertEqual(first, try SessionVault.account(namespace: "issuer-a", slot: "account-a"))
    XCTAssertEqual(first.count, 64)
    XCTAssertFalse(first.contains("account-a"))
    XCTAssertNotEqual(first, try SessionVault.account(namespace: "issuer-b", slot: "account-a"))
    XCTAssertNotEqual(first, try SessionVault.account(namespace: "issuer-a", slot: "account-b"))
    XCTAssertNotEqual(try SessionVault.account(namespace: "a|b", slot: "c"),
                      try SessionVault.account(namespace: "a", slot: "b|c"))
    let instance = vault()
    let a = try acquire(instance)
    let b = try acquire(instance, slot: "account-b", policy: .afterFirstUnlock)
    XCTAssertEqual(try commit(instance, a), 1)
    XCTAssertEqual(try commit(instance, b, slot: "account-b"), 1)
    XCTAssertEqual(try acquire(instance, slot: "account-b", policy: .afterFirstUnlock).sessionJSON, session)
  }

  func testExpiredLeaseDropsUncertainSessionPreservesKeysAndFencesLateCompletion() throws {
    let first = vault()
    _ = try commit(first, acquire(first))
    let refresh = try acquire(first)
    time += 30
    let recovered = try acquire(vault())
    XCTAssertEqual(recovered.generation, refresh.generation + 1)
    XCTAssertEqual(recovered.identityJSON, identity)
    XCTAssertNil(recovered.sessionJSON)
    XCTAssertTrue(recovered.recoveryRequired)
    assertError(.lostLease) { try self.commit(first, refresh) }
    assertError(.lostLease) { try self.renew(first, refresh) }
    assertError(.lostLease) { try self.abandon(first, refresh) }
    _ = try commit(first, recovered)
    XCTAssertFalse(try acquire(first).recoveryRequired)
  }

  func testRenewalExtendsLeaseButCannotReviveAnExpiredLease() throws {
    let first = vault()
    let held = try acquire(first)
    time += 29
    try renew(first, held)
    time += 2
    assertError(.busy) { try self.acquire(self.vault()) }
    time += 28
    assertError(.lostLease) { try self.renew(first, held) }
    assertError(.lostLease) { try self.commit(first, held) }
    XCTAssertTrue(try acquire(vault()).recoveryRequired)
  }

  func testLogoutPreemptsInflightOperationWithoutClearingOtherAccountOrKeyReferences() throws {
    let first = vault()
    _ = try commit(first, acquire(first))
    _ = try commit(first, acquire(first, slot: "account-b"), slot: "account-b")
    let inFlight = try acquire(first)
    XCTAssertEqual(try vault().invalidate(namespace: "https://issuer.example/auth|native",
      slot: "account-a", accessibility: .whenUnlocked), 2)
    let fresh = try acquire(vault())
    assertError(.lostLease) { try self.commit(first, inFlight) }
    assertError(.lostLease) { try self.renew(first, inFlight) }
    assertError(.lostLease) { try self.abandon(first, inFlight) }
    XCTAssertNil(fresh.sessionJSON)
    XCTAssertEqual(fresh.identityJSON, identity)
    XCTAssertEqual(try acquire(first, slot: "account-b").sessionJSON, session)
  }

  func testAbandonmentNeverRestoresPreviousRefreshToken() throws {
    let instance = vault()
    _ = try commit(instance, acquire(instance))
    let refresh = try acquire(instance)
    _ = try abandon(instance, refresh)
    let next = try acquire(vault())
    XCTAssertNil(next.sessionJSON)
    XCTAssertEqual(next.identityJSON, identity)
    XCTAssertTrue(next.recoveryRequired)
  }
  func testClearSessionPreservesLeaseAndKeysAndFencesLateWrites() throws {
    let instance = vault()
    _ = try commit(instance, acquire(instance))
    let held = try acquire(instance)
    try instance.clearSession(namespace: "https://issuer.example/auth|native", slot: "account-a",
      leaseId: held.leaseId, generation: Double(held.generation))
    assertError(.busy) { try self.acquire(self.vault()) }
    let account = try SessionVault.account(namespace: "https://issuer.example/auth|native", slot: "account-a")
    let encoded = try XCTUnwrap(storage.values[account])
    XCTAssertFalse(String(data: encoded, encoding: .utf8)!.contains("secret-refresh"))
    _ = try abandon(instance, held)
    let recovered = try acquire(vault())
    XCTAssertEqual(recovered.identityJSON, identity)
    XCTAssertNil(recovered.sessionJSON)
    assertError(.lostLease) {
      try instance.clearSession(namespace: "https://issuer.example/auth|native", slot: "account-a",
        leaseId: held.leaseId, generation: Double(held.generation))
    }
  }
  func testReadOnlyReleaseRetainsSessionButCannotUndoLogout() throws {
    let instance = vault()
    _ = try commit(instance, acquire(instance))
    let held = try acquire(instance)
    try instance.release(namespace: "https://issuer.example/auth|native", slot: "account-a",
      leaseId: held.leaseId, generation: Double(held.generation))
    let next = try acquire(vault())
    XCTAssertEqual(next.sessionJSON, session)
    XCTAssertEqual(next.identityJSON, identity)
    XCTAssertEqual(next.generation, held.generation + 1)
    _ = try instance.invalidate(namespace: "https://issuer.example/auth|native", slot: "account-a", accessibility: .whenUnlocked)
    assertError(.lostLease) {
      try instance.release(namespace: "https://issuer.example/auth|native", slot: "account-a",
        leaseId: next.leaseId, generation: Double(next.generation))
    }
    XCTAssertNil(try acquire(vault()).sessionJSON)
  }

  func testRegistrationJournalSurvivesAbandonmentAndProcessRecovery() throws {
    let progress = "{\"keyAlias\":\"retained-key\",\"registration\":\"attesting\"}"
    for expired in [false, true] {
      storage = VaultTestStorage()
      let instance = vault()
      _ = try commit(instance, acquire(instance))
      let held = try acquire(instance)
      try instance.saveIdentity(namespace: "https://issuer.example/auth|native", slot: "account-a",
        leaseId: held.leaseId, generation: Double(held.generation), identityJSON: progress)
      assertError(.busy) { try self.acquire(self.vault()) }
      if expired { time += 30 } else { _ = try abandon(instance, held) }
      let recovered = try acquire(vault())
      XCTAssertEqual(recovered.identityJSON, progress)
      XCTAssertNil(recovered.sessionJSON)
      XCTAssertTrue(recovered.recoveryRequired)
      assertError(.lostLease) {
        try instance.saveIdentity(namespace: "https://issuer.example/auth|native", slot: "account-a",
          leaseId: held.leaseId, generation: Double(held.generation), identityJSON: self.identity)
      }
    }
  }

  func testRegistrationJournalFailureIsAtomicAndCancellationFencesLateWrites() throws {
    let instance = vault()
    _ = try commit(instance, acquire(instance))
    let held = try acquire(instance)
    let before = storage.values
    storage.writeError = .storage
    assertError(.storage) {
      try instance.saveIdentity(namespace: "https://issuer.example/auth|native", slot: "account-a",
        leaseId: held.leaseId, generation: Double(held.generation), identityJSON: "{}")
    }
    XCTAssertEqual(storage.values, before)
    storage.writeError = nil
    _ = try instance.invalidate(namespace: "https://issuer.example/auth|native", slot: "account-a",
      accessibility: .whenUnlocked)
    assertError(.lostLease) {
      try instance.saveIdentity(namespace: "https://issuer.example/auth|native", slot: "account-a",
        leaseId: held.leaseId, generation: Double(held.generation), identityJSON: "{}")
    }
    XCTAssertEqual(try acquire(vault()).identityJSON, identity)
  }

  func testCancelledCommitCleanupFencesItsGenerationButCannotEraseLaterLogin() throws {
    let instance = vault()
    let cancelledGeneration = try commit(instance, acquire(instance))
    let readingCancelledResult = try acquire(instance)
    XCTAssertTrue(try instance.discard(namespace: "https://issuer.example/auth|native",
      slot: "account-a", generation: Double(cancelledGeneration)))
    assertError(.lostLease) { try self.commit(instance, readingCancelledResult) }
    let next = try acquire(instance)
    XCTAssertNil(next.sessionJSON)
    XCTAssertEqual(next.identityJSON, identity)
    _ = try commit(instance, next)
    XCTAssertFalse(try instance.discard(namespace: "https://issuer.example/auth|native",
      slot: "account-a", generation: Double(cancelledGeneration)))
    XCTAssertEqual(try acquire(instance).sessionJSON, session)
  }

  func testFailedCommitDoesNotReportSuccessOrLoseDurableLease() throws {
    let instance = vault()
    _ = try commit(instance, acquire(instance))
    let refresh = try acquire(instance)
    let prior = storage.values
    storage.writeError = .storage
    assertError(.storage) { try self.commit(instance, refresh) }
    XCTAssertEqual(storage.values, prior)
    storage.writeError = nil
    assertError(.busy) { try self.acquire(self.vault()) }
    time += 30
    let recovery = try acquire(vault())
    XCTAssertNil(recovery.sessionJSON)
    XCTAssertEqual(recovery.identityJSON, identity)
  }

  func testInaccessibleStorageIsNeverTreatedAsMissing() throws {
    for failure in [SessionVaultError.locked, .unavailable, .storage] {
      storage.readError = failure
      assertError(failure) { try self.acquire(self.vault()) }
      assertError(failure) {
        try self.vault().invalidate(namespace: "issuer", slot: "slot", accessibility: .whenUnlocked)
      }
    }
    XCTAssertEqual(storage.writes, 0)
    XCTAssertTrue(storage.values.isEmpty)
    storage.readError = nil
    storage.writeError = .locked
    assertError(.locked) { try self.acquire(self.vault()) }
    XCTAssertTrue(storage.values.isEmpty)
  }

  func testCorruptRecordAndPolicyChangeDoNotOverwriteStoredData() throws {
    let instance = vault()
    _ = try commit(instance, acquire(instance))
    let prior = storage.values
    assertError(.policyMismatch) { try self.acquire(instance, policy: .afterFirstUnlock) }
    assertError(.policyMismatch) {
      try instance.invalidate(namespace: "https://issuer.example/auth|native", slot: "account-a",
                              accessibility: .afterFirstUnlock)
    }
    XCTAssertEqual(storage.values, prior)
    let account = try SessionVault.account(namespace: "https://issuer.example/auth|native", slot: "account-a")
    storage.values[account] = Data("not-json".utf8)
    assertError(.corrupt) { try self.acquire(instance) }
    XCTAssertEqual(storage.values[account], Data("not-json".utf8))
  }

  func testInvalidInputsAndGenerationOverflowFailClosed() throws {
    let instance = vault()
    let held = try acquire(instance)
    for value in [Double.nan, .infinity, -1, 0.5, Double(SessionVault.maximumGeneration) + 1] {
      assertError(.invalidInput) {
        try instance.commit(namespace: "https://issuer.example/auth|native", slot: "account-a",
          leaseId: held.leaseId, generation: value, identityJSON: nil, sessionJSON: nil)
      }
    }
    for value in ["[]", "null", "{", "{\"value\":\"\(String(repeating: "x", count: 8192))\"}"] {
      assertError(.invalidInput) {
        try instance.commit(namespace: "https://issuer.example/auth|native", slot: "account-a",
          leaseId: held.leaseId, generation: 0, identityJSON: value, sessionJSON: nil)
      }
    }
    for duration in [Double.nan, .infinity, 4999, 120001, 5000.5] {
      assertError(.invalidInput) {
        try instance.acquire(namespace: "issuer", slot: "slot", accessibility: .whenUnlocked,
                              leaseMilliseconds: duration)
      }
    }
    assertError(.invalidInput) { try SessionVault.account(namespace: "", slot: "slot") }
    let account = try SessionVault.account(namespace: "https://issuer.example/auth|native", slot: "account-a")
    var record = try JSONDecoder().decode(VaultRecord.self, from: XCTUnwrap(storage.values[account]))
    record.generation = SessionVault.maximumGeneration
    storage.values[account] = try JSONEncoder().encode(record)
    assertError(.corrupt) {
      try instance.commit(namespace: "https://issuer.example/auth|native", slot: "account-a",
        leaseId: held.leaseId, generation: Double(record.generation), identityJSON: nil, sessionJSON: nil)
    }
  }
}
