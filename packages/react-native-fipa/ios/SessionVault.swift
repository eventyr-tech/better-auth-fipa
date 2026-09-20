import CryptoKit
import Foundation

/// No application extension/shared-access-group support. The native lock covers
/// every bridge/runtime in this app process, while the durable lease fences late
/// responses and survives a process restart.
enum VaultAccessibility: String, Codable {
  case whenUnlocked = "when-unlocked"
  case afterFirstUnlock = "after-first-unlock"
}

enum SessionVaultError: String, Error {
  case invalidInput = "vault_invalid_input"
  case busy = "vault_busy"
  case lostLease = "vault_lost_lease"
  case corrupt = "vault_corrupt"
  case locked = "vault_locked"
  case unavailable = "vault_unavailable"
  case storage = "vault_storage_failed"
  case policyMismatch = "vault_policy_mismatch"
}

protocol SessionVaultStorage {
  func read(account: String) throws -> Data?
  func write(account: String, data: Data, accessibility: VaultAccessibility) throws
}

struct VaultLease: Codable {
  let id: String
  var expiresAt: Double
  var preserveSession: Bool?
}

struct VaultRecord: Codable {
  let version: Int
  let account: String
  let accessibility: VaultAccessibility
  var generation: Int64
  var identityJSON: String?
  var sessionJSON: String?
  var recoverySessionJSON: String?
  var rollbackSessionJSON: String?
  var hasInteraction: Bool?
  var recoveryRequired: Bool
  var lease: VaultLease?
}

struct VaultSnapshot {
  let leaseId: String
  let generation: Int64
  let identityJSON: String?
  let sessionJSON: String?
  let recoveryRequired: Bool
}

final class SessionVault {
  // A static lock, not a per-module or per-JS-runtime lock. Keychain calls are
  // synchronous and bounded to local storage work. No network is performed here.
  private static let mutationLock = NSLock()
  static let maximumGeneration: Int64 = 9_007_199_254_740_991
  private let storage: SessionVaultStorage
  private let now: () -> Double
  private let random: () -> String

  init(storage: SessionVaultStorage,
       now: @escaping () -> Double = { Date().timeIntervalSince1970 },
       random: @escaping () -> String = {
         SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
           .base64EncodedString().replacingOccurrences(of: "+", with: "-")
           .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
       }) {
    self.storage = storage
    self.now = now
    self.random = random
  }

  func acquire(namespace: String, slot: String, accessibility: VaultAccessibility,
               leaseMilliseconds: Double, preserveSession: Bool = false) throws -> VaultSnapshot {
    let account = try Self.account(namespace: namespace, slot: slot)
    let duration = try Self.duration(leaseMilliseconds)
    return try locked {
      var record = try read(account) ?? VaultRecord(version: 1, account: account,
        accessibility: accessibility, generation: 0, identityJSON: nil,
        sessionJSON: nil, recoveryRequired: false, lease: nil)
      guard record.accessibility == accessibility else { throw SessionVaultError.policyMismatch }
      if let lease = record.lease {
        guard lease.expiresAt <= now() else { throw SessionVaultError.busy }
        // Only an interaction lease can recover independently committed access.
        // A refresh/session mutation never restores a potentially consumed token.
        try invalidate(&record, recover: lease.preserveSession == true)
      }
      let id = random()
      record.lease = VaultLease(id: id, expiresAt: now() + duration, preserveSession: preserveSession)
      try write(record)
      return VaultSnapshot(leaseId: id, generation: record.generation,
        identityJSON: record.identityJSON, sessionJSON: record.sessionJSON,
        recoveryRequired: record.recoveryRequired)
    }
  }

  /// A successful atomic commit consumes the lease. The caller must not expose
  /// newly issued access credentials before this write completes.
  func commit(namespace: String, slot: String, leaseId: String, generation: Double,
              identityJSON: String?, sessionJSON: String?, recoverySessionJSON: String? = nil,
              hasInteraction: Bool = false) throws -> Int64 {
    try Self.validateJSON(identityJSON, limit: 8192)
    try Self.validateJSON(sessionJSON, limit: 65536)
    try Self.validateJSON(recoverySessionJSON, limit: 65536)
    let account = try Self.account(namespace: namespace, slot: slot)
    let expected = try Self.generation(generation)
    return try locked {
      var record = try owned(account, leaseId: leaseId, generation: expected)
      record.generation = try successor(record.generation)
      record.rollbackSessionJSON = record.lease?.preserveSession == true ? record.recoverySessionJSON : nil
      record.identityJSON = identityJSON
      record.sessionJSON = sessionJSON
      record.recoverySessionJSON = recoverySessionJSON
      record.hasInteraction = hasInteraction
      record.recoveryRequired = false
      record.lease = nil
      try write(record)
      return record.generation
    }
  }

  func renew(namespace: String, slot: String, leaseId: String, generation: Double,
             leaseMilliseconds: Double) throws {
    let account = try Self.account(namespace: namespace, slot: slot)
    let expected = try Self.generation(generation)
    let duration = try Self.duration(leaseMilliseconds)
    try locked {
      var record = try owned(account, leaseId: leaseId, generation: expected)
      record.lease?.expiresAt = now() + duration
      try write(record)
    }
  }
  /// Release a read-only operation without discarding a known committed session.
  /// A preempted or expired lease still fails and cannot restore any old state.
  func release(namespace: String, slot: String, leaseId: String, generation: Double) throws {
    let account = try Self.account(namespace: namespace, slot: slot)
    let expected = try Self.generation(generation)
    try locked {
      var record = try owned(account, leaseId: leaseId, generation: expected)
      record.generation = try successor(record.generation)
      record.lease = nil
      try write(record)
    }
  }

  /// Persist irreversible key-registration progress without releasing the slot.
  /// Session material and generation stay unchanged while this lease owns it.
  func saveIdentity(namespace: String, slot: String, leaseId: String, generation: Double,
                    identityJSON: String) throws {
    try Self.validateJSON(identityJSON, limit: 8192)
    let account = try Self.account(namespace: namespace, slot: slot)
    let expected = try Self.generation(generation)
    try locked {
      var record = try owned(account, leaseId: leaseId, generation: expected)
      record.identityJSON = identityJSON
      try write(record)
    }
  }

  /// Clear capabilities before a best-effort remote termination, keeping this
  /// operation's lease and identity so another runtime cannot start a new login.
  func clearSession(namespace: String, slot: String, leaseId: String, generation: Double) throws {
    let account = try Self.account(namespace: namespace, slot: slot)
    let expected = try Self.generation(generation)
    try locked {
      var record = try owned(account, leaseId: leaseId, generation: expected)
      record.sessionJSON = nil
      record.recoverySessionJSON = nil
      record.rollbackSessionJSON = nil
      record.hasInteraction = false
      try write(record)
    }
  }

  /// Interaction failures may recover independent, previously committed access.
  /// Session mutations never restore a potentially consumed refresh token.
  func abandon(namespace: String, slot: String, leaseId: String, generation: Double) throws -> Int64 {
    let account = try Self.account(namespace: namespace, slot: slot)
    let expected = try Self.generation(generation)
    return try locked {
      var record = try owned(account, leaseId: leaseId, generation: expected)
      try invalidate(&record, recover: record.lease?.preserveSession == true)
      try write(record)
      return record.generation
    }
  }

  /// Logout/cancel can preempt an in-flight operation. Durable generation fences
  /// prevent any previously issued lease from writing its late result back.
  func invalidate(namespace: String, slot: String, accessibility: VaultAccessibility) throws -> Int64 {
    let account = try Self.account(namespace: namespace, slot: slot)
    return try locked {
      var record = try read(account) ?? VaultRecord(version: 1, account: account,
        accessibility: accessibility, generation: 0, identityJSON: nil,
        sessionJSON: nil, recoveryRequired: false, lease: nil)
      guard record.accessibility == accessibility else { throw SessionVaultError.policyMismatch }
      try invalidate(&record)
      try write(record)
      return record.generation
    }
  }

  /// Cancel only an interaction. A refresh lease must settle first; it may have
  /// consumed the recovery token. Return the old step only for best-effort remote
  /// cancellation, after durable local removal and generation fencing.
  func cancelInteraction(namespace: String, slot: String, accessibility: VaultAccessibility) throws -> (sessionJSON: String?, cancelled: Bool) {
    let account = try Self.account(namespace: namespace, slot: slot)
    return try locked {
      guard var record = try read(account) else { return (nil, false) }
      guard record.accessibility == accessibility else { throw SessionVaultError.policyMismatch }
      if let lease = record.lease, lease.expiresAt > now(), lease.preserveSession != true { throw SessionVaultError.busy }
      guard record.lease != nil || record.hasInteraction == true else { return (nil, false) }
      let previous = record.sessionJSON
      let recover = record.lease == nil || record.lease?.preserveSession == true
      try invalidate(&record, recover: recover)
      try write(record)
      return (previous, true)
    }
  }

  static func account(namespace: String, slot: String) throws -> String {
    guard !namespace.isEmpty, namespace.utf8.count <= 4096,
          !slot.isEmpty, slot.utf8.count <= 256 else { throw SessionVaultError.invalidInput }
    let bytes = try JSONEncoder().encode(["device-attestation-vault/v1", namespace, slot])
    return SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
  }

  /// Compensate a cancelled commit only while its generation is still current.
  /// A later committed login must never be erased by this stale cleanup.
  func discard(namespace: String, slot: String, generation: Double) throws -> Bool {
    let account = try Self.account(namespace: namespace, slot: slot)
    let expected = try Self.generation(generation)
    return try locked {
      guard var record = try read(account), record.generation == expected else { return false }
      record.recoverySessionJSON = record.rollbackSessionJSON
      try invalidate(&record, recover: true)
      try write(record)
      return true
    }
  }

  private func owned(_ account: String, leaseId: String, generation: Int64) throws -> VaultRecord {
    guard let record = try read(account), record.generation == generation,
          let lease = record.lease, lease.id == leaseId, lease.expiresAt > now() else {
      throw SessionVaultError.lostLease
    }
    return record
  }
  private func read(_ account: String) throws -> VaultRecord? {
    guard let bytes = try storage.read(account: account) else { return nil }
    guard bytes.count <= 524_288,
          let record = try? JSONDecoder().decode(VaultRecord.self, from: bytes),
          record.version == 1, record.account == account,
          record.generation >= 0, record.generation <= Self.maximumGeneration,
          record.lease == nil || (record.lease!.id.utf8.count == 43 && record.lease!.expiresAt.isFinite) else {
      throw SessionVaultError.corrupt
    }
    do {
      try Self.validateJSON(record.identityJSON, limit: 8192)
      try Self.validateJSON(record.sessionJSON, limit: 65536)
      try Self.validateJSON(record.recoverySessionJSON, limit: 65536)
      try Self.validateJSON(record.rollbackSessionJSON, limit: 65536)
    } catch { throw SessionVaultError.corrupt }
    return record
  }
  private func write(_ record: VaultRecord) throws {
    let bytes = try JSONEncoder().encode(record)
    guard bytes.count <= 524_288 else { throw SessionVaultError.invalidInput }
    try storage.write(account: record.account, data: bytes, accessibility: record.accessibility)
  }
  private func invalidate(_ record: inout VaultRecord, recover: Bool = false) throws {
    record.generation = try successor(record.generation)
    record.sessionJSON = recover ? record.recoverySessionJSON : nil
    record.recoverySessionJSON = record.sessionJSON
    record.rollbackSessionJSON = nil
    record.hasInteraction = false
    record.recoveryRequired = true
    record.lease = nil
  }
  private func successor(_ generation: Int64) throws -> Int64 {
    guard generation < Self.maximumGeneration else { throw SessionVaultError.corrupt }
    return generation + 1
  }
  private static func generation(_ value: Double) throws -> Int64 {
    guard value.isFinite, value >= 0, value <= Double(maximumGeneration), value.rounded(.towardZero) == value else {
      throw SessionVaultError.invalidInput
    }
    return Int64(value)
  }
  private static func duration(_ milliseconds: Double) throws -> Double {
    guard milliseconds.isFinite, milliseconds >= 5000, milliseconds <= 120_000,
          milliseconds.rounded(.towardZero) == milliseconds else { throw SessionVaultError.invalidInput }
    return milliseconds / 1000
  }
  private static func validateJSON(_ value: String?, limit: Int) throws {
    guard let value else { return }
    guard value.utf8.count <= limit,
          let object = try? JSONSerialization.jsonObject(with: Data(value.utf8)),
          object is [String: Any] else { throw SessionVaultError.invalidInput }
  }
  private func locked<T>(_ body: () throws -> T) rethrows -> T {
    Self.mutationLock.lock()
    defer { Self.mutationLock.unlock() }
    return try body()
  }
}
