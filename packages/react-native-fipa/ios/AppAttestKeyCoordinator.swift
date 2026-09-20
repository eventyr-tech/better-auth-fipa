import Foundation

struct PreparedAppAttestKey {
  let keyId: String
  let created: Bool
}

/// A cancelled JS call cannot cancel Apple's key generation. Join that native
/// operation across bridge instances instead of creating another key for the slot.
actor AppAttestKeyCoordinator {
  static let shared = AppAttestKeyCoordinator()
  private let defaults: UserDefaults
  private var pending: [String: (id: UUID, task: Task<PreparedAppAttestKey, Error>)] = [:]

  init(defaults: UserDefaults = .standard) { self.defaults = defaults }

  func prepare(prefix: String, scope: String,
               generate: @escaping () async throws -> String) async throws -> PreparedAppAttestKey {
    let account = AppAttestKeyStore.defaultsKey(storagePrefix: prefix, for: scope)
    if let held = pending[account] { return try await held.task.value }
    let store = AppAttestKeyStore(storagePrefix: prefix, defaults: defaults)
    if let keyId = store.keyId(for: scope) {
      return PreparedAppAttestKey(keyId: keyId, created: false)
    }
    let id = UUID()
    let task = Task {
      let keyId = try await generate()
      store.setKeyId(keyId, for: scope)
      return PreparedAppAttestKey(keyId: keyId, created: true)
    }
    pending[account] = (id, task)
    defer { if pending[account]?.id == id { pending.removeValue(forKey: account) } }
    return try await task.value
  }

  // Preserve the legacy explicit reset API without allowing a still-running
  // generation to repopulate the reference after reset has completed.
  func reset(prefix: String, scope: String) async {
    let account = AppAttestKeyStore.defaultsKey(storagePrefix: prefix, for: scope)
    if let held = pending[account] {
      _ = try? await held.task.value
      if pending[account]?.id == held.id { pending.removeValue(forKey: account) }
    }
    AppAttestKeyStore(storagePrefix: prefix, defaults: defaults).resetKey(for: scope)
  }

  func remove(prefix: String, scope: String, expectedKeyId: String) async throws {
    guard !expectedKeyId.isEmpty else { throw FirstPartyKeyError.invalidInput }
    let account = AppAttestKeyStore.defaultsKey(storagePrefix: prefix, for: scope)
    if let held = pending[account] {
      _ = try await held.task.value
      if pending[account]?.id == held.id { pending.removeValue(forKey: account) }
    }
    let store = AppAttestKeyStore(storagePrefix: prefix, defaults: defaults)
    guard let current = store.keyId(for: scope) else { return }
    guard current == expectedKeyId else { throw FirstPartyKeyError.mismatch }
    // App Attest exposes no platform key deletion API. Forget its local reference
    // only after server retirement; the durable vault tombstone prevents reuse.
    store.resetKey(for: scope)
  }
}
