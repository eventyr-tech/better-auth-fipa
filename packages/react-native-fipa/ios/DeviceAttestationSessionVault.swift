import Foundation
import React

@objc(DeviceAttestationSessionVault)
class DeviceAttestationSessionVault: NSObject {
  private static let queue = DispatchQueue(label: "DeviceAttestation.SessionVault")
  private static let vault: SessionVault? = {
    guard let bundle = Bundle.main.bundleIdentifier, !bundle.isEmpty else { return nil }
    return SessionVault(storage: KeychainSessionVaultStorage(service: "\(bundle).DeviceAttestation.SessionVault.v1"))
  }()

  @objc static func requiresMainQueueSetup() -> Bool { false }

  @objc func acquire(_ namespace: String, slotId: String, accessibility: String,
                     leaseMilliseconds: Double, preserveSession: Bool, resolver resolve: @escaping RCTPromiseResolveBlock,
                     rejecter reject: @escaping RCTPromiseRejectBlock) {
    run(resolve, reject) { vault in
      guard let policy = VaultAccessibility(rawValue: accessibility) else { throw SessionVaultError.invalidInput }
      let snapshot = try vault.acquire(namespace: namespace, slot: slotId, accessibility: policy, leaseMilliseconds: leaseMilliseconds, preserveSession: preserveSession)
      return ["leaseId": snapshot.leaseId, "generation": NSNumber(value: snapshot.generation),
              "identityJSON": snapshot.identityJSON as Any? ?? NSNull(),
              "sessionJSON": snapshot.sessionJSON as Any? ?? NSNull(),
              "recoveryRequired": snapshot.recoveryRequired]
    }
  }

  @objc func commit(_ namespace: String, slotId: String, leaseId: String, generation: Double,
                    identityJSON: String?, sessionJSON: String?, recoverySessionJSON: String?, hasInteraction: Bool, resolver resolve: @escaping RCTPromiseResolveBlock,
                    rejecter reject: @escaping RCTPromiseRejectBlock) {
    run(resolve, reject) { vault in
      NSNumber(value: try vault.commit(namespace: namespace, slot: slotId, leaseId: leaseId,
        generation: generation, identityJSON: identityJSON, sessionJSON: sessionJSON,
        recoverySessionJSON: recoverySessionJSON, hasInteraction: hasInteraction))
    }
  }

  @objc func renew(_ namespace: String, slotId: String, leaseId: String, generation: Double,
                   leaseMilliseconds: Double, resolver resolve: @escaping RCTPromiseResolveBlock,
                   rejecter reject: @escaping RCTPromiseRejectBlock) {
    run(resolve, reject) { vault in
      try vault.renew(namespace: namespace, slot: slotId, leaseId: leaseId, generation: generation,
                      leaseMilliseconds: leaseMilliseconds)
      return nil
    }
  }

  @objc func abandon(_ namespace: String, slotId: String, leaseId: String, generation: Double,
                     resolver resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
    run(resolve, reject) { vault in
      NSNumber(value: try vault.abandon(namespace: namespace, slot: slotId, leaseId: leaseId, generation: generation))
    }
  }

  @objc func invalidate(_ namespace: String, slotId: String, accessibility: String,
                        resolver resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
    run(resolve, reject) { vault in
      guard let policy = VaultAccessibility(rawValue: accessibility) else { throw SessionVaultError.invalidInput }
      return NSNumber(value: try vault.invalidate(namespace: namespace, slot: slotId, accessibility: policy))
    }
  }

  private func run(_ resolve: @escaping RCTPromiseResolveBlock, _ reject: @escaping RCTPromiseRejectBlock,
                   _ operation: @escaping (SessionVault) throws -> Any?) {
    Self.queue.async {
      do {
        guard let vault = Self.vault else { throw SessionVaultError.unavailable }
        resolve(try operation(vault))
      } catch let error as SessionVaultError {
        reject(error.rawValue, "Unable to complete secure session storage operation.", nil)
      } catch {
        reject(SessionVaultError.storage.rawValue, "Unable to complete secure session storage operation.", nil)
      }
    }
  }

  @objc func discard(_ storageNamespace: String, slotId: String, generation: Double,
                     resolver resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
    run(resolve, reject) { vault in
      try vault.discard(namespace: storageNamespace, slot: slotId, generation: generation)
    }
  }
  @objc func saveIdentity(_ storageNamespace: String, slotId: String, leaseId: String, generation: Double,
                         identityJSON: String, resolver resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
    run(resolve, reject) { vault in
      try vault.saveIdentity(namespace: storageNamespace, slot: slotId, leaseId: leaseId,
        generation: generation, identityJSON: identityJSON)
      return nil
    }
  }
  @objc func clearSession(_ storageNamespace: String, slotId: String, leaseId: String, generation: Double,
                         resolver resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
    run(resolve, reject) { vault in
      try vault.clearSession(namespace: storageNamespace, slot: slotId, leaseId: leaseId, generation: generation)
      return nil
    }
  }
  @objc func release(_ storageNamespace: String, slotId: String, leaseId: String, generation: Double,
                    resolver resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
    run(resolve, reject) { vault in
      try vault.release(namespace: storageNamespace, slot: slotId, leaseId: leaseId, generation: generation)
      return nil
    }
  }
  @objc func cancelInteraction(_ storageNamespace: String, slotId: String, accessibility: String,
                              resolver resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
    run(resolve, reject) { vault in
      guard let policy = VaultAccessibility(rawValue: accessibility) else { throw SessionVaultError.invalidInput }
      let result = try vault.cancelInteraction(namespace: storageNamespace, slot: slotId, accessibility: policy)
      return ["sessionJSON": result.sessionJSON as Any? ?? NSNull(), "cancelled": result.cancelled]
    }
  }
}
