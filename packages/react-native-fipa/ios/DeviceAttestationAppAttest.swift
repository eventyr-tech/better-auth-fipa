import CryptoKit
import DeviceCheck
import Foundation
import React

@objc(DeviceAttestationAppAttest)
class DeviceAttestationAppAttest: NSObject {

  @objc func getKey(_ storagePrefix: String, credentialScope: String,
                   resolver resolve: RCTPromiseResolveBlock, rejecter _: RCTPromiseRejectBlock) {
    resolve(AppAttestKeyStore(storagePrefix: storagePrefix).keyId(for: credentialScope) as Any? ?? NSNull())
  }

  @objc
  static func requiresMainQueueSetup() -> Bool {
    false
  }

  @objc
  func getOrCreateKey(
    _ storagePrefix: String,
    credentialScope: String,
    resolver resolve: @escaping RCTPromiseResolveBlock,
    rejecter reject: @escaping RCTPromiseRejectBlock
  ) {
#if targetEnvironment(simulator)
    reject("app_attest_unavailable", "App Attest is unavailable on the simulator.", nil)
#else
    Task {
      do {
        let service = DCAppAttestService.shared
        guard service.isSupported else {
          throw AppAttestError.unsupported
        }
        let key = try await AppAttestKeyCoordinator.shared.prepare(prefix: storagePrefix, scope: credentialScope) {
          try await service.generateKey()
        }
        resolve(["keyId": key.keyId, "created": key.created])
      } catch {
        reject("app_attest_failed", "Unable to initialize App Attest.", nil)
      }
    }
#endif
  }

  @objc
  func generateEvidence(
    _ keyId: String,
    clientData: String,
    operation: String,
    resolver resolve: @escaping RCTPromiseResolveBlock,
    rejecter reject: @escaping RCTPromiseRejectBlock
  ) {
#if targetEnvironment(simulator)
    reject("app_attest_unavailable", "App Attest is unavailable on the simulator.", nil)
#else
    Task {
      do {
        guard let clientDataBytes = Self.decodeBase64Url(clientData) else {
          throw AppAttestError.invalidClientData
        }
        let clientDataHash = Data(SHA256.hash(data: clientDataBytes))
        let service = DCAppAttestService.shared
        guard service.isSupported else {
          throw AppAttestError.unsupported
        }
        let evidence: Data
        switch operation {
        case "register":
          evidence = try await service.attestKey(
            keyId,
            clientDataHash: clientDataHash
          )
        case "assert":
          evidence = try await service.generateAssertion(
            keyId,
            clientDataHash: clientDataHash
          )
        default:
          throw AppAttestError.invalidOperation
        }
        resolve(evidence.base64EncodedString())
      } catch {
        reject("app_attest_failed", "Unable to verify this app instance.", nil)
      }
    }
#endif
  }

  @objc
  func resetKey(
    _ storagePrefix: String,
    credentialScope: String,
    resolver resolve: @escaping RCTPromiseResolveBlock,
    rejecter _: RCTPromiseRejectBlock
  ) {
    Task {
      await AppAttestKeyCoordinator.shared.reset(prefix: storagePrefix, scope: credentialScope)
      resolve(nil)
    }
  }

  private static func decodeBase64Url(_ value: String) -> Data? {
    var normalized = value
      .replacingOccurrences(of: "-", with: "+")
      .replacingOccurrences(of: "_", with: "/")
    let remainder = normalized.count % 4
    if remainder != 0 {
      normalized += String(repeating: "=", count: 4 - remainder)
    }
    return Data(base64Encoded: normalized)
  }
  @objc func removeKey(_ storagePrefix: String, credentialScope: String, expectedKeyId: String,
                       resolver resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
    Task {
      do {
        try await AppAttestKeyCoordinator.shared.remove(prefix: storagePrefix, scope: credentialScope, expectedKeyId: expectedKeyId)
        resolve(nil)
      } catch {
        reject("app_attest_failed", "Unable to remove the local App Attest reference.", nil)
      }
    }
  }
}

private enum AppAttestError: Error {
  case invalidClientData
  case invalidOperation
  case unsupported
}
