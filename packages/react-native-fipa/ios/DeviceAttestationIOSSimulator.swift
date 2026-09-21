import Foundation
import React

@objc(DeviceAttestationIOSSimulator)
class DeviceAttestationIOSSimulator: NSObject {
  @objc static func requiresMainQueueSetup() -> Bool { false }
  private func call(_ resolve: RCTPromiseResolveBlock, _ reject: RCTPromiseRejectBlock, _ operation: () throws -> Any?) {
    do { try FirstPartySimulatorKey.requireSimulator(); resolve(try operation()) }
    catch is FirstPartySimulatorKey.EligibilityError { reject("simulator_unavailable", "An iOS Simulator runtime is required.", nil) }
    catch let error as FirstPartyKeyError { reject(error.rawValue, "Unable to use the simulator key.", nil) }
    catch { reject("key_failed", "Unable to use the simulator key.", nil) }
  }
  @objc func getKey(_ storagePrefix: String, credentialScope: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) {
    call(resolve, reject) {
      let id = try FirstPartySimulatorKey.keyId(prefix: storagePrefix, scope: credentialScope)
      do { _ = try FirstPartySimulatorKey.existing("evidence.\(id)"); return id }
      catch FirstPartyKeyError.missing { return NSNull() }
    }
  }
  @objc func getOrCreateKey(_ storagePrefix: String, credentialScope: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) {
    call(resolve, reject) {
      let id = try FirstPartySimulatorKey.keyId(prefix: storagePrefix, scope: credentialScope)
      let (_, created) = try FirstPartySimulatorKey.prepare("evidence.\(id)")
      return ["keyId": id, "created": created]
    }
  }
  @objc func generateEvidence(_ keyId: String, clientData: String, operation: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) {
    call(resolve, reject) { try FirstPartySimulatorKey.evidence(keyId: keyId, clientData: clientData, operation: operation) }
  }
  @objc func removeKey(_ storagePrefix: String, credentialScope: String, expectedKeyId: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) {
    call(resolve, reject) {
      let id = try FirstPartySimulatorKey.keyId(prefix: storagePrefix, scope: credentialScope)
      guard id == expectedKeyId else { throw FirstPartyKeyError.mismatch }
      try FirstPartySimulatorKey.remove("evidence.\(id)"); return nil
    }
  }
  @objc func prepareDpop(_ alias: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) {
    call(resolve, reject) { try FirstPartyDpopKey.thumbprint(FirstPartyDpopKey.publicJwk(FirstPartySimulatorKey.prepare("dpop.\(alias)").0)) }
  }
  @objc func inspectDpop(_ alias: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) {
    call(resolve, reject) { try FirstPartyDpopKey.thumbprint(FirstPartyDpopKey.publicJwk(FirstPartySimulatorKey.existing("dpop.\(alias)"))) }
  }
  @objc func removeDpop(_ alias: String, expectedThumbprint: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) {
    call(resolve, reject) { try FirstPartySimulatorKey.remove("dpop.\(alias)", expectedThumbprint: expectedThumbprint); return nil }
  }
  @objc func signDpop(_ alias: String, expectedThumbprint: String, url: String, method: String, accessToken: String?, nonce: String?, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) {
    call(resolve, reject) { try FirstPartyDpopKey.proof(key: FirstPartySimulatorKey.existing("dpop.\(alias)"), expectedThumbprint: expectedThumbprint, url: url, method: method, accessToken: accessToken, nonce: nonce) }
  }
}
