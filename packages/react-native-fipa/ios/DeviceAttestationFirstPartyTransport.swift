import Foundation
import React

@objc(DeviceAttestationFirstPartyTransport)
class DeviceAttestationFirstPartyTransport: NSObject {
  private static let client = FirstPartyHTTPClient()
  @objc static func requiresMainQueueSetup() -> Bool { false }

  @objc func randomToken(_ resolve: RCTPromiseResolveBlock, rejecter _: RCTPromiseRejectBlock) {
    resolve(FirstPartyCrypto.randomToken())
  }
  @objc func transaction(_ resolve: RCTPromiseResolveBlock, rejecter _: RCTPromiseRejectBlock) {
    resolve(FirstPartyCrypto.transaction())
  }
  @objc func prepareDpop(_ alias: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) {
    keyCall(resolve, reject) { try FirstPartyDpopKey.prepare(alias: alias) }
  }
  @objc func inspectDpop(_ alias: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) {
    keyCall(resolve, reject) { try FirstPartyDpopKey.inspect(alias: alias) }
  }
  @objc func removeDpop(_ alias: String, expectedThumbprint: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) {
    keyCall(resolve, reject) { try FirstPartyDpopKey.remove(alias: alias, expectedThumbprint: expectedThumbprint); return nil }
  }
  @objc func signDpop(_ alias: String, expectedThumbprint: String, url: String, method: String,
                     accessToken: String?, nonce: String?, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) {
    keyCall(resolve, reject) { try FirstPartyDpopKey.proof(alias: alias, expectedThumbprint: expectedThumbprint,
      url: url, method: method, accessToken: accessToken, nonce: nonce) }
  }
  private func keyCall(_ resolve: RCTPromiseResolveBlock, _ reject: RCTPromiseRejectBlock, _ operation: () throws -> Any?) {
    do { resolve(try operation()) }
    catch let error as FirstPartyKeyError { reject(error.rawValue, "Unable to use the device signing key.", nil) }
    catch { reject(FirstPartyKeyError.failed.rawValue, "Unable to use the device signing key.", nil) }
  }
  @objc func cancel(_ requestId: String, resolver resolve: RCTPromiseResolveBlock, rejecter _: RCTPromiseRejectBlock) {
    Self.client.cancel(id: requestId); resolve(nil)
  }
  @objc func openBrowser(_ requestId: String, url: String, redirectUri: String, timeoutMilliseconds: Double,
                        allowInsecureLoopback: Bool, resolver resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
    DispatchQueue.main.async {
      FirstPartyBrowser.shared.open(id: requestId, url: url, redirectUri: redirectUri,
        timeoutMilliseconds: timeoutMilliseconds, allowInsecureLoopback: allowInsecureLoopback) { result in
        switch result {
        case .success(let callback): resolve(callback)
        case .failure(let error): reject(error.rawValue, "Unable to complete browser authentication.", nil)
        }
      }
    }
  }
  @objc func cancelBrowser(_ requestId: String, resolver resolve: @escaping RCTPromiseResolveBlock, rejecter _: RCTPromiseRejectBlock) {
    DispatchQueue.main.async { FirstPartyBrowser.shared.cancel(id: requestId); resolve(nil) }
  }
  @objc func send(_ requestId: String, url: String, method: String, headersJSON: String, body: String?,
                  maximumResponseBytes: Double, timeoutMilliseconds: Double, allowInsecureLoopback: Bool,
                  resolver resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
    guard headersJSON.utf8.count <= 32768,
          let headers = try? JSONDecoder().decode([String: String].self, from: Data(headersJSON.utf8)),
          maximumResponseBytes.isFinite, maximumResponseBytes > 0, maximumResponseBytes <= 1_048_576,
          maximumResponseBytes.rounded(.towardZero) == maximumResponseBytes,
          timeoutMilliseconds.isFinite, timeoutMilliseconds >= 1000, timeoutMilliseconds <= 120000,
          timeoutMilliseconds.rounded(.towardZero) == timeoutMilliseconds else {
      reject(FirstPartyHTTPError.invalidRequest.rawValue, "Unable to complete authentication request.", nil); return
    }
    Self.client.send(id: requestId, url: url, method: method, headers: headers, body: body,
      maximumResponseBytes: Int(maximumResponseBytes), timeoutMilliseconds: Int(timeoutMilliseconds),
      allowInsecureLoopback: allowInsecureLoopback) { result in
        switch result {
        case .success(let response):
          guard let data = try? JSONEncoder().encode(response.headers), let headersJSON = String(data: data, encoding: .utf8) else {
            reject(FirstPartyHTTPError.invalidResponse.rawValue, "Unable to complete authentication request.", nil); return
          }
          resolve(["url": response.url, "status": response.status, "headersJSON": headersJSON, "body": response.body])
        case .failure(let error):
          reject(error.rawValue, "Unable to complete authentication request.", nil)
        }
      }
  }
}
