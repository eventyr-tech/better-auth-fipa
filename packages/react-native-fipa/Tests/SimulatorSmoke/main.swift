import Foundation
import UIKit

class SmokeDelegate: UIResponder, UIApplicationDelegate {
  func application(_ application: UIApplication, didFinishLaunchingWithOptions _: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
    let resultURL = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0].appendingPathComponent("result.json")
    do {
      let first = UserDefaults.standard.string(forKey: "alias") == nil
      let alias = UserDefaults.standard.string(forKey: "alias") ?? "smoke-" + UUID().uuidString
      UserDefaults.standard.set(alias, forKey: "alias")
      let id = try FirstPartySimulatorKey.keyId(prefix: "test", scope: alias)
      let (_, created) = try FirstPartySimulatorKey.prepare("evidence.\(id)")
      precondition(created == first)
      let (key, dpopCreated) = try FirstPartySimulatorKey.prepare("dpop.\(alias)")
      precondition(dpopCreated == first)
      let jkt = try FirstPartyDpopKey.thumbprint(FirstPartyDpopKey.publicJwk(key))
      let proof = try FirstPartyDpopKey.proof(key: key, expectedThumbprint: jkt,
        url: "http://eventyr.localhost:3000/api/auth/resource", method: "GET", accessToken: "test-token", nonce: nil)
      let data = Data("challenge".utf8).base64EncodedString().replacingOccurrences(of: "=", with: "")
      let registration = try FirstPartySimulatorKey.evidence(keyId: id, clientData: data, operation: "register")
      let assertion = try FirstPartySimulatorKey.evidence(keyId: id, clientData: data, operation: "assert")
      do { _ = try FirstPartyDpopKey.prepare(alias: alias); throw FirstPartyKeyError.mismatch }
      catch FirstPartyKeyError.unavailable { }
      do { _ = try FirstPartyDpopKey.inspect(alias: alias); throw FirstPartyKeyError.mismatch }
      catch FirstPartyKeyError.missing { }
      let storage = KeychainSessionVaultStorage(service: "dev.fipa.simulator-smoke")
      if first { try storage.write(account: alias, data: Data("vault-marker".utf8), accessibility: .whenUnlocked) }
      else { let stored = try storage.read(account: alias); precondition(stored == Data("vault-marker".utf8)) }
      if !first {
        try FirstPartySimulatorKey.remove("evidence.\(id)")
        try FirstPartySimulatorKey.remove("dpop.\(alias)", expectedThumbprint: jkt)
        do { _ = try FirstPartySimulatorKey.existing("evidence.\(id)"); throw FirstPartyKeyError.mismatch }
        catch FirstPartyKeyError.missing { }
        UserDefaults.standard.removeObject(forKey: "alias")
      }
      let result: [String: Any] = ["phase": first ? "created" : "restored-and-removed",
        "keyId": id, "registration": registration, "assertion": assertion, "dpop": proof]
      try JSONSerialization.data(withJSONObject: result).write(to: resultURL, options: .atomic)
    } catch {
      try? JSONSerialization.data(withJSONObject: ["error": String(describing: error)]).write(to: resultURL)
    }
    return true
  }
}
UIApplicationMain(CommandLine.argc, CommandLine.unsafeArgv, nil, NSStringFromClass(SmokeDelegate.self))
