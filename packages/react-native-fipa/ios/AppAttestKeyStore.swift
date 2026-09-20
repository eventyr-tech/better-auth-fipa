import CryptoKit
import Foundation

struct AppAttestKeyStore {
  private let storagePrefix: String
  private let defaults: UserDefaults

  init(storagePrefix: String, defaults: UserDefaults = .standard) {
    self.storagePrefix = storagePrefix
    self.defaults = defaults
  }

  func keyId(for credentialScope: String) -> String? {
    defaults.string(forKey: Self.defaultsKey(storagePrefix: storagePrefix, for: credentialScope))
  }

  func setKeyId(_ keyId: String, for credentialScope: String) {
    defaults.set(keyId, forKey: Self.defaultsKey(storagePrefix: storagePrefix, for: credentialScope))
  }

  func resetKey(for credentialScope: String) {
    defaults.removeObject(forKey: Self.defaultsKey(storagePrefix: storagePrefix, for: credentialScope))
  }

  static func defaultsKey(storagePrefix: String, for credentialScope: String) -> String {
    let digest = SHA256.hash(data: Data(credentialScope.utf8))
    let suffix = digest.map { String(format: "%02x", $0) }.joined()
    return storagePrefix + suffix
  }
}
