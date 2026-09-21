import CryptoKit
import Foundation
import Security

/// Development software keys in a separate Keychain domain. No production
/// signing path calls this type. Every operation enforces simulator eligibility.
enum FirstPartySimulatorKey {
  enum EligibilityError: Error { case unavailable }
  private static let lock = NSLock()
  static func requireSimulator() throws {
#if !targetEnvironment(simulator)
    throw EligibilityError.unavailable
#endif
  }
  static func keyId(prefix: String, scope: String) throws -> String {
    try requireSimulator()
    guard !prefix.isEmpty, prefix.utf8.count <= 256, !scope.isEmpty, scope.utf8.count <= 256 else { throw FirstPartyKeyError.invalidInput }
    return Data(SHA256.hash(data: Data("\(prefix)\u{0}\(scope)".utf8))).base64EncodedString()
  }
  private static func query(_ alias: String) throws -> [String: Any] {
    try requireSimulator()
    guard !alias.isEmpty, alias.utf8.count <= 512 else { throw FirstPartyKeyError.invalidInput }
    return [kSecClass as String: kSecClassKey,
      kSecAttrApplicationTag as String: Data("dev.fipa.ios-simulator.v1.\(alias)".utf8),
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom]
  }
  static func existing(_ alias: String) throws -> SecKey {
    var q = try query(alias)
    q[kSecReturnRef as String] = true; q[kSecMatchLimit as String] = kSecMatchLimitOne
    var result: CFTypeRef?
    let status = SecItemCopyMatching(q as CFDictionary, &result)
    if status == errSecItemNotFound { throw FirstPartyKeyError.missing }
    if status == errSecInteractionNotAllowed { throw FirstPartyKeyError.locked }
    guard status == errSecSuccess, let result, CFGetTypeID(result) == SecKeyGetTypeID() else { throw FirstPartyKeyError.unavailable }
    return result as! SecKey
  }
  static func prepare(_ alias: String) throws -> (SecKey, Bool) {
    try requireSimulator()
    lock.lock(); defer { lock.unlock() }
    do { return (try existing(alias), false) }
    catch FirstPartyKeyError.missing { }
    let q = try query(alias)
    let attrs: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeySizeInBits as String: 256,
      kSecPrivateKeyAttrs as String: [kSecAttrIsPermanent as String: true,
        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        kSecAttrApplicationTag as String: q[kSecAttrApplicationTag as String]!]]
    guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, nil) else { throw FirstPartyKeyError.failed }
    return (key, true)
  }
  static func remove(_ alias: String, expectedThumbprint: String? = nil) throws {
    try requireSimulator()
    lock.lock(); defer { lock.unlock() }
    let key: SecKey
    do { key = try existing(alias) } catch FirstPartyKeyError.missing { return }
    if let expectedThumbprint, try FirstPartyDpopKey.thumbprint(FirstPartyDpopKey.publicJwk(key)) != expectedThumbprint { throw FirstPartyKeyError.mismatch }
    let status = SecItemDelete([kSecClass as String: kSecClassKey, kSecValueRef as String: key] as CFDictionary)
    guard status == errSecSuccess || status == errSecItemNotFound else { throw FirstPartyKeyError.failed }
  }
  static func evidence(keyId: String, clientData: String, operation: String) throws -> String {
    try requireSimulator()
    guard ["register", "assert"].contains(operation), clientData.utf8.count <= 32768 else { throw FirstPartyKeyError.invalidInput }
    var encoded = clientData.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    encoded += String(repeating: "=", count: (4 - encoded.count % 4) % 4)
    guard let data = Data(base64Encoded: encoded) else { throw FirstPartyKeyError.invalidInput }
    let key = try existing("evidence.\(keyId)")
    let hash = Data(SHA256.hash(data: data)).base64EncodedString()
    let message = "fipa/ios-simulator/v1\n\(operation)\n\(keyId)\n\(hash)"
    let value: [String: Any] = ["version": 1, "provider": "ios-simulator", "operation": operation,
      "jwk": try FirstPartyDpopKey.publicJwk(key), "signature": try FirstPartyDpopKey.sign(message, key: key)]
    return try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]).base64EncodedString()
  }
}
