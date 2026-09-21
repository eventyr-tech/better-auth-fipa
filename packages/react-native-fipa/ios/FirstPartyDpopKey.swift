import CryptoKit
import Foundation
import LocalAuthentication
import Security

enum FirstPartyKeyError: String, Error {
  case invalidInput = "key_invalid_input"
  case missing = "key_missing"
  case locked = "key_locked"
  case unavailable = "key_unavailable"
  case mismatch = "key_mismatch"
  case failed = "key_failed"
}

/// Uses react-native-dpop 1.0's Secure Enclave application-tag convention so an
/// explicitly mapped Eventyr alias retains its original key. No software-key
/// fallback, replacement-on-error, or private-key export is permitted here.
enum FirstPartyDpopKey {
  private static let lock = NSLock()
  private static let service = "com.dpop.secureenclave"

  static func inspect(alias: String) throws -> String {
    try thumbprint(publicJwk(try existing(alias: alias)))
  }
  static func remove(alias: String, expectedThumbprint: String) throws {
    guard expectedThumbprint.range(of: "^[A-Za-z0-9_-]{43}$", options: .regularExpression) != nil else { throw FirstPartyKeyError.invalidInput }
    lock.lock(); defer { lock.unlock() }
    let key: SecKey
    do { key = try existing(alias: alias) }
    catch FirstPartyKeyError.missing { return }
    guard try thumbprint(publicJwk(key)) == expectedThumbprint else { throw FirstPartyKeyError.mismatch }
    // Delete the exact reference returned by lookup, never every key at an alias.
    let context = LAContext(); context.interactionNotAllowed = true
    var query: [String: Any] = [kSecClass as String: kSecClassKey,
      kSecUseAuthenticationContext as String: context]
    #if os(iOS)
    // SecItemDelete uses a single value reference on iOS; macOS uses a match list.
    query[kSecValueRef as String] = key
    #else
    query[kSecMatchItemList as String] = [key]
    #endif
    let status = SecItemDelete(query as CFDictionary)
    switch status {
    case errSecSuccess, errSecItemNotFound: return
    case errSecInteractionNotAllowed, errSecAuthFailed: throw FirstPartyKeyError.locked
    case errSecNotAvailable: throw FirstPartyKeyError.unavailable
    default: throw FirstPartyKeyError.failed
    }
  }
  static func prepare(alias: String) throws -> String {
#if targetEnvironment(simulator)
    // Hardware composition never falls back to simulator software keys.
    throw FirstPartyKeyError.unavailable
#else
    lock.lock(); defer { lock.unlock() }
    do { return try inspect(alias: alias) }
    catch FirstPartyKeyError.missing { /* Only an authoritative absent item permits creation. */ }
    catch { throw error }
    let tag = try tag(alias)
    var error: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
      .privateKeyUsage, &error) else { throw FirstPartyKeyError.failed }
    let attributes: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeySizeInBits as String: 256,
      kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
      kSecPrivateKeyAttrs as String: [kSecAttrIsPermanent as String: true,
        kSecAttrApplicationTag as String: tag, kSecAttrLabel as String: service, kSecAttrAccessControl as String: access]
    ]
    // Never delete an existing alias. A racing/failed creation is an error, not
    // permission to rotate a key that another runtime may already be using.
    guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else { throw FirstPartyKeyError.failed }
    return try thumbprint(publicJwk(key))
#endif
  }

  static func proof(alias: String, expectedThumbprint: String, url: String, method: String,
                    accessToken: String?, nonce: String?) throws -> String {
    let key = try existing(alias: alias)
    return try proof(key: key, expectedThumbprint: expectedThumbprint, url: url, method: method, accessToken: accessToken, nonce: nonce)
  }
  /// Encoding helper for deterministic software-key tests. The bridge only calls
  /// the alias overload above, which enforces an existing Secure Enclave key.
  static func proof(key: SecKey, expectedThumbprint: String, url: String, method: String,
                    accessToken: String?, nonce: String?) throws -> String {
    let jwk = try publicJwk(key)
    guard try thumbprint(jwk) == expectedThumbprint else { throw FirstPartyKeyError.mismatch }
    guard var components = URLComponents(string: url), ["https", "http"].contains(components.scheme ?? ""),
          components.host != nil, components.user == nil, components.password == nil,
          url.utf8.count <= 8192,
          method.range(of: "^[A-Z]{1,16}$", options: .regularExpression) != nil,
          (accessToken?.utf8.count ?? 0) <= 16384, (nonce?.utf8.count ?? 0) <= 1024 else { throw FirstPartyKeyError.invalidInput }
    components.query = nil; components.fragment = nil
    if components.percentEncodedPath.isEmpty { components.percentEncodedPath = "/" }
    guard let htu = components.url?.absoluteString else { throw FirstPartyKeyError.invalidInput }
    var payload: [String: Any] = ["htu": htu, "htm": method, "iat": Int(Date().timeIntervalSince1970), "jti": FirstPartyCrypto.randomToken()]
    if let accessToken { payload["ath"] = encode(Data(SHA256.hash(data: Data(accessToken.utf8)))) }
    if let nonce { payload["nonce"] = nonce }
    let header: [String: Any] = ["typ": "dpop+jwt", "alg": "ES256", "jwk": jwk]
    let input = try "\(encode(JSONSerialization.data(withJSONObject: header, options: [.sortedKeys, .withoutEscapingSlashes]))).\(encode(JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys, .withoutEscapingSlashes])))"
    return try input + "." + sign(input, key: key)
  }

  private static func existing(alias: String) throws -> SecKey {
    let context = LAContext(); context.interactionNotAllowed = true
    let query: [String: Any] = [kSecClass as String: kSecClassKey,
      kSecAttrApplicationTag as String: try tag(alias), kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave, kSecReturnRef as String: true,
      kSecMatchLimit as String: kSecMatchLimitOne, kSecUseAuthenticationContext as String: context]
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    switch status {
    case errSecItemNotFound: throw FirstPartyKeyError.missing
    case errSecInteractionNotAllowed, errSecAuthFailed: throw FirstPartyKeyError.locked
    case errSecNotAvailable: throw FirstPartyKeyError.unavailable
    case errSecSuccess: break
    default: throw FirstPartyKeyError.failed
    }
    guard let result, CFGetTypeID(result) == SecKeyGetTypeID() else { throw FirstPartyKeyError.failed }
    let key = result as! SecKey
    guard let attributes = SecKeyCopyAttributes(key) as? [String: Any],
          attributes[kSecAttrTokenID as String] as? String == kSecAttrTokenIDSecureEnclave as String else { throw FirstPartyKeyError.failed }
    return key
  }
  private static func tag(_ alias: String) throws -> Data {
    guard !alias.isEmpty, alias.utf8.count <= 256 else { throw FirstPartyKeyError.invalidInput }
    return Data("\(service).\(alias)".utf8)
  }
  // Kept separate for software-key cryptographic tests. Production proof() can
  // reach these helpers only after reading a Secure Enclave key reference.
  static func publicJwk(_ key: SecKey) throws -> [String: String] {
    guard let publicKey = SecKeyCopyPublicKey(key),
          let raw = SecKeyCopyExternalRepresentation(publicKey, nil) as Data?, raw.count == 65, raw.first == 4 else { throw FirstPartyKeyError.failed }
    return ["kty": "EC", "crv": "P-256", "x": encode(raw.subdata(in: 1..<33)), "y": encode(raw.subdata(in: 33..<65))]
  }
  static func thumbprint(_ jwk: [String: String]) throws -> String {
    encode(Data(SHA256.hash(data: try JSONSerialization.data(withJSONObject: jwk, options: [.sortedKeys, .withoutEscapingSlashes]))))
  }
  static func sign(_ input: String, key: SecKey) throws -> String {
    var error: Unmanaged<CFError>?
    guard let der = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256, Data(input.utf8) as CFData, &error) as Data? else { throw FirstPartyKeyError.failed }
    return try encode(P256.Signing.ECDSASignature(derRepresentation: der).rawRepresentation)
  }
  private static func encode(_ bytes: Data) -> String {
    bytes.base64EncodedString().replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
  }
}
