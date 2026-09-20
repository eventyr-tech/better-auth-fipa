import Foundation
import LocalAuthentication
import Security

/// One complete record per slot: identity, session secrets, generation and lease
/// share one Keychain write. No synchronizable or shared-access-group option.
final class KeychainSessionVaultStorage: SessionVaultStorage {
  private let service: String
  init(service: String) { self.service = service }

  func read(account: String) throws -> Data? {
    var query = base(account)
    let context = LAContext()
    context.interactionNotAllowed = true
    query[kSecUseAuthenticationContext as String] = context
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    query[kSecReturnData as String] = true
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    if status == errSecItemNotFound { return nil }
    try check(status)
    guard let data = item as? Data else { throw SessionVaultError.corrupt }
    return data
  }

  func write(account: String, data: Data, accessibility: VaultAccessibility) throws {
    let query = base(account)
    let attributes: [String: Any] = [
      kSecValueData as String: data,
      kSecAttrAccessible as String: accessibility == .whenUnlocked
        ? kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        : kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
    ]
    let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
    if status == errSecItemNotFound {
      try check(SecItemAdd(query.merging(attributes) { _, new in new } as CFDictionary, nil))
    } else { try check(status) }
  }

  private func base(_ account: String) -> [String: Any] {
    [kSecClass as String: kSecClassGenericPassword,
     kSecAttrService as String: service,
     kSecAttrAccount as String: account,
     kSecAttrSynchronizable as String: false,
     kSecUseDataProtectionKeychain as String: true]
  }
  private func check(_ status: OSStatus) throws {
    switch status {
    case errSecSuccess: return
    case errSecInteractionNotAllowed, errSecAuthFailed: throw SessionVaultError.locked
    case errSecNotAvailable: throw SessionVaultError.unavailable
    default: throw SessionVaultError.storage
    }
  }
}
