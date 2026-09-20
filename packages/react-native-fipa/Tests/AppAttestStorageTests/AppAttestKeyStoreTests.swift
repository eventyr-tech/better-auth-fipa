import XCTest
@testable import AppAttestStorage

final class AppAttestKeyStoreTests: XCTestCase {
  private var defaults: UserDefaults!
  private var suiteName: String!

  override func setUp() {
    super.setUp()
    suiteName = "AppAttestKeyStoreTests.\(UUID().uuidString)"
    defaults = UserDefaults(suiteName: suiteName)
  }

  override func tearDown() {
    defaults.removePersistentDomain(forName: suiteName)
    defaults = nil
    suiteName = nil
    super.tearDown()
  }

  func testScopeMappingIsStableAndDoesNotExposeTheAccountIdentifier() {
    let key = AppAttestKeyStore.defaultsKey(storagePrefix: "EventyrAppAttestKeyId.v2.", for: "account-test")

    XCTAssertEqual(
      key,
      "EventyrAppAttestKeyId.v2.d86f70b3c693a77a2bed6e40c741e09cd5b82d09a97a3346b7a718d609c89224"
    )
    XCTAssertFalse(key.contains("account-test"))
  }

  func testScopesRemainIsolatedAndResetRetiresOnlyTheRequestedKey() {
    let store = AppAttestKeyStore(storagePrefix: "EventyrAppAttestKeyId.v2.", defaults: defaults)
    store.setKeyId("key-a", for: "account-a")
    store.setKeyId("key-b", for: "account-b")

    XCTAssertEqual(store.keyId(for: "account-a"), "key-a")
    XCTAssertEqual(store.keyId(for: "account-b"), "key-b")

    store.resetKey(for: "account-a")

    XCTAssertNil(store.keyId(for: "account-a"))
    XCTAssertEqual(store.keyId(for: "account-b"), "key-b")
  }

  func testExistingIdentifiersSurviveNewStoreInstancesAndNamespacesStayIsolated() {
    let original = AppAttestKeyStore(storagePrefix: "EventyrAppAttestKeyId.v2.", defaults: defaults)
    original.setKeyId("retained-key", for: "account-a")
    let upgraded = AppAttestKeyStore(storagePrefix: "EventyrAppAttestKeyId.v2.", defaults: defaults)
    let independent = AppAttestKeyStore(storagePrefix: "Example.AppAttest.v1.", defaults: defaults)

    XCTAssertEqual(upgraded.keyId(for: "account-a"), "retained-key")
    XCTAssertNil(independent.keyId(for: "account-a"))
    independent.setKeyId("independent-key", for: "account-a")
    independent.resetKey(for: "account-a")
    XCTAssertEqual(upgraded.keyId(for: "account-a"), "retained-key")
  }

}
