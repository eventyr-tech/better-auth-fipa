import CryptoKit
import Security
import XCTest
@testable import AppAttestStorage

final class FirstPartyDpopKeyTests: XCTestCase {
  // Ephemeral software keys verify encoding and signature math only. Production
  // key lookup rejects software keys; Secure Enclave retention needs a device.
  func testPublicJwkAndJoseSignatureVerifyWithIndependentCryptoKitPublicKey() throws {
    let key = try XCTUnwrap(SecKeyCreateRandomKey([
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeySizeInBits as String: 256,
    ] as CFDictionary, nil))
    let jwk = try FirstPartyDpopKey.publicJwk(key)
    XCTAssertEqual(jwk["kty"], "EC")
    XCTAssertEqual(jwk["crv"], "P-256")
    let x = try decode(XCTUnwrap(jwk["x"]))
    let y = try decode(XCTUnwrap(jwk["y"]))
    XCTAssertEqual(x.count, 32); XCTAssertEqual(y.count, 32)
    let publicKey = try P256.Signing.PublicKey(x963Representation: Data([4]) + x + y)
    for index in 0..<8 {
      let input = "header.payload-\(index)"
      let bytes = try decode(FirstPartyDpopKey.sign(input, key: key))
      XCTAssertEqual(bytes.count, 64)
      let signature = try P256.Signing.ECDSASignature(rawRepresentation: bytes)
      XCTAssertTrue(publicKey.isValidSignature(signature, for: Data(input.utf8)))
      XCTAssertFalse(publicKey.isValidSignature(signature, for: Data("changed".utf8)))
    }
    let expected = Data(SHA256.hash(data: Data("{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"\(jwk["x"]!)\",\"y\":\"\(jwk["y"]!)\"}".utf8)))
    XCTAssertEqual(try decode(FirstPartyDpopKey.thumbprint(jwk)), expected)
  }

  func testRejectsInvalidAliasesWithoutKeyCreation() {
    for alias in ["", String(repeating: "x", count: 257)] {
      XCTAssertThrowsError(try FirstPartyDpopKey.inspect(alias: alias)) {
        XCTAssertEqual($0 as? FirstPartyKeyError, .invalidInput)
      }
      XCTAssertThrowsError(try FirstPartyDpopKey.prepare(alias: alias)) {
        XCTAssertEqual($0 as? FirstPartyKeyError, .invalidInput)
      }
    }
  }
  func testProofBindsMethodURLTokenNonceAndTheExpectedKey() throws {
    let key = try XCTUnwrap(SecKeyCreateRandomKey([
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeySizeInBits as String: 256,
    ] as CFDictionary, nil))
    let jwk = try FirstPartyDpopKey.publicJwk(key)
    let thumbprint = try FirstPartyDpopKey.thumbprint(jwk)
    let first = try FirstPartyDpopKey.proof(key: key, expectedThumbprint: thumbprint,
      url: "https://example.test/resource?query=1#fragment", method: "POST", accessToken: "test-access", nonce: "test-nonce")
    let second = try FirstPartyDpopKey.proof(key: key, expectedThumbprint: thumbprint,
      url: "https://example.test/resource", method: "POST", accessToken: nil, nonce: nil)
    let parts = first.split(separator: ".").map(String.init)
    let header = try XCTUnwrap(JSONSerialization.jsonObject(with: decode(parts[0])) as? [String: Any])
    let payload = try XCTUnwrap(JSONSerialization.jsonObject(with: decode(parts[1])) as? [String: Any])
    let secondPayload = try XCTUnwrap(JSONSerialization.jsonObject(with: decode(String(second.split(separator: ".")[1]))) as? [String: Any])
    XCTAssertEqual(header["alg"] as? String, "ES256")
    XCTAssertEqual(header["typ"] as? String, "dpop+jwt")
    XCTAssertEqual(header["jwk"] as? [String: String], jwk)
    XCTAssertEqual(payload["htu"] as? String, "https://example.test/resource")
    XCTAssertEqual(payload["htm"] as? String, "POST")
    XCTAssertEqual(payload["nonce"] as? String, "test-nonce")
    XCTAssertEqual(try decode(XCTUnwrap(payload["ath"] as? String)), Data(SHA256.hash(data: Data("test-access".utf8))))
    XCTAssertNotEqual(payload["jti"] as? String, secondPayload["jti"] as? String)
    XCTAssertNil(secondPayload["ath"]); XCTAssertNil(secondPayload["nonce"])
    let publicKey = try P256.Signing.PublicKey(x963Representation: Data([4]) + decode(jwk["x"]!) + decode(jwk["y"]!))
    XCTAssertTrue(publicKey.isValidSignature(try P256.Signing.ECDSASignature(rawRepresentation: decode(parts[2])),
      for: Data("\(parts[0]).\(parts[1])".utf8)))
    XCTAssertThrowsError(try FirstPartyDpopKey.proof(key: key, expectedThumbprint: "wrong-key", url: "https://example.test", method: "POST", accessToken: nil, nonce: nil)) {
      XCTAssertEqual($0 as? FirstPartyKeyError, .mismatch)
    }
  }
  private func decode(_ value: String) throws -> Data {
    let text = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    return try XCTUnwrap(Data(base64Encoded: text + String(repeating: "=", count: (4 - text.count % 4) % 4)))
  }
}
