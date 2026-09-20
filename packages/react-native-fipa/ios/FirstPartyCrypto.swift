import CryptoKit
import Foundation

enum FirstPartyCrypto {
  static func randomToken() -> String {
    SymmetricKey(size: .bits256).withUnsafeBytes { encode(Data($0)) }
  }
  static func transaction() -> [String: String] {
    let verifier = randomToken()
    return ["id": randomToken(), "verifier": verifier, "challenge": encode(Data(SHA256.hash(data: Data(verifier.utf8))))]
  }
  private static func encode(_ bytes: Data) -> String {
    bytes.base64EncodedString().replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
  }
}
