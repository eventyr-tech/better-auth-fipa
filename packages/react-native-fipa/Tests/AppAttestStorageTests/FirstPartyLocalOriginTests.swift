import Foundation
import XCTest
@testable import AppAttestStorage

final class FirstPartyLocalOriginTests: XCTestCase {
  func testParsedLocalOrigins() throws {
    let accepted = ["localhost", "eventyr.localhost", "deep.eventyr.localhost", "EVENTYR.LocalHost", "localhost.", "eventyr.localhost.", "a-b.localhost", "127.0.0.1", "[::1]"]
    let rejected = ["notlocalhost", "localhost.example.com", "eventyr.localhost.evil.com", "evil-localhost", ".localhost", "a..localhost", "-a.localhost", "a-.localhost", "a_b.localhost", "localhost..", "eventyr.localhost..", "192.168.1.1", "127.0.0.2", "10.0.2.2"]
    func request(_ url: String, _ enabled: Bool) throws -> URLRequest {
      try FirstPartyHTTPClient.request(id: String(repeating: "a", count: 43), url: url,
        method: "GET", headers: [:], body: nil, maximumResponseBytes: 4096,
        timeoutMilliseconds: 1000, allowInsecureLoopback: enabled)
    }
    for host in accepted {
      for port in ["", ":3000"] {
        let url = "http://\(host)\(port)/auth"
        XCTAssertTrue(FirstPartyLocalOrigin.contains(URL(string: url)!.host!))
        XCTAssertNoThrow(try request(url, true), url)
        XCTAssertThrowsError(try request(url, false), url)
      }
    }
    for host in rejected {
      let url = "http://\(host):3000/auth"
      XCTAssertFalse(FirstPartyLocalOrigin.contains(host))
      XCTAssertThrowsError(try request(url, true), url)
    }
    XCTAssertThrowsError(try request("http://user:pass@eventyr.localhost:3000/auth", true))
    XCTAssertThrowsError(try request("http://eventyr.localhost:3000/auth#fragment", true))
  }
}
