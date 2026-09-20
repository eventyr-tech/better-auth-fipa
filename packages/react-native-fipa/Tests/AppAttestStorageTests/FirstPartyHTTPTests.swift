import Foundation
import Network
import XCTest
@testable import AppAttestStorage

/// Actual loopback sockets, not URLProtocol interception: redirects and cookie
/// behavior below are exercised by Foundation's HTTP implementation.
private final class LoopbackHTTPServer {
  private let listener: NWListener
  private let queue = DispatchQueue(label: "DeviceAttestation.HTTPTests.Server")
  private let lock = NSLock()
  private var received: [String] = []
  private let handler: (String) -> (Data, TimeInterval)
  let url: String

  init(handler: @escaping (String) -> (Data, TimeInterval)) throws {
    self.handler = handler
    let parameters = NWParameters.tcp
    parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
    let listener = try NWListener(using: parameters)
    self.listener = listener
    let ready = DispatchSemaphore(value: 0)
    listener.stateUpdateHandler = { state in
      switch state { case .ready, .failed: ready.signal(); default: break }
    }
    // Set a temporary connection handler before start, then install the handler
    // that captures this instance after all stored properties are initialized.
    listener.newConnectionHandler = { $0.cancel() }
    listener.start(queue: queue)
    guard ready.wait(timeout: .now() + 3) == .success, let port = listener.port else {
      listener.cancel(); throw NSError(domain: "LoopbackHTTPServer", code: 1)
    }
    url = "http://127.0.0.1:\(port.rawValue)"
    listener.newConnectionHandler = { [weak self] connection in
      guard let self else { connection.cancel(); return }
      connection.start(queue: self.queue)
      self.read(connection, bytes: Data())
    }
  }
  var requests: [String] {
    lock.lock(); defer { lock.unlock() }; return received
  }
  func stop() { listener.cancel() }

  private func read(_ connection: NWConnection, bytes: Data) {
    connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, complete, error in
      guard let self, error == nil, let data, !data.isEmpty else { connection.cancel(); return }
      let next = bytes + data
      guard next.count < 1_048_576 else { connection.cancel(); return }
      guard let text = String(data: next, encoding: .utf8), let boundary = text.range(of: "\r\n\r\n") else {
        if !complete { self.read(connection, bytes: next) } else { connection.cancel() }; return
      }
      let headers = String(text[..<boundary.lowerBound])
      let contentLength = headers.components(separatedBy: "\r\n").first { $0.lowercased().hasPrefix("content-length:") }
        .flatMap { Int($0.split(separator: ":", maxSplits: 1)[1].trimmingCharacters(in: .whitespaces)) } ?? 0
      if text[boundary.upperBound...].utf8.count < contentLength && !complete {
        self.read(connection, bytes: next); return
      }
      self.lock.lock(); self.received.append(text); self.lock.unlock()
      let (response, delay) = self.handler(text)
      self.queue.asyncAfter(deadline: .now() + delay) {
        connection.send(content: response, completion: .contentProcessed { _ in connection.cancel() })
      }
    }
  }
}

final class FirstPartyHTTPTests: XCTestCase {
  private func response(_ body: String = "{}", headers: String = "", status: String = "200 OK") -> Data {
    Data("HTTP/1.1 \(status)\r\nContent-Length: \(body.utf8.count)\r\nConnection: close\r\n\(headers)\r\n\(body)".utf8)
  }
  private func send(_ client: FirstPartyHTTPClient, _ url: String, id: String = FirstPartyCrypto.randomToken(),
                    limit: Int = 65536, headers: [String: String] = [:], allowHTTP: Bool = true) async -> Result<FirstPartyHTTPResponse, FirstPartyHTTPError> {
    await withCheckedContinuation { continuation in
      client.send(id: id, url: url, method: "GET", headers: headers, body: nil,
        maximumResponseBytes: limit, timeoutMilliseconds: 2000, allowInsecureLoopback: allowHTTP) {
          continuation.resume(returning: $0)
        }
    }
  }
  private func assertFailure(_ result: Result<FirstPartyHTTPResponse, FirstPartyHTTPError>, _ code: FirstPartyHTTPError,
                             file: StaticString = #filePath, line: UInt = #line) {
    switch result {
    case .success: XCTFail("Expected transport rejection", file: file, line: line)
    case .failure(let error): XCTAssertEqual(error, code, file: file, line: line)
    }
  }

  func testDoesNotForwardCredentialsOnRedirectEvenToSameOrigin() async throws {
    let server = try LoopbackHTTPServer { _ in
      (self.response(headers: "Location: /target\r\n", status: "302 Found"), 0)
    }
    defer { server.stop() }
    let result = await send(FirstPartyHTTPClient(), server.url + "/start", headers: ["Authorization": "DPoP test-only", "DPoP": "test-proof"])
    assertFailure(result, .redirect)
    XCTAssertEqual(server.requests.count, 1)
    XCTAssertTrue(server.requests[0].hasPrefix("GET /start "))
  }

  func testDoesNotReuseResponseCookiesOrCache() async throws {
    let server = try LoopbackHTTPServer { _ in
      (self.response("payload", headers: "Set-Cookie: auth=secret; Path=/\r\nCache-Control: max-age=3600\r\n"), 0)
    }
    defer { server.stop() }
    let client = FirstPartyHTTPClient()
    for _ in 0..<2 {
      let result = try await send(client, server.url + "/same").get()
      XCTAssertEqual(result.body, "payload")
      XCTAssertNil(result.headers["set-cookie"])
    }
    XCTAssertEqual(server.requests.count, 2)
    XCTAssertFalse(server.requests.contains { $0.lowercased().contains("\r\ncookie:") })
  }

  func testBoundsBothDeclaredAndChunkedResponseBodies() async throws {
    let declared = try LoopbackHTTPServer { _ in (self.response(String(repeating: "a", count: 1024)), 0) }
    let chunked = try LoopbackHTTPServer { _ in
      (Data(("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n400\r\n" +
        String(repeating: "b", count: 1024) + "\r\n0\r\n\r\n").utf8), 0)
    }
    defer { declared.stop(); chunked.stop() }
    assertFailure(await send(FirstPartyHTTPClient(), declared.url, limit: 100), .tooLarge)
    assertFailure(await send(FirstPartyHTTPClient(), chunked.url, limit: 100), .tooLarge)
  }

  func testCancelsBeforeSendWithoutContactingServer() async throws {
    let server = try LoopbackHTTPServer { _ in (self.response(), 0) }
    defer { server.stop() }
    let client = FirstPartyHTTPClient()
    let id = FirstPartyCrypto.randomToken()
    client.cancel(id: id)
    assertFailure(await send(client, server.url, id: id), .cancelled)
    XCTAssertEqual(server.requests.count, 0)
  }

  func testCancelsInflightRequestAndCompletesOnlyOnce() async throws {
    let received = expectation(description: "request arrived")
    let server = try LoopbackHTTPServer { _ in received.fulfill(); return (self.response(), 0.5) }
    defer { server.stop() }
    let client = FirstPartyHTTPClient()
    let id = FirstPartyCrypto.randomToken()
    let work = Task { await send(client, server.url, id: id) }
    await fulfillment(of: [received], timeout: 2)
    client.cancel(id: id)
    assertFailure(await work.value, .cancelled)
  }

  func testRejectsInvalidUTF8AndDoesNotSupplyHTTPAuthenticationCredentials() async throws {
    let invalid = try LoopbackHTTPServer { _ in
      (Data("HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\n".utf8) + Data([255]), 0)
    }
    let auth = try LoopbackHTTPServer { _ in
      (self.response(headers: "WWW-Authenticate: Basic realm=\"test\"\r\n", status: "401 Unauthorized"), 0)
    }
    defer { invalid.stop(); auth.stop() }
    assertFailure(await send(FirstPartyHTTPClient(), invalid.url), .invalidResponse)
    assertFailure(await send(FirstPartyHTTPClient(), auth.url), .failed)
    XCTAssertEqual(auth.requests.count, 1)
  }

  func testRejectsUnsafeInputsBeforeNetworkUse() async throws {
    let server = try LoopbackHTTPServer { _ in (self.response(), 0) }
    defer { server.stop() }
    let client = FirstPartyHTTPClient()
    assertFailure(await send(client, server.url, allowHTTP: false), .invalidRequest)
    assertFailure(await send(client, "http://example.com/"), .invalidRequest)
    assertFailure(await send(client, server.url + "/#fragment"), .invalidRequest)
    assertFailure(await send(client, server.url, headers: ["Cookie": "secret"]), .invalidRequest)
    assertFailure(await send(client, server.url, headers: ["DPoP": "x\r\nInjected: true"]), .invalidRequest)
    XCTAssertEqual(server.requests.count, 0)
  }

  func testNativeTransactionUsesIndependentBoundedPKCEMaterial() {
    let first = FirstPartyCrypto.transaction()
    let second = FirstPartyCrypto.transaction()
    for field in ["id", "verifier", "challenge"] {
      XCTAssertNotNil(first[field]?.range(of: "^[A-Za-z0-9_-]{43}$", options: .regularExpression))
      XCTAssertNotEqual(first[field], second[field])
    }
    XCTAssertNotEqual(first["id"], first["verifier"])
    XCTAssertNotEqual(first["verifier"], first["challenge"])
  }
}
