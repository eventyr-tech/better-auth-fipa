import Foundation

enum FirstPartyHTTPError: String, Error {
  case invalidRequest = "http_invalid_request"
  case invalidResponse = "http_invalid_response"
  case redirect = "http_redirect_rejected"
  case tooLarge = "http_response_too_large"
  case cancelled = "http_cancelled"
  case unavailable = "http_unavailable"
  case failed = "http_failed"
}

struct FirstPartyHTTPResponse {
  let url: String
  let status: Int
  let headers: [String: String]
  let body: String
}

/// Isolated foreground transport. Each request has its own ephemeral session,
/// no ambient cookies/credentials/cache, no redirects and bounded response data.
final class FirstPartyHTTPClient {
  private let queue = DispatchQueue(label: "DeviceAttestation.HTTP")
  private var active: [String: FirstPartyHTTPExchange] = [:]
  private var cancelled: [String: Date] = [:]
  private var rejectNewUntil = Date.distantPast

  func send(id: String, url: String, method: String, headers: [String: String], body: String?,
            maximumResponseBytes: Int, timeoutMilliseconds: Int, allowInsecureLoopback: Bool,
            completion: @escaping (Result<FirstPartyHTTPResponse, FirstPartyHTTPError>) -> Void) {
    queue.async {
      self.cancelled = self.cancelled.filter { $0.value > Date() }
      guard self.rejectNewUntil <= Date() else { completion(.failure(.cancelled)); return }
      if self.cancelled.removeValue(forKey: id) != nil { completion(.failure(.cancelled)); return }
      guard self.active[id] == nil, self.active.count < 32 else { completion(.failure(.unavailable)); return }
      do {
        let request = try Self.request(id: id, url: url, method: method, headers: headers, body: body,
          maximumResponseBytes: maximumResponseBytes, timeoutMilliseconds: timeoutMilliseconds,
          allowInsecureLoopback: allowInsecureLoopback)
        let exchange = FirstPartyHTTPExchange(request: request, maximumBytes: maximumResponseBytes,
          timeout: Double(timeoutMilliseconds) / 1000, queue: self.queue) { result in
            self.active.removeValue(forKey: id)
            completion(result)
          }
        self.active[id] = exchange
        exchange.start()
      } catch { completion(.failure(.invalidRequest)) }
    }
  }

  func cancel(id: String) {
    queue.async {
      if let exchange = self.active[id] { exchange.cancel(); return }
      // A bridge cancellation may arrive before send. Retain bounded tombstones
      // rather than starting a request after its JS caller has already cancelled.
      self.cancelled = self.cancelled.filter { $0.value > Date() }
      guard id.range(of: "^[A-Za-z0-9_-]{43}$", options: .regularExpression) != nil else { return }
      guard self.cancelled.count < 128 else {
        self.rejectNewUntil = Date().addingTimeInterval(120)
        return
      }
      self.cancelled[id] = Date().addingTimeInterval(120)
    }
  }

  private static func request(id: String, url: String, method: String, headers: [String: String], body: String?,
                              maximumResponseBytes: Int, timeoutMilliseconds: Int,
                              allowInsecureLoopback: Bool) throws -> URLRequest {
    guard id.range(of: "^[A-Za-z0-9_-]{43}$", options: .regularExpression) != nil,
          url.utf8.count <= 8192, let parts = URLComponents(string: url),
          parts.user == nil, parts.password == nil, parts.fragment == nil,
          let host = parts.host, !host.isEmpty,
          parts.scheme == "https" || (allowInsecureLoopback && parts.scheme == "http" &&
            ["localhost", "127.0.0.1", "::1", "[::1]"].contains(host.lowercased())),
          ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"].contains(method),
          maximumResponseBytes > 0, maximumResponseBytes <= 1_048_576,
          timeoutMilliseconds >= 1000, timeoutMilliseconds <= 120_000,
          (body?.utf8.count ?? 0) <= 2_097_152,
          !(body != nil && ["GET", "HEAD"].contains(method)) else { throw FirstPartyHTTPError.invalidRequest }
    var normalized = parts
    if normalized.percentEncodedPath.isEmpty { normalized.percentEncodedPath = "/" }
    guard let endpoint = normalized.url else { throw FirstPartyHTTPError.invalidRequest }
    var request = URLRequest(url: endpoint, cachePolicy: .reloadIgnoringLocalCacheData,
                             timeoutInterval: Double(timeoutMilliseconds) / 1000)
    request.httpMethod = method
    request.httpBody = body.map { Data($0.utf8) }
    request.httpShouldHandleCookies = false
    let forbidden = Set(["host", "cookie", "cookie2", "connection", "transfer-encoding", "content-length", "proxy-authorization"])
    var headerBytes = 0
    var names = Set<String>()
    for (name, value) in headers {
      let normalized = name.lowercased()
      headerBytes += name.utf8.count + value.utf8.count
      guard headerBytes <= 16384, !forbidden.contains(normalized), names.insert(normalized).inserted,
            name.range(of: "^[!#$%&'*+.^_`|~0-9A-Za-z-]+$", options: .regularExpression) != nil,
            !value.unicodeScalars.contains(where: { $0.value < 32 || $0.value == 127 }) else {
        throw FirstPartyHTTPError.invalidRequest
      }
      request.setValue(value, forHTTPHeaderField: name)
    }
    return request
  }
}

private final class FirstPartyHTTPExchange: NSObject, URLSessionDataDelegate, @unchecked Sendable {
  private let request: URLRequest
  private let maximumBytes: Int
  private let timeout: Double
  private let queue: DispatchQueue
  private let completion: (Result<FirstPartyHTTPResponse, FirstPartyHTTPError>) -> Void
  private var session: URLSession?
  private var task: URLSessionDataTask?
  private var response: HTTPURLResponse?
  private var bytes = Data()
  private var finished = false

  init(request: URLRequest, maximumBytes: Int, timeout: Double, queue: DispatchQueue,
       completion: @escaping (Result<FirstPartyHTTPResponse, FirstPartyHTTPError>) -> Void) {
    self.request = request; self.maximumBytes = maximumBytes; self.timeout = timeout
    self.queue = queue; self.completion = completion
  }
  func start() {
    let configuration = URLSessionConfiguration.ephemeral
    configuration.httpCookieStorage = nil
    configuration.httpShouldSetCookies = false
    configuration.httpCookieAcceptPolicy = .never
    configuration.urlCredentialStorage = nil
    configuration.urlCache = nil
    configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
    configuration.timeoutIntervalForRequest = timeout
    configuration.timeoutIntervalForResource = timeout
    configuration.waitsForConnectivity = false
    let delegates = OperationQueue()
    delegates.maxConcurrentOperationCount = 1
    delegates.underlyingQueue = queue
    let session = URLSession(configuration: configuration, delegate: self, delegateQueue: delegates)
    self.session = session
    let task = session.dataTask(with: request)
    self.task = task
    task.resume()
  }
  func cancel() { finish(.failure(.cancelled)) }

  func urlSession(_ session: URLSession, task: URLSessionTask,
                  willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest,
                  completionHandler: @escaping (URLRequest?) -> Void) {
    completionHandler(nil)
    finish(.failure(.redirect))
  }
  func urlSession(_ session: URLSession, task: URLSessionTask, didReceive challenge: URLAuthenticationChallenge,
                  completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
    if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust {
      // System certificate/hostname validation. Never install a permissive trust
      // callback, supply a trust credential, or prompt for ambient credentials.
      completionHandler(.performDefaultHandling, nil)
    } else { completionHandler(.cancelAuthenticationChallenge, nil) }
  }
  func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse,
                  completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
    guard !finished, let http = response as? HTTPURLResponse else {
      completionHandler(.cancel); finish(.failure(.invalidResponse)); return
    }
    guard !(300..<400).contains(http.statusCode) else {
      completionHandler(.cancel); finish(.failure(.redirect)); return
    }
    guard http.expectedContentLength <= Int64(maximumBytes) else {
      completionHandler(.cancel); finish(.failure(.tooLarge)); return
    }
    guard http.url == request.url, http.allHeaderFields.reduce(0, { $0 + String(describing: $1.key).utf8.count + String(describing: $1.value).utf8.count }) <= 16384 else {
      completionHandler(.cancel); finish(.failure(.invalidResponse)); return
    }
    self.response = http
    completionHandler(.allow)
  }
  func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
    guard !finished else { return }
    guard data.count <= maximumBytes - bytes.count else { finish(.failure(.tooLarge)); return }
    bytes.append(data)
  }
  func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
    guard !finished else { return }
    guard error == nil else { finish(.failure(.failed)); return }
    guard let response, let url = response.url?.absoluteString,
          let body = String(data: bytes, encoding: .utf8) else { finish(.failure(.invalidResponse)); return }
    var headers: [String: String] = [:]
    for (name, value) in response.allHeaderFields {
      let name = String(describing: name).lowercased()
      if name != "set-cookie" && name != "set-cookie2" { headers[name] = String(describing: value) }
    }
    finish(.success(FirstPartyHTTPResponse(url: url, status: response.statusCode, headers: headers, body: body)))
  }
  func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, willCacheResponse proposedResponse: CachedURLResponse,
                  completionHandler: @escaping (CachedURLResponse?) -> Void) { completionHandler(nil) }

  private func finish(_ result: Result<FirstPartyHTTPResponse, FirstPartyHTTPError>) {
    guard !finished else { return }
    finished = true
    task?.cancel()
    session?.invalidateAndCancel()
    task = nil; session = nil; bytes.removeAll()
    completion(result)
  }
}
