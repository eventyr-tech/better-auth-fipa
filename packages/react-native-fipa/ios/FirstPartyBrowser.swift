import AuthenticationServices
import Foundation
import UIKit

/// One external authentication presentation per app process, across JS bridges.
/// User interaction never holds a session-vault lease.
@MainActor
final class FirstPartyBrowser: NSObject, ASWebAuthenticationPresentationContextProviding {
  static let shared = FirstPartyBrowser()
  private var active: (id: String, session: ASWebAuthenticationSession, anchor: UIWindow,
                       timeout: DispatchWorkItem, complete: (Result<String, BrowserError>) -> Void)?
  private var cancelled: [String: Date] = [:]
  private var rejectUntil = Date.distantPast
  enum BrowserError: String, Error {
    case cancelled = "browser_cancelled"
    case busy = "browser_busy"
    case unavailable = "browser_unavailable"
    case failed = "browser_failed"
  }

  func open(id: String, url: String, redirectUri: String, timeoutMilliseconds: Double,
            allowInsecureLoopback: Bool, complete: @escaping (Result<String, BrowserError>) -> Void) {
    cancelled = cancelled.filter { $0.value > Date() }
    if cancelled.removeValue(forKey: id) != nil || rejectUntil > Date() { complete(.failure(.cancelled)); return }
    guard active == nil else { complete(.failure(.busy)); return }
    guard id.range(of: "^[A-Za-z0-9_-]{43}$", options: .regularExpression) != nil,
          timeoutMilliseconds.isFinite, timeoutMilliseconds >= 1, timeoutMilliseconds <= 300_000,
          url.utf8.count <= 8192, redirectUri.utf8.count <= 2048,
          let authorization = URL(string: url), let callback = URL(string: redirectUri),
          let callbackScheme = callback.scheme, !callbackScheme.isEmpty,
          !["http", "javascript", "data", "file", "about"].contains(callbackScheme),
          callback.user == nil, callback.password == nil, callback.fragment == nil,
          authorization.user == nil, authorization.password == nil, authorization.fragment == nil,
          authorization.scheme == "https" || (allowInsecureLoopback && authorization.scheme == "http" &&
            FirstPartyLocalOrigin.contains(authorization.host ?? "")),
          let window = UIApplication.shared.connectedScenes.compactMap({ $0 as? UIWindowScene })
            .filter({ $0.activationState == .foregroundActive }).flatMap({ $0.windows }).first(where: { $0.isKeyWindow })
    else { complete(.failure(.unavailable)); return }
    let completion: ASWebAuthenticationSession.CompletionHandler = { [weak self] callbackURL, error in
      DispatchQueue.main.async {
        guard let self else { return }
        if let callbackURL, error == nil { self.finish(id, .success(callbackURL.absoluteString)) }
        else if let error = error as? ASWebAuthenticationSessionError, error.code == .canceledLogin {
          self.finish(id, .failure(.cancelled))
        } else { self.finish(id, .failure(.failed)) }
      }
    }
    let session: ASWebAuthenticationSession
    if callbackScheme == "https" {
      guard #available(iOS 17.4, *), let host = callback.host, callback.port == nil else {
        complete(.failure(.unavailable)); return
      }
      session = ASWebAuthenticationSession(url: authorization, callback: .https(host: host, path: callback.path), completionHandler: completion)
    } else {
      session = ASWebAuthenticationSession(url: authorization, callbackURLScheme: callbackScheme, completionHandler: completion)
    }
    session.presentationContextProvider = self
    session.prefersEphemeralWebBrowserSession = true
    let timeout = DispatchWorkItem { [weak self] in self?.cancel(id: id) }
    active = (id, session, window, timeout, complete)
    if !session.start() { finish(id, .failure(.unavailable)); return }
    DispatchQueue.main.asyncAfter(deadline: .now() + timeoutMilliseconds / 1000, execute: timeout)
  }

  func cancel(id: String) {
    if let held = active, held.id == id {
      finish(id, .failure(.cancelled))
      held.session.cancel()
      return
    }
    cancelled = cancelled.filter { $0.value > Date() }
    if cancelled.count >= 128 { rejectUntil = Date().addingTimeInterval(300); return }
    cancelled[id] = Date().addingTimeInterval(300)
  }
  private func finish(_ id: String, _ result: Result<String, BrowserError>) {
    guard let held = active, held.id == id else { return }
    active = nil
    held.timeout.cancel()
    held.complete(result)
  }
  func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
    // The active tuple is installed before start(), which asks for this anchor.
    guard let held = active, held.session === session else { return ASPresentationAnchor() }
    return held.anchor
  }
}
