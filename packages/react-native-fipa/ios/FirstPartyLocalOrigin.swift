import Foundation

/// Receives a parsed hostname, never an authority or an unparsed URL.
enum FirstPartyLocalOrigin {
  static func contains(_ hostname: String) -> Bool {
    let host = hostname.lowercased()
    if ["127.0.0.1", "::1", "[::1]"].contains(host) { return true }
    let name = host.hasSuffix(".") ? String(host.dropLast()) : host
    guard name.utf8.count <= 253 else { return false }
    let labels = name.split(separator: ".", omittingEmptySubsequences: false)
    return labels.last == "localhost" && labels.allSatisfy {
      $0.range(of: "^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", options: .regularExpression) != nil
    }
  }
}
