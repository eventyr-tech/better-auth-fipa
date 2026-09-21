// swift-tools-version: 5.9
import PackageDescription
let package = Package(
  name: "AppAttestStorage",
  platforms: [.macOS(.v12)],
  products: [.library(name: "AppAttestStorage", targets: ["AppAttestStorage"])],
  targets: [
    .target(name: "AppAttestStorage", path: "ios", exclude: ["DeviceAttestationIOSSimulator.swift", "IOSSimulatorBridge.mm", "DeviceAttestationAppAttest.swift", "DeviceAttestationBridge.mm", "DeviceAttestationSessionVault.swift", "SessionVaultBridge.mm", "DeviceAttestationFirstPartyTransport.swift", "FirstPartyTransportBridge.mm", "FirstPartyBrowser.swift"], sources: ["AppAttestKeyStore.swift", "AppAttestKeyCoordinator.swift", "SessionVault.swift", "KeychainSessionVaultStorage.swift", "FirstPartyHTTP.swift", "FirstPartyLocalOrigin.swift", "FirstPartyCrypto.swift", "FirstPartyDpopKey.swift", "FirstPartySimulatorKey.swift"]),
    .testTarget(name: "AppAttestStorageTests", dependencies: ["AppAttestStorage"], path: "Tests/AppAttestStorageTests")
  ]
)
