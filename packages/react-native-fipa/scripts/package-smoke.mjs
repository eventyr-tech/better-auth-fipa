import { execFileSync } from "node:child_process";
import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const directory = fileURLToPath(new URL("..", import.meta.url));
const temporary = mkdtempSync(join(tmpdir(), "native-attestation-pack-"));
try {
  const [packed] = JSON.parse(
    execFileSync("npm", ["pack", "--json", "--pack-destination", temporary], {
      cwd: directory,
      encoding: "utf8",
    }),
  );
  const files = new Set(packed.files.map((file) => file.path));
  for (const required of [
    "DeviceAttestation.podspec",
    "android/build.gradle",
    "android/settings.gradle",
    "android/src/main/AndroidManifest.xml",
    "android/src/main/java/com/deviceattestation/AndroidAttestedKey.kt",
    "android/src/main/java/com/deviceattestation/FirstPartyCrypto.kt",
    "android/src/main/java/com/deviceattestation/StandardIntegrityCoordinator.kt",
    "android/src/main/java/com/deviceattestation/AndroidPlayIntegrity.kt",
    "android/src/main/java/com/deviceattestation/DeviceAttestationAndroidIntegrity.kt",
    "android/src/main/java/com/deviceattestation/DeviceAttestationPackage.kt",
    "android/src/main/java/com/deviceattestation/SessionVault.kt",
    "android/src/main/java/com/deviceattestation/VaultRecord.kt",
    "android/src/main/java/com/deviceattestation/EncryptedVaultStorage.kt",
    "android/src/main/java/com/deviceattestation/AndroidVaultStorage.kt",
    "android/src/main/java/com/deviceattestation/DeviceAttestationSessionVault.kt",
    "android/src/main/java/com/deviceattestation/FirstPartyHTTP.kt",
    "android/src/main/java/com/deviceattestation/DeviceAttestationFirstPartyTransport.kt",
    "android/src/main/java/com/deviceattestation/FirstPartyBrowserCoordinator.kt",
    "android/src/main/java/com/deviceattestation/AndroidFirstPartyBrowser.kt",
    "android/src/main/java/com/deviceattestation/FirstPartyBrowserActivity.kt",
    "ios/DeviceAttestationBridge.mm",
    "ios/DeviceAttestationAppAttest.swift",
    "ios/AppAttestKeyStore.swift",
    "ios/AppAttestKeyCoordinator.swift",
    "ios/SessionVault.swift",
    "ios/KeychainSessionVaultStorage.swift",
    "ios/DeviceAttestationSessionVault.swift",
    "ios/SessionVaultBridge.mm",
    "ios/FirstPartyHTTP.swift",
    "ios/FirstPartyCrypto.swift",
    "ios/FirstPartyBrowser.swift",
    "ios/FirstPartyDpopKey.swift",
    "ios/DeviceAttestationFirstPartyTransport.swift",
    "ios/FirstPartyTransportBridge.mm",
    "src/NativeFirstPartyTransport.ts",
    "src/NativeAndroidIntegrity.ts",
    "src/NativeAndroidVaultRecovery.ts",
    "android/src/main/java/com/deviceattestation/VaultRecovery.kt",
    "android/src/main/java/com/deviceattestation/DeviceAttestationAndroidVaultRecovery.kt",
    "dist/first-party/android-storage-recovery.js",
    "src/NativeSessionVault.ts",
    "src/NativeDeviceAttestation.ts",
    "dist/index.d.ts",
    "dist/core.js",
    "dist/first-party.js",
    "dist/first-party.d.ts",
    "src/first-party.ts",
    "dist/first-party/native-client.js",
    "dist/first-party/android-keys.js",
    "dist/first-party/android-client.js",
    "dist/first-party/native-lifecycle.js",
    "dist/first-party/ios-retained-keys.js",
    "dist/first-party/account-catalog.js",
    "src/first-party/native-client.ts",
    "src/first-party/ios-retained-keys.ts",
    "react-native.config.cjs",
  ]) {
    if (!files.has(required))
      throw new Error(`Native package is missing ${required}`);
  }
  if (
    [...files].some(
      (file) => file.endsWith(".test.ts") || file.includes("/test-fixtures/"),
    )
  )
    throw new Error("Tests leaked into the native package.");
  if (
    [...files].some((file) =>
      /android\/(build|\.gradle|src\/test)\//.test(file),
    )
  )
    throw new Error("Android build output or tests leaked into the package.");
  const consumer = join(temporary, "consumer");
  mkdirSync(consumer);
  writeFileSync(
    join(consumer, "package.json"),
    JSON.stringify({
      name: "native-package-consumer",
      private: true,
      type: "module",
    }),
  );
  execFileSync(
    "npm",
    [
      "install",
      "--ignore-scripts",
      "--legacy-peer-deps",
      "--no-audit",
      "--no-fund",
      join(temporary, packed.filename),
    ],
    { cwd: consumer, stdio: "pipe" },
  );
  execFileSync(
    process.execPath,
    [
      "--input-type=module",
      "--eval",
      'const core = await import("@eventyr-tech/react-native-fipa/core"); if (typeof core.createAppAttestClient !== "function" || typeof core.createDpopClient !== "function") throw new Error("Missing core exports");',
    ],
    { cwd: consumer, stdio: "pipe" },
  );
  const metadata = JSON.parse(
    readFileSync(
      join(
        consumer,
        "node_modules/@eventyr-tech/react-native-fipa/package.json",
      ),
      "utf8",
    ),
  );
  if (
    metadata.codegenConfig.jsSrcsDir !== "src" ||
    metadata.exports["."].types !== "./dist/index.d.ts" ||
    metadata.exports["./first-party"].types !== "./dist/first-party.d.ts" ||
    metadata.exports["./first-party"]["react-native"] !== "./src/first-party.ts"
  )
    throw new Error("Invalid native package entry points.");
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
