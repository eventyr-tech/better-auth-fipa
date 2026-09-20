import { consumerRunner, packNativePackage } from "./packed-consumer.mjs";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

// This compiles the packed native library. Full APK/device checks remain a
// separate gate for reference-app integration and physical-device acceptance.
const root = fileURLToPath(new URL("..", import.meta.url));
const temporary = mkdtempSync(join(tmpdir(), "attestation-android-consumer-"));
const run = consumerRunner(temporary);
try {
  const { manifest, filename } = packNativePackage(root, temporary);
  writeFileSync(
    join(temporary, "package.json"),
    JSON.stringify({
      name: "android-packed-library-consumer",
      private: true,
      dependencies: {
        [manifest.name]: `file:./${filename}`,
        "react-native": manifest.devDependencies["react-native"],
        react: manifest.devDependencies.react,
        "react-native-dpop": manifest.devDependencies["react-native-dpop"],
      },
    }),
  );
  run("npm", [
    "install",
    "--ignore-scripts",
    "--legacy-peer-deps",
    "--no-audit",
    "--no-fund",
  ]);
  run(
    process.env.DEVICE_ATTESTATION_GRADLE ?? "gradle",
    ["--no-daemon", "--max-workers=2", "assembleDebug", "lintDebug"],
    join(temporary, "node_modules", manifest.name, "android"),
  );
  rmSync(temporary, { recursive: true, force: true });
  console.log(
    "Packed Android native library passed Codegen, Kotlin/Java compilation, AAR assembly and lint. No APK or physical-device claim.",
  );
} catch (error) {
  console.error(
    `Packed Android consumer retained for diagnosis at ${temporary}`,
  );
  throw error;
}
