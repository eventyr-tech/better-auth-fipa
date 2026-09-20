import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { consumerRunner, prepareExampleConsumer } from "./packed-consumer.mjs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

// Separate tarball installation: test the real consumer's native autolinking,
// not a library-only Gradle build. The generated test key is not a Play signer.
const root = fileURLToPath(new URL("..", import.meta.url));
const temporary = mkdtempSync(join(tmpdir(), "attestation-android-app-"));
const run = consumerRunner(temporary);

try {
  prepareExampleConsumer(root, temporary, "android");
  run(
    "./gradlew",
    [
      "--no-daemon",
      "--max-workers=2",
      ":app:assembleRelease",
      "-PreactNativeArchitectures=arm64-v8a",
    ],
    join(temporary, "android"),
  );
  // Assembly must actually package this library's autolinked module.
  const autolinking = readFileSync(
    join(
      temporary,
      "android/app/build/generated/autolinking/src/main/java/com/facebook/react/PackageList.java",
    ),
    "utf8",
  );
  if (
    !/\bnew\s+(?:com\.deviceattestation\.)?DeviceAttestationPackage\s*\(/u.test(
      autolinking,
    )
  )
    throw new Error("Android consumer omitted the attestation native package.");
  const apk = readFileSync(
    join(temporary, "android/app/build/outputs/apk/release/app-release.apk"),
  );
  if (apk.length < 1024)
    throw new Error("Android consumer did not produce an APK.");
  rmSync(temporary, { recursive: true, force: true });
  console.log(
    "Packed Android reference app passed types, Metro, Codegen, autolinking and arm64 APK assembly with the generated test signing key. No Play distribution or physical-device claim.",
  );
} catch (error) {
  console.error(`Packed Android app retained for diagnosis at ${temporary}`);
  throw error;
}
