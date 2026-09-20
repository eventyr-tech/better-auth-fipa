import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

// Toolchain installation is explicit: use JDK 17+, SDK 36/build-tools 36.0.0,
// and Gradle 8.14.3 (matching the current AGP 8.12 baseline).
execFileSync(
  process.env.DEVICE_ATTESTATION_GRADLE ?? "gradle",
  [
    "--no-daemon",
    "--max-workers=2",
    "testDebugUnitTest",
    "assembleDebug",
    "lintDebug",
  ],
  {
    cwd: fileURLToPath(new URL("../android", import.meta.url)),
    stdio: "inherit",
  },
);
