import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

// This compiles the packed native library. Full APK/device checks remain a
// separate gate for reference-app integration and physical-device acceptance.
const root = fileURLToPath(new URL("..", import.meta.url));
const temporary = mkdtempSync(join(tmpdir(), "attestation-android-consumer-"));
try {
  const directory = join(root, "packages/react-native-fipa");
  const manifest = JSON.parse(
    readFileSync(join(directory, "package.json"), "utf8"),
  );
  const [packed] = JSON.parse(
    execFileSync("npm", ["pack", "--json", "--pack-destination", temporary], {
      cwd: directory,
      encoding: "utf8",
    }),
  );
  writeFileSync(
    join(temporary, "package.json"),
    JSON.stringify({
      name: "android-packed-library-consumer",
      private: true,
      dependencies: {
        [manifest.name]: `file:./${packed.filename}`,
        "react-native": manifest.devDependencies["react-native"],
        react: manifest.devDependencies.react,
        "react-native-dpop": manifest.devDependencies["react-native-dpop"],
      },
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
    ],
    { cwd: temporary, stdio: "inherit" },
  );
  execFileSync(
    process.env.DEVICE_ATTESTATION_GRADLE ?? "gradle",
    ["--no-daemon", "--max-workers=2", "assembleDebug", "lintDebug"],
    {
      cwd: join(temporary, "node_modules", manifest.name, "android"),
      stdio: "inherit",
    },
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
