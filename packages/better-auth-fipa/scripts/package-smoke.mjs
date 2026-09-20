import { execFileSync } from "node:child_process";
import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { execPath } from "node:process";
import { fileURLToPath } from "node:url";

const repository = dirname(dirname(fileURLToPath(import.meta.url)));
const temporaryDirectory = mkdtempSync(join(tmpdir(), "better-auth-fipa-"));

try {
  const packed = JSON.parse(
    execFileSync(
      "npm",
      ["pack", "--json", "--pack-destination", temporaryDirectory],
      { cwd: repository, encoding: "utf8" },
    ),
  );
  const filename = packed[0]?.filename;
  if (typeof filename !== "string") {
    throw new TypeError("npm pack did not return a package filename.");
  }

  const consumer = join(temporaryDirectory, "consumer");
  mkdirSync(consumer);
  writeFileSync(
    join(consumer, "package.json"),
    JSON.stringify({ name: "package-smoke", private: true, type: "module" }),
  );
  execFileSync(
    "npm",
    [
      "install",
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
      join(temporaryDirectory, filename),
    ],
    { cwd: consumer, stdio: "pipe" },
  );
  execFileSync(
    execPath,
    [
      "--input-type=module",
      "--eval",
      [
        'const server = await import("@eventyr-tech/better-auth-fipa");',
        'const client = await import("@eventyr-tech/better-auth-fipa/client");',
        'if (typeof server.appAttest !== "function") throw new TypeError("Missing appAttest export");',
        'if (typeof server.createDeviceAttestation !== "function") throw new TypeError("Missing createDeviceAttestation export");',
        'if (typeof client.deviceAttestationClient !== "function") throw new TypeError("Missing client export");',
      ].join("\n"),
    ],
    { cwd: consumer, stdio: "pipe" },
  );

  // The legacy root/client entries above must work without the optional peer.
  // The FiPA entry explicitly opts into the OAuth provider runtime.
  execFileSync(
    "npm",
    [
      "install",
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
      "@better-auth/oauth-provider@1.7.5",
    ],
    { cwd: consumer, stdio: "pipe" },
  );
  execFileSync(
    execPath,
    [
      "--input-type=module",
      "--eval",
      [
        'const native = await import("@eventyr-tech/better-auth-fipa/first-party");',
        'if (typeof native.androidHardware !== "function") throw new TypeError("Missing Android provider export");',
        'if (typeof native.resolveFirstPartyTokenContext !== "function") throw new TypeError("Missing first-party claims resolver export");',
        'if (typeof native.createNativeFirstPartyPlugin !== "function" || typeof native.requireNativeAccess !== "function") throw new TypeError("Missing first-party exports");',
      ].join("\n"),
    ],
    { cwd: consumer, stdio: "pipe" },
  );
  execFileSync(
    execPath,
    [
      "--input-type=commonjs",
      "--eval",
      [
        'require.resolve("@eventyr-tech/better-auth-fipa");',
        'require.resolve("@eventyr-tech/better-auth-fipa/client");',
      ].join("\n"),
    ],
    { cwd: consumer, stdio: "pipe" },
  );

  const installedPackage = JSON.parse(
    readFileSync(
      join(
        consumer,
        "node_modules",
        "@eventyr-tech",
        "better-auth-fipa",
        "package.json",
      ),
      "utf8",
    ),
  );
  if (installedPackage.name !== "@eventyr-tech/better-auth-fipa") {
    throw new TypeError("Installed package metadata is invalid.");
  }
} finally {
  rmSync(temporaryDirectory, { recursive: true, force: true });
}
