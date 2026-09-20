import { execFileSync } from "node:child_process";
import {
  cpSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

// A separate installation catches missing published files and workspace-only resolution.
if (process.platform !== "darwin")
  throw new Error("iOS validation requires macOS and Xcode.");
const root = fileURLToPath(new URL("..", import.meta.url));
const temporary = mkdtempSync(join(tmpdir(), "attestation-ios-consumer-"));
const example = join(root, "apps/example-mobile");
const run = (command, args, cwd = temporary) =>
  execFileSync(command, args, { cwd, stdio: "inherit" });

try {
  const [packed] = JSON.parse(
    execFileSync("npm", ["pack", "--json", "--pack-destination", temporary], {
      cwd: join(root, "packages/react-native-fipa"),
      encoding: "utf8",
    }),
  );
  for (const file of [
    "App.tsx",
    "app.config.js",
    "index.js",
    "metro.config.cjs",
    "tsconfig.json",
  ])
    cpSync(join(example, file), join(temporary, file));
  const manifest = JSON.parse(
    readFileSync(join(example, "package.json"), "utf8"),
  );
  manifest.dependencies["@eventyr-tech/react-native-fipa"] =
    `file:./${packed.filename}`;
  manifest.packageManager = "pnpm@10.34.5";
  writeFileSync(
    join(temporary, "package.json"),
    JSON.stringify(manifest, null, 2),
  );
  writeFileSync(
    join(temporary, "pnpm-workspace.yaml"),
    "onlyBuiltDependencies:\n  - esbuild\n",
  );
  run("pnpm", ["install", "--ignore-workspace", "--no-frozen-lockfile"]);
  run("pnpm", ["exec", "tsc", "--noEmit"]);
  run("pnpm", ["exec", "expo", "export", "--platform", "ios"]);
  run("pnpm", [
    "exec",
    "expo",
    "prebuild",
    "--platform",
    "ios",
    "--no-install",
  ]);
  run("pod", ["install"], join(temporary, "ios"));
  run(
    "xcodebuild",
    [
      "-workspace",
      "AttestationExample.xcworkspace",
      "-scheme",
      "AttestationExample",
      "-configuration",
      "Debug",
      "-destination",
      "generic/platform=iOS",
      "-derivedDataPath",
      join(temporary, "build"),
      "CODE_SIGNING_ALLOWED=NO",
      "build",
    ],
    join(temporary, "ios"),
  );
  rmSync(temporary, { recursive: true, force: true });
  console.log(
    "Packed iOS consumer passed types, Metro, autolinking, Codegen, and device compilation.",
  );
} catch (error) {
  console.error(`Packed iOS consumer retained for diagnosis at ${temporary}`);
  throw error;
}
