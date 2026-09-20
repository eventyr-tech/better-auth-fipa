import { execFileSync } from "node:child_process";
import { cpSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

// Each caller owns its temporary directory, native build, assertions and cleanup.
export function consumerRunner(directory) {
  return (command, args, cwd = directory) =>
    execFileSync(command, args, { cwd, stdio: "inherit" });
}

export function packNativePackage(root, directory) {
  const source = join(root, "packages/react-native-fipa");
  const manifest = JSON.parse(
    readFileSync(join(source, "package.json"), "utf8"),
  );
  const [packed] = JSON.parse(
    execFileSync("npm", ["pack", "--json", "--pack-destination", directory], {
      cwd: source,
      encoding: "utf8",
    }),
  );
  return { manifest, filename: packed.filename };
}

export function prepareExampleConsumer(root, directory, platform) {
  const { manifest: library, filename } = packNativePackage(root, directory);
  const example = join(root, "apps/example-mobile");
  for (const file of [
    "App.tsx",
    "app.config.js",
    "index.js",
    "metro.config.cjs",
    "tsconfig.json",
  ])
    cpSync(join(example, file), join(directory, file));
  const manifest = JSON.parse(
    readFileSync(join(example, "package.json"), "utf8"),
  );
  manifest.dependencies[library.name] = `file:./${filename}`;
  manifest.packageManager = "pnpm@10.34.5";
  writeFileSync(
    join(directory, "package.json"),
    JSON.stringify(manifest, null, 2),
  );
  writeFileSync(
    join(directory, "pnpm-workspace.yaml"),
    "onlyBuiltDependencies:\n  - esbuild\n",
  );
  const run = consumerRunner(directory);
  run("pnpm", ["install", "--ignore-workspace", "--no-frozen-lockfile"]);
  run("pnpm", ["exec", "tsc", "--noEmit"]);
  run("pnpm", ["exec", "expo", "export", "--platform", platform]);
  run("pnpm", [
    "exec",
    "expo",
    "prebuild",
    "--platform",
    platform,
    "--no-install",
  ]);
}
