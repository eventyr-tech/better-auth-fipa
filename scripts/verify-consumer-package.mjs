import { execFileSync } from "node:child_process";
import {
  cpSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const consumer = mkdtempSync(join(tmpdir(), "fipa-consumer-"));
const server = join(root, "packages/better-auth-fipa");
const native = join(root, "packages/react-native-fipa");
const manifest = JSON.parse(readFileSync(join(server, "package.json"), "utf8"));
const nativeManifest = JSON.parse(
  readFileSync(join(native, "package.json"), "utf8"),
);
const published = process.argv.includes("--published");
const testArguments = process.argv
  .slice(2)
  .filter((arg) => arg !== "--published");
const run = (command, args, cwd = consumer) =>
  execFileSync(command, args, {
    cwd,
    stdio: "inherit",
    env: process.env,
  });
function pack(directory) {
  const [result] = JSON.parse(
    execFileSync("npm", ["pack", "--json", "--pack-destination", consumer], {
      cwd: directory,
      encoding: "utf8",
    }),
  );
  return `file:./${result.filename}`;
}

try {
  // Use the same committed dependency patch as workspace CI and consumers.
  // pnpm applies it during installation; there is no test-only adapter shim.
  cpSync(
    join(root, "pnpm-workspace.yaml"),
    join(consumer, "pnpm-workspace.yaml"),
  );
  cpSync(join(root, "patches"), join(consumer, "patches"), { recursive: true });
  writeFileSync(
    join(consumer, "package.json"),
    JSON.stringify(
      {
        name: "fipa-release-consumer",
        private: true,
        type: "module",
        packageManager: "pnpm@10.34.5",
        dependencies: {
          ...manifest.dependencies,
          ...manifest.devDependencies,
          // The test runner and coverage provider require matching versions.
          vitest: manifest.devDependencies["@vitest/coverage-v8"],
          "@eventyr-tech/better-auth-fipa": published
            ? manifest.version
            : pack(server),
          "@eventyr-tech/react-native-fipa": published
            ? nativeManifest.version
            : pack(native),
          react: "19.2.3",
          "react-native": "0.86.0",
          "react-native-dpop": "1.0.0",
        },
      },
      null,
      2,
    ),
  );
  run("pnpm", ["install", "--ignore-scripts", "--no-frozen-lockfile"]);
  // The release carries the exact workaround consumers must install themselves.
  const patchName = "@better-auth__drizzle-adapter@1.7.5.patch";
  if (
    !readFileSync(join(root, "patches", patchName)).equals(
      readFileSync(
        join(
          consumer,
          "node_modules/@eventyr-tech/better-auth-fipa/docs",
          patchName,
        ),
      ),
    )
  )
    throw new Error(
      "Published compatibility patch does not match the validated patch",
    );
  run(process.execPath, [
    "--input-type=module",
    "--eval",
    `
    const server = await import('@eventyr-tech/better-auth-fipa');
    const firstParty = await import('@eventyr-tech/better-auth-fipa/first-party');
    const client = await import('@eventyr-tech/better-auth-fipa/client');
    for (const fn of [server.createDeviceAttestation, firstParty.createNativeFirstPartyPlugin,
      firstParty.requireNativeAccess, firstParty.requireLegacyAccess,
      firstParty.resolveFirstPartyTokenContext, client.deviceAttestationClient]) {
      if (typeof fn !== 'function') throw new Error('Missing public consumer export');
    }
  `,
  ]);
  writeFileSync(
    join(consumer, "consumer.ts"),
    `
    import { createNativeFirstPartyPlugin, resolveFirstPartyTokenContext } from '@eventyr-tech/better-auth-fipa/first-party';
    import { createNativeFirstPartyClient, type NativeFirstPartyClient } from '@eventyr-tech/react-native-fipa/first-party';
    const client: NativeFirstPartyClient = createNativeFirstPartyClient({
      issuer: 'https://example.test/api/auth', clientId: 'eventyr_mobile',
      applicationId: 'TEAM.io.example.consumer', environment: 'production',
      scopes: ['offline_access'], resources: [],
      browser: { redirectUri: 'example:/callback' },
    });
    void [client, createNativeFirstPartyPlugin, resolveFirstPartyTokenContext];
  `,
  );
  run("npx", [
    "--no-install",
    "tsc",
    "--noEmit",
    "--strict",
    "--skipLibCheck",
    "--module",
    "NodeNext",
    "--moduleResolution",
    "NodeNext",
    "--target",
    "ES2023",
    "consumer.ts",
  ]);

  // Test only bytes from the installed tarball. Copying dist beside the test
  // harness permits existing relative internal-contract imports; no production
  // .ts source or workspace node_modules is copied into this consumer.
  cpSync(
    join(consumer, "node_modules/@eventyr-tech/better-auth-fipa/dist"),
    join(consumer, "src"),
    { recursive: true },
  );
  function copyTests(directory) {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      const name = relative(join(server, "src"), path);
      if (entry.isDirectory()) copyTests(path);
      else if (
        name.endsWith(".test.ts") ||
        name.split("/").includes("fixtures")
      ) {
        cpSync(path, join(consumer, "src", name), { recursive: true });
      }
    }
  }
  copyTests(join(server, "src"));
  for (const config of [
    "vitest.config.postgres.ts",
    "vitest.config.drizzle.ts",
  ])
    cpSync(join(server, config), join(consumer, config));
  run("npx", [
    "--no-install",
    "vitest",
    "run",
    "--config",
    "vitest.config.drizzle.ts",
    ...testArguments,
  ]);
  console.log(
    `${published ? "Published" : "Packed"} package pair, declarations, and patched Drizzle contracts passed. Artifacts: ${consumer}`,
  );
} catch (error) {
  console.error(`Consumer retained for diagnosis: ${consumer}`);
  throw error;
}
