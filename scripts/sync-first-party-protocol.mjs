import { readFileSync, writeFileSync } from "node:fs";
const root = new URL("../", import.meta.url);
const source = readFileSync(
  new URL("protocol/first-party-binding.ts", root),
  "utf8",
);
const output =
  "// Generated from protocol/first-party-binding.ts. Do not edit directly.\n" +
  source;
for (const name of ["better-auth-fipa", "react-native-fipa"]) {
  const target = new URL(
    `packages/${name}/src/first-party/binding-fields.ts`,
    root,
  );
  if (process.argv.includes("--check")) {
    if (readFileSync(target, "utf8") !== output)
      throw new Error(
        `Stale ${name} binding encoder. Run node scripts/sync-first-party-protocol.mjs.`,
      );
  } else writeFileSync(target, output);
}
