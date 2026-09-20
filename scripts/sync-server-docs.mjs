import { cpSync, mkdirSync, rmSync } from "node:fs";
import { fileURLToPath } from "node:url";

const destination = fileURLToPath(
  new URL("../packages/better-auth-fipa/docs", import.meta.url),
);
// Rebuild generated docs so removed files cannot survive in a package tarball.
rmSync(destination, { recursive: true, force: true });
mkdirSync(destination, { recursive: true });
// Copy only publication documentation, not arbitrary repository planning files.
cpSync(
  fileURLToPath(new URL("../docs/design.md", import.meta.url)),
  fileURLToPath(
    new URL("../packages/better-auth-fipa/docs/design.md", import.meta.url),
  ),
);
