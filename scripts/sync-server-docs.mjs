import { cpSync } from "node:fs";
import { fileURLToPath } from "node:url";
cpSync(
  fileURLToPath(new URL("../docs", import.meta.url)),
  fileURLToPath(new URL("../packages/better-auth-fipa/docs", import.meta.url)),
  { recursive: true },
);
