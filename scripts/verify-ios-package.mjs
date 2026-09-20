import { mkdtempSync, rmSync } from "node:fs";
import { consumerRunner, prepareExampleConsumer } from "./packed-consumer.mjs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

// A separate installation catches missing published files and workspace-only resolution.
if (process.platform !== "darwin")
  throw new Error("iOS validation requires macOS and Xcode.");
const root = fileURLToPath(new URL("..", import.meta.url));
const temporary = mkdtempSync(join(tmpdir(), "attestation-ios-consumer-"));
const run = consumerRunner(temporary);

try {
  prepareExampleConsumer(root, temporary, "ios");
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
