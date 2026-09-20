import { createRequire } from "node:module";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { resolve, dirname } from "node:path";
const require = createRequire(resolve(".artifacts/maestro-tools/package.json"));
const { parseAllDocuments, stringify } = require("yaml");
// Runner 1.1.27 does not dispatch runShell inside subflows. Expand the shared
// flow into root steps for Android, retaining the same assertions and order.
export function prepareAndroidFlow(file) {
  function expand(file, depth = 0) {
    if (depth > 10) throw Error("Flow nesting limit exceeded");
    const docs = parseAllDocuments(readFileSync(file, "utf8"));
    if (docs.some((doc) => doc.errors.length))
      throw Error(`Invalid YAML: ${file}`);
    return steps(docs[1].toJSON(), dirname(file), depth);
  }
  function steps(items, directory, depth) {
    let focusedId;
    return items.flatMap((step) => {
      if (step?.tapOn?.id) focusedId = step.tapOn.id;
      if (step && typeof step === "object" && "runFlow" in step) {
        const sub = step.runFlow;
        if (typeof sub === "string")
          return expand(resolve(directory, sub), depth + 1);
        if (
          Object.keys(sub).some((key) => !["when", "commands"].includes(key)) ||
          Object.keys(sub.when ?? {}).join() !== "platform"
        )
          throw Error("Unsupported flow condition");
        return sub.when.platform === "Android"
          ? steps(sub.commands, directory, depth + 1)
          : [];
      }
      if (step && typeof step === "object" && "eraseText" in step) {
        if (!focusedId)
          throw Error("Text clearing requires a preceding field ID");
        return [
          { runShell: "node scripts/device-lab/android-clear-text.mjs" },
          "hideKeyboard",
          { assertVisible: { id: focusedId, text: "^$" } },
        ];
      }
      return [step];
    });
  }
  const output = resolve(".artifacts/device-screen/android-lifecycle.yaml");
  mkdirSync(dirname(output), { recursive: true });
  writeFileSync(
    output,
    "appId: io.eventyr.attestationlab\n---\n" +
      stringify(expand(resolve(file))),
  );
  return output;
}
