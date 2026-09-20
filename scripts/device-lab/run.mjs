import { spawnSync } from "node:child_process";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
process.chdir(resolve(dirname(fileURLToPath(import.meta.url)), "../.."));
const args = process.argv.slice(2);
const value = (flag) => {
  const i = args.indexOf(flag);
  return i < 0 ? undefined : args[i + 1];
};
const platform = value("--platform"),
  device = value("--device");
if (
  !["android", "ios"].includes(platform) ||
  !device ||
  !/^[A-Za-z0-9-]+$/.test(device)
)
  throw Error(
    "Supply --platform android|ios --device SERIAL/UDID [--team-id TEAM] [--env-file FILE] [--probe] [--fail-probe]",
  );
const runner = resolve(
  ".artifacts/maestro-tools/node_modules/.bin/maestro-runner",
);
const globals = ["--platform", platform, "--device", device];
if (platform === "ios") {
  const team = value("--team-id");
  if (!team) throw Error("--team-id is required for iOS");
  globals.push(
    "--team-id",
    team,
    "--wda-bundle-id",
    "io.eventyr.attestationlab.wda",
  );
}
const env = {
  ...process.env,
  PATH:
    resolve(".artifacts/android-tools/sdk/platform-tools") +
    ":" +
    process.env.PATH,
  ANDROID_HOME:
    process.env.ANDROID_HOME ?? resolve(".artifacts/android-tools/sdk"),
};
const probe = args.includes("--probe") || args.includes("--fail-probe");
const options = [
  "test",
  "--output",
  `.artifacts/device-screen/${platform}-jobs`,
];
const file = value("--env-file");
if (!probe && !file) throw Error("--env-file is required for lifecycle tests");
const main = [...globals, ...options, "--typing-frequency", "10"];
if (file) main.push("--env-file", resolve(file));
main.push(
  "-e",
  `SCREEN_PROBE_FAIL=${args.includes("--fail-probe") ? "1" : "0"}`,
);
if (args.includes("--recovery") && platform !== "ios")
  throw Error("--recovery is the iOS selective missing-key acceptance case");
const flow = `apps/example-mobile/flows/${probe ? "screen-probe" : args.includes("--recovery") ? "ios-missing-key" : "lifecycle"}.yaml`;
main.push(
  platform === "android" && !probe
    ? (await import("./prepare-android-flow.mjs")).prepareAndroidFlow(flow)
    : flow,
);
let code = 1,
  cleanupCode = 1;
// Keep the parent alive on Ctrl-C so the final cleanup command can execute.
// SIGKILL, host failure and device disconnect remain outside this guarantee.
const interrupt = () => {
  code = 130;
};
process.on("SIGINT", interrupt);
process.on("SIGTERM", interrupt);
try {
  const result = spawnSync(runner, main, { stdio: "inherit", env });
  code = result.status ?? 1;
  if (result.error) console.error(result.error.message);
} finally {
  console.log("Restoring screen settings and sleeping the selected device...");
  const result = spawnSync(
    runner,
    [...globals, ...options, "apps/example-mobile/flows/screen-sleep.yaml"],
    { stdio: "inherit", env },
  );
  cleanupCode = result.status ?? 1;
  if (result.error) console.error(result.error.message);
}
process.exitCode = code || cleanupCode;
