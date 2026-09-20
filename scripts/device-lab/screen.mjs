// Maestro Runner 1.1.27 device hooks. Never selects a device implicitly.
import { execFileSync } from "node:child_process";
import {
  mkdirSync,
  existsSync,
  readFileSync,
  writeFileSync,
  unlinkSync,
} from "node:fs";
import { resolve } from "node:path";
const action = process.argv[2];
const platform = process.env.MAESTRO_PLATFORM;
const device = process.env.MAESTRO_DEVICE_ID;
if (
  !["wake", "sleep"].includes(action) ||
  !device ||
  !/^[A-Za-z0-9-]+$/.test(device)
)
  throw Error("Expected wake/sleep and an explicit MAESTRO_DEVICE_ID");
if (platform === "android") {
  const adb =
    process.env.ADB ??
    resolve(".artifacts/android-tools/sdk/platform-tools/adb");
  const shell = (...args) =>
    execFileSync(adb, ["-s", device, "shell", ...args], {
      encoding: "utf8",
      timeout: 15000,
    }).trim();
  const dir = resolve(".artifacts/device-screen");
  mkdirSync(dir, { recursive: true });
  const file = resolve(dir, `${device}.json`);
  if (action === "wake") {
    if (existsSync(file))
      throw Error("Unrestored screen settings: run sleep cleanup first");
    const original = shell(
      "settings",
      "get",
      "global",
      "stay_on_while_plugged_in",
    );
    writeFileSync(file, JSON.stringify({ original }), { mode: 0o600 });
    shell("settings", "put", "global", "stay_on_while_plugged_in", "7");
    shell("input", "keyevent", "KEYCODE_WAKEUP");
    shell("wm", "dismiss-keyguard");
  } else {
    // Restore the setting even after an assertion fails. Then explicitly sleep.
    try {
      if (existsSync(file)) {
        const { original } = JSON.parse(readFileSync(file, "utf8"));
        if (original === "null")
          shell("settings", "delete", "global", "stay_on_while_plugged_in");
        else
          shell(
            "settings",
            "put",
            "global",
            "stay_on_while_plugged_in",
            original,
          );
        unlinkSync(file);
      }
    } finally {
      shell("input", "keyevent", "KEYCODE_SLEEP");
    }
  }
  console.log(
    `Android ${action}: ${shell("dumpsys", "power").match(/mWakefulness=\w+/)?.[0] ?? "unknown state"}`,
  );
} else if (platform === "ios") {
  // Matches pinned runner's PortFromUDID; only its selected device's loopback port.
  const tail = device.split("-").at(-1).slice(-12);
  if (!/^[a-fA-F0-9]+$/.test(tail)) throw Error("Invalid iOS UDID");
  const port = 8100 + Number(BigInt(`0x${tail}`) % 1000n);
  const call = async (path, method = "GET") => {
    const r = await fetch(`http://127.0.0.1:${port}/wda/${path}`, {
      method,
      ...(method === "POST"
        ? { headers: { "Content-Type": "application/json" }, body: "{}" }
        : {}),
      signal: AbortSignal.timeout(15000),
    });
    const body = await r.json();
    if (!r.ok || body.value?.error)
      throw Error(`WDA ${path} failed: ${JSON.stringify(body.value)}`);
    return body.value;
  };
  await call(action === "wake" ? "unlock" : "lock", "POST");
  const locked = await call("locked");
  if (locked !== (action === "sleep"))
    throw Error(`Unexpected iOS locked state: ${locked}`);
  console.log(`iOS ${action}: locked=${locked}`);
} else throw Error("Expected MAESTRO_PLATFORM ios/android");
