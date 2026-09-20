import { execFileSync } from "node:child_process";
import { resolve } from "node:path";
const device = process.env.MAESTRO_DEVICE_ID;
if (!device || !/^[A-Za-z0-9-]+$/.test(device))
  throw Error("Missing Android device");
const adb = resolve(".artifacts/android-tools/sdk/platform-tools/adb");
const call = (...args) =>
  execFileSync(adb, ["-s", device, ...args], {
    encoding: "utf8",
    timeout: 15000,
  });
// Real keyboard events notify React Native controlled inputs, unlike UIA2 Clear().
call("shell", "input", "keycombination", "113", "29"); // Ctrl+A
call("shell", "input", "keyevent", "67"); // Delete selection
console.log("Sent Android Select All and Delete");
