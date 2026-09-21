import { execFileSync } from "node:child_process";
import {
  mkdtempSync,
  writeFileSync,
  readFileSync,
  existsSync,
  unlinkSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createHash, createPublicKey, verify } from "node:crypto";
import assert from "node:assert/strict";
import { iosSimulator } from "../packages/better-auth-fipa/dist/first-party.js";
const root = resolve(import.meta.dirname, "..");
const run = (cmd, args) => execFileSync(cmd, args, { encoding: "utf8" });
const temp = mkdtempSync(join(tmpdir(), "fipa-simulator-"));
const app = join(temp, "FiPASmoke.app");
const { mkdirSync } = await import("node:fs");
mkdirSync(app);
const device = process.env.FIPA_SIMULATOR_UDID ?? "booted";
const bundle = "dev.fipa.simulator-smoke";
try {
  writeFileSync(
    join(app, "Info.plist"),
    `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>${bundle}</string><key>CFBundleExecutable</key><string>FiPASmoke</string><key>CFBundleName</key><string>FiPA Native Smoke</string><key>CFBundleVersion</key><string>1</string><key>CFBundlePackageType</key><string>APPL</string><key>MinimumOSVersion</key><string>17.0</string></dict></plist>`,
  );
  const entitlements = join(temp, "entitlements.plist");
  writeFileSync(
    entitlements,
    `<?xml version="1.0"?><plist version="1.0"><dict><key>application-identifier</key><string>FIPATEST.${bundle}</string><key>keychain-access-groups</key><array><string>FIPATEST.${bundle}</string></array></dict></plist>`,
  );
  const native = join(root, "packages/react-native-fipa/ios");
  const sdk = run("xcrun", [
    "--sdk",
    "iphonesimulator",
    "--show-sdk-path",
  ]).trim();
  run("xcrun", [
    "--sdk",
    "iphonesimulator",
    "swiftc",
    "-target",
    `${process.arch === "arm64" ? "arm64" : "x86_64"}-apple-ios17.0-simulator`,
    "-sdk",
    sdk,
    ...[
      "FirstPartyCrypto.swift",
      "FirstPartyDpopKey.swift",
      "FirstPartySimulatorKey.swift",
      "SessionVault.swift",
      "KeychainSessionVaultStorage.swift",
    ].map((f) => join(native, f)),
    join(root, "packages/react-native-fipa/Tests/SimulatorSmoke/main.swift"),
    "-Xlinker",
    "-sectcreate",
    "-Xlinker",
    "__TEXT",
    "-Xlinker",
    "__entitlements",
    "-Xlinker",
    entitlements,
    "-o",
    join(app, "FiPASmoke"),
  ]);
  run("codesign", ["--force", "--sign", "-", app]);
  run("xcrun", ["simctl", "install", device, app]);
  const container = run("xcrun", [
    "simctl",
    "get_app_container",
    device,
    bundle,
    "data",
  ]).trim();
  const resultPath = join(container, "Documents/result.json");
  let first;
  for (const phase of ["created", "restored-and-removed"]) {
    if (existsSync(resultPath)) unlinkSync(resultPath);
    run("xcrun", ["simctl", "launch", device, bundle]);
    for (let i = 0; i < 100 && !existsSync(resultPath); i++)
      await new Promise((r) => setTimeout(r, 100));
    const result = JSON.parse(readFileSync(resultPath, "utf8"));
    assert.equal(
      result.phase,
      phase,
      `Native simulator smoke failed: ${result.error ?? "unknown"}`,
    );
    if (first) assert.equal(result.keyId, first.keyId);
    first = result;
    const provider = iosSimulator({
      enabled: true,
      environment: "development",
      applicationIds: [bundle],
    });
    const input = {
      applicationId: bundle,
      keyId: provider.decodeKeyId(result.keyId),
      clientDataHash: createHash("sha256").update("challenge").digest(),
    };
    const registered = await provider.verifyRegistration({
      ...input,
      evidence: Buffer.from(result.registration, "base64"),
    });
    await provider.verifyAssertion({
      ...input,
      credential: { ...registered, provider: "ios-simulator", counter: 0 },
      evidence: Buffer.from(result.assertion, "base64"),
    });
    const [header, payload, signature] = result.dpop.split(".");
    const jwk = JSON.parse(Buffer.from(header, "base64url")).jwk;
    assert(
      verify(
        "sha256",
        Buffer.from(`${header}.${payload}`),
        {
          key: createPublicKey({ key: jwk, format: "jwk" }),
          dsaEncoding: "ieee-p1363",
        },
        Buffer.from(signature, "base64url"),
      ),
    );
    assert.equal(
      JSON.parse(Buffer.from(payload, "base64url")).ath,
      createHash("sha256").update("test-token").digest("base64url"),
    );
    run("xcrun", ["simctl", "terminate", device, bundle]);
  }
  console.log(
    "Actual iOS Simulator: native software evidence verified by server provider; DPoP signature; Keychain key/vault persistence across relaunch; hardware namespace separation; key removal passed. This is not a React Native UI or physical-device test.",
  );
} finally {
  try {
    run("xcrun", ["simctl", "uninstall", device, bundle]);
  } catch {
    /* app may not have installed */
  }
  rmSync(temp, { recursive: true, force: true });
}
