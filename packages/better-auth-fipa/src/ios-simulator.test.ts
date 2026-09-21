import {
  createHash,
  generateKeyPairSync,
  randomBytes,
  sign,
} from "node:crypto";
import { afterEach, expect, it, vi } from "vitest";
import { iosSimulator } from "./ios-simulator.js";
import { appAttest } from "./app-attest/provider.js";
import type { StoredAttestationCredential } from "./types.js";
import { createNativeAdmissionEndpoints } from "./first-party/admission-endpoints.js";

const options = {
  enabled: true,
  environment: "development",
  applicationIds: ["TEAM.app"],
} as const;
afterEach(() => vi.unstubAllEnvs());
function fixture() {
  const provider = iosSimulator(options);
  const { publicKey, privateKey } = generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
  });
  const keyId = randomBytes(32);
  const clientDataHash = createHash("sha256").update("challenge").digest();
  const evidence = (operation: "register" | "assert") =>
    Buffer.from(
      JSON.stringify({
        version: 1,
        provider: "ios-simulator",
        operation,
        jwk: publicKey.export({ format: "jwk" }),
        signature: sign(
          "sha256",
          Buffer.from(
            `fipa/ios-simulator/v1\n${operation}\n${keyId.toString("base64")}\n${clientDataHash.toString("base64")}`,
          ),
          { key: privateKey, dsaEncoding: "ieee-p1363" },
        ).toString("base64url"),
      }),
    );
  const credential: StoredAttestationCredential = {
    id: "credential",
    provider: "ios-simulator",
    applicationId: "TEAM.app",
    environment: "development",
    lookupKey: "lookup",
    counter: 0,
    externallyBound: false,
    bindingVersion: 0,
    status: "active",
    extensionsPresent: false,
    publicKey: publicKey
      .export({ format: "der", type: "spki" })
      .toString("base64"),
  };
  return { provider, keyId, clientDataHash, evidence, credential };
}
it("accepts only separately identified software proof of possession", async () => {
  const f = fixture();
  expect(
    await f.provider.verifyRegistration({
      ...f,
      applicationId: "TEAM.app",
      evidence: f.evidence("register"),
    }),
  ).toMatchObject({
    environment: "development",
    counter: 0,
    publicKey: f.credential.publicKey,
  });
  expect(
    await f.provider.verifyAssertion({ ...f, evidence: f.evidence("assert") }),
  ).toEqual({ counter: 1, extensionsPresent: false });
});
it("fails closed without explicit opt-in or in production", () => {
  expect(() =>
    iosSimulator({ ...options, enabled: false as unknown as true }),
  ).toThrow();
  expect(() =>
    iosSimulator({ ...options, environment: "production" as "development" }),
  ).toThrow();
  vi.stubEnv("NODE_ENV", "production");
  expect(() => iosSimulator(options)).toThrow();
});
it("rejects runtime production registration and assertion even for an earlier factory", async () => {
  const f = fixture();
  vi.stubEnv("NODE_ENV", "production");
  expect(() => f.provider.decodeKeyId(f.keyId.toString("base64"))).toThrow();
  await expect(
    f.provider.verifyRegistration({
      ...f,
      applicationId: "TEAM.app",
      evidence: f.evidence("register"),
    }),
  ).rejects.toThrow();
  await expect(
    f.provider.verifyAssertion({ ...f, evidence: f.evidence("assert") }),
  ).rejects.toThrow();
});
it("rejects a simulator provider in a production native policy", () => {
  expect(() =>
    createNativeAdmissionEndpoints([
      {
        clientId: "mobile",
        provider: iosSimulator(options),
        applicationId: "TEAM.app",
        environment: "production",
        scopes: [],
        resources: [],
      },
    ]),
  ).toThrow();
});
it.each(["application", "challenge", "key", "operation", "signature"])(
  "rejects mismatched %s registration evidence",
  async (field) => {
    const f = fixture();
    const input = {
      ...f,
      applicationId: "TEAM.app",
      evidence: f.evidence("register"),
    };
    if (field === "application") input.applicationId = "OTHER.app";
    if (field === "challenge") input.clientDataHash = randomBytes(32);
    if (field === "key") input.keyId = randomBytes(32);
    if (field === "operation") input.evidence = f.evidence("assert");
    if (field === "signature")
      input.evidence = Buffer.from(
        input.evidence.toString().replace('"signature":"', '"signature":"A'),
      );
    await expect(f.provider.verifyRegistration(input)).rejects.toThrow();
  },
);
it.each(["app-attest", "production", "another-key"])(
  "rejects stored credential from %s trust domain",
  async (domain) => {
    const f = fixture();
    if (domain === "app-attest") f.credential.provider = domain;
    if (domain === "production") f.credential.environment = domain;
    if (domain === "another-key")
      f.credential.publicKey = fixture().credential.publicKey!;
    await expect(
      f.provider.verifyAssertion({ ...f, evidence: f.evidence("assert") }),
    ).rejects.toThrow();
  },
);
it("simulator evidence cannot register with App Attest", async () => {
  const f = fixture();
  const hardware = appAttest({
    applications: [
      { appId: "TEAM.app", platform: "ios", environment: "production" },
    ],
  });
  await expect(
    hardware.verifyRegistration({
      ...f,
      applicationId: "TEAM.app",
      evidence: f.evidence("register"),
    }),
  ).rejects.toThrow();
});
