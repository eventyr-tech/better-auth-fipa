import {
  createHash,
  generateKeyPairSync,
  randomBytes,
  sign,
} from "node:crypto";
import { afterEach, expect, it, vi } from "vitest";
import {
  developmentProvider,
  developmentPolicyAllowed,
} from "./development.js";
import { appAttest } from "./app-attest/provider.js";
import type { StoredAttestationCredential } from "./types.js";
import { createNativeAdmissionEndpoints } from "./first-party/admission-endpoints.js";

const options = {
  enabled: true,
  authorize: () => true,
  environment: "development",
  applicationIds: ["TEAM.app"],
} as const;
afterEach(() => vi.unstubAllEnvs());
function fixture(authorize = () => true) {
  const provider = developmentProvider({ ...options, authorize });
  const { publicKey, privateKey } = generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
  });
  const keyId = randomBytes(32);
  const clientDataHash = createHash("sha256").update("challenge").digest();
  const evidence = (operation: "register" | "assert") =>
    Buffer.from(
      JSON.stringify({
        version: 1,
        provider: "development",
        operation,
        jwk: publicKey.export({ format: "jwk" }),
        signature: sign(
          "sha256",
          Buffer.from(
            `fipa/development/v1\n${operation}\n${keyId.toString("base64")}\n${clientDataHash.toString("base64")}`,
          ),
          { key: privateKey, dsaEncoding: "ieee-p1363" },
        ).toString("base64url"),
      }),
    );
  const credential: StoredAttestationCredential = {
    id: "credential",
    provider: "development",
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
it.each(["development", "production"])(
  "accepts authorized software evidence with NODE_ENV=%s",
  async (mode) => {
    vi.stubEnv("NODE_ENV", mode);
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
      await f.provider.verifyAssertion({
        ...f,
        evidence: f.evidence("assert"),
      }),
    ).toEqual({ counter: 1, extensionsPresent: false });
  },
);
it("fails closed without explicit opt-in, host authorization or development credentials", () => {
  vi.stubEnv("NODE_ENV", "production");
  expect(() =>
    developmentProvider({ ...options, enabled: false as unknown as true }),
  ).toThrow();
  expect(() =>
    developmentProvider({
      ...options,
      environment: "production" as "development",
    }),
  ).toThrow();
  expect(() =>
    developmentProvider({ ...options, authorize: () => false }),
  ).toThrow();
  expect(() =>
    developmentProvider({ ...options, authorize: undefined as never }),
  ).toThrow();
  expect(() =>
    developmentProvider({
      ...options,
      authorize: () => {
        throw new Error("policy unavailable");
      },
    }),
  ).toThrow();
});
it("rejects registration and assertion after deployment authorization is revoked", async () => {
  vi.stubEnv("NODE_ENV", "production");
  let allowed = true;
  const f = fixture(() => allowed);
  allowed = false;
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
it("rejects a development provider in a production native policy", () => {
  expect(() =>
    createNativeAdmissionEndpoints([
      {
        clientId: "mobile",
        provider: developmentProvider(options),
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
it.each(["app-attest", "android-hardware", "production", "another-key"])(
  "rejects stored credential from %s trust domain",
  async (domain) => {
    const f = fixture();
    if (domain === "app-attest" || domain === "android-hardware")
      f.credential.provider = domain;
    if (domain === "production") f.credential.environment = domain;
    if (domain === "another-key")
      f.credential.publicKey = fixture().credential.publicKey!;
    await expect(
      f.provider.verifyAssertion({ ...f, evidence: f.evidence("assert") }),
    ).rejects.toThrow();
  },
);
it("development evidence cannot register with App Attest", async () => {
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

it("fails closed for unauthorized provider copies and policy callback errors", () => {
  let denied = false;
  const f = fixture(() => {
    if (denied) throw new Error("host policy failed");
    return true;
  });
  expect(developmentPolicyAllowed(f.provider, "development")).toBe(true);
  expect(developmentPolicyAllowed({ ...f.provider }, "development")).toBe(
    false,
  );
  denied = true;
  expect(developmentPolicyAllowed(f.provider, "development")).toBe(false);
});
