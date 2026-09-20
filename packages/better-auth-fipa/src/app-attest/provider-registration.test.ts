import { generateKeyPairSync } from "node:crypto";

import cbor from "cbor";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { DeviceAttestationError } from "../errors.js";
import { sha256 } from "../protocol/crypto.js";
import type { AppAttestPlatform } from "./platform-policy.js";
import { appAttest } from "./provider.js";
import { verifyAppAttestCertificateChain } from "./x509.js";

vi.mock("./x509.js", () => ({
  verifyAppAttestCertificateChain: vi.fn(),
}));

const APP_ID = "TEAMID.com.example.mobile";
const PRODUCTION_AAGUID = Buffer.concat([
  Buffer.from("appattest", "ascii"),
  Buffer.alloc(7),
]);
const DEVELOPMENT_AAGUID = Buffer.from("appattestdevelop", "ascii");
const CLIENT_DATA_HASH = sha256(Buffer.from("registration-client-data"));
const mockedCertificateVerifier = vi.mocked(verifyAppAttestCertificateChain);

beforeEach(() => {
  mockedCertificateVerifier.mockReset();
});

describe("App Attest registration policy", () => {
  it("registers TestFlight evidence with object-shaped byte extensions", async () => {
    const fixture = await createRegistrationFixture({
      validationCategory: 2,
      bundleVersion: "42",
    });
    mockCertificate(fixture);
    const provider = createProvider(
      "production",
      [2, 4],
      (version) => version === "42",
    );

    await expect(provider.verifyRegistration(fixture.input)).resolves.toEqual({
      applicationId: APP_ID,
      environment: "production",
      publicKey: fixture.publicKeySpki.toString("base64"),
      counter: 0,
      extensionsPresent: true,
      validationCategory: 2,
      bundleVersion: "42",
      untrustedReceipt: Buffer.from("synthetic-receipt"),
    });
  });

  it("accepts an explicit compatibility policy when extensions are absent", async () => {
    const fixture = await createRegistrationFixture({ extensions: undefined });
    mockCertificate(fixture);
    const provider = createProvider("production", [2, 4], () => true, {
      presence: "if-present",
    });

    await expect(
      provider.verifyRegistration(fixture.input),
    ).resolves.toMatchObject({
      extensionsPresent: false,
    });
  });

  it.each([
    {
      name: "development evidence for a production application",
      fixture: { aaguid: DEVELOPMENT_AAGUID },
      reason: "app_attest_environment_mismatch",
    },
    {
      name: "a nonzero registration counter",
      fixture: { counter: 1 },
      reason: "nonzero_attestation_counter",
    },
    {
      name: "the wrong RP ID hash",
      fixture: { rpId: "TEAMID.com.example.other" },
      reason: "rp_id_hash_mismatch",
    },
    {
      name: "a mismatched credential ID",
      fixture: { credentialId: Buffer.alloc(32, 0xa1) },
      reason: "credential_id_mismatch",
    },
    {
      name: "a disallowed distribution category",
      fixture: { validationCategory: 5 },
      reason: "validation_category_disallowed",
    },
    {
      name: "a disallowed bundle version",
      fixture: { bundleVersion: "41" },
      reason: "bundle_version_disallowed",
    },
  ])("rejects $name", async ({ fixture: overrides, reason }) => {
    const fixture = await createRegistrationFixture(overrides);
    mockCertificate(fixture);
    const provider = createProvider(
      "production",
      [2, 4],
      (version) => version === "42",
    );

    await expectFailureReason(
      () => provider.verifyRegistration(fixture.input),
      reason,
    );
  });

  it("rejects a nonce that does not commit to authenticator and client data", async () => {
    const fixture = await createRegistrationFixture();
    mockCertificate(fixture, { nonce: Buffer.alloc(32, 0xff) });
    const provider = createProvider("production", [2, 4], () => true);

    await expectFailureReason(
      () => provider.verifyRegistration(fixture.input),
      "attestation_nonce_mismatch",
    );
  });

  it("rejects a key ID that does not identify the certified key", async () => {
    const fixture = await createRegistrationFixture();
    mockCertificate(fixture, { publicKeyRaw: Buffer.alloc(65, 0xaa) });
    const provider = createProvider("production", [2, 4], () => true);

    await expectFailureReason(
      () => provider.verifyRegistration(fixture.input),
      "credential_key_id_mismatch",
    );
  });

  it("rejects a COSE key that does not match the certified key", async () => {
    const fixture = await createRegistrationFixture({
      cosePublicKeyRaw: Buffer.concat([
        Buffer.from([4]),
        Buffer.alloc(64, 0xbb),
      ]),
    });
    mockCertificate(fixture);
    const provider = createProvider("production", [2, 4], () => true);

    await expectFailureReason(
      () => provider.verifyRegistration(fixture.input),
      "cose_certificate_key_mismatch",
    );
  });

  it("accepts development evidence only for an explicit development application", async () => {
    const fixture = await createRegistrationFixture({
      aaguid: DEVELOPMENT_AAGUID,
    });
    mockCertificate(fixture);
    const provider = createProvider("development", [2, 4], () => true);

    await expect(
      provider.verifyRegistration(fixture.input),
    ).resolves.toMatchObject({
      environment: "development",
    });
  });

  it("does not let receipt callback failure replace a valid decision", async () => {
    const fixture = await createRegistrationFixture();
    mockCertificate(fixture);
    const onReceipt = vi.fn().mockRejectedValue(new Error("queue unavailable"));
    const provider = appAttest({
      applications: [application("production", [2, 4], () => true)],
      receipt: { onReceipt, failureMode: "report" },
    });

    await expect(
      provider.verifyRegistration(fixture.input),
    ).resolves.toMatchObject({
      applicationId: APP_ID,
    });
    expect(onReceipt).toHaveBeenCalledOnce();
  });

  it.each([
    () => appAttest({ applications: [] }),
    () =>
      appAttest({
        applications: [
          application("production", [2], () => true),
          application("production", [2], () => true),
        ],
      }),
    () => createProvider("production", [], () => true),
    () => createProvider("production", [-1], () => true),
    () =>
      appAttest({
        applications: [
          {
            ...application("production", [2], () => true),
            platform: "tvos" as AppAttestPlatform,
          },
        ],
      }),
    () =>
      appAttest({
        applications: [application("production", [2], () => true)],
        maxEvidenceBytes: 0,
      }),
  ])("rejects invalid provider configuration", (create) => {
    expect(create).toThrow(TypeError);
  });
});

interface FixtureOverrides {
  aaguid?: Buffer;
  bundleVersion?: string;
  counter?: number;
  cosePublicKeyRaw?: Buffer;
  credentialId?: Buffer;
  extensions?: undefined;
  rpId?: string;
  validationCategory?: number;
}

async function createRegistrationFixture(overrides: FixtureOverrides = {}) {
  const { publicKey } = generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
  });
  const jwk = publicKey.export({ format: "jwk" });
  if (!jwk.x || !jwk.y) {
    throw new TypeError("Generated key has no EC coordinates.");
  }
  const publicKeyRaw = Buffer.concat([
    Buffer.from([4]),
    Buffer.from(jwk.x, "base64url"),
    Buffer.from(jwk.y, "base64url"),
  ]);
  const publicKeySpki = Buffer.from(
    publicKey.export({ format: "der", type: "spki" }),
  );
  const keyId = sha256(publicKeyRaw);
  const coseRaw = overrides.cosePublicKeyRaw ?? publicKeyRaw;
  const cose = new Map<number, number | Buffer>([
    [1, 2],
    [3, -7],
    [-1, 1],
    [-2, coseRaw.subarray(1, 33)],
    [-3, coseRaw.subarray(33, 65)],
  ]);
  const counter = Buffer.alloc(4);
  counter.writeUInt32BE(overrides.counter ?? 0);
  const credentialId = overrides.credentialId ?? keyId;
  const credentialLength = Buffer.alloc(2);
  credentialLength.writeUInt16BE(credentialId.length);
  const extensions =
    Object.hasOwn(overrides, "extensions") && overrides.extensions === undefined
      ? Buffer.alloc(0)
      : await cbor.encodeAsync({
          apple_bundle_version_01: overrides.bundleVersion ?? "42",
          apple_validation_category_01: categoryBytes(
            overrides.validationCategory ?? 2,
          ),
        });
  const authData = Buffer.concat([
    sha256(Buffer.from(overrides.rpId ?? APP_ID, "utf8")),
    Buffer.from([0x40]),
    counter,
    overrides.aaguid ?? PRODUCTION_AAGUID,
    credentialLength,
    credentialId,
    await cbor.encodeAsync(cose),
    extensions,
  ]);
  const evidence = await cbor.encodeAsync({
    fmt: "apple-appattest",
    authData,
    attStmt: {
      x5c: [Buffer.from("leaf"), Buffer.from("intermediate")],
      receipt: Buffer.from("synthetic-receipt"),
    },
  });
  return {
    input: {
      applicationId: APP_ID,
      keyId,
      clientDataHash: CLIENT_DATA_HASH,
      evidence,
    },
    authData,
    publicKeyRaw,
    publicKeySpki,
  };
}

function mockCertificate(
  fixture: Awaited<ReturnType<typeof createRegistrationFixture>>,
  overrides: { nonce?: Buffer; publicKeyRaw?: Buffer } = {},
): void {
  mockedCertificateVerifier.mockResolvedValue({
    publicKeyRaw: overrides.publicKeyRaw ?? fixture.publicKeyRaw,
    publicKeySpki: fixture.publicKeySpki,
    nonce:
      overrides.nonce ??
      sha256(Buffer.concat([fixture.authData, CLIENT_DATA_HASH])),
  });
}

function createProvider(
  environment: "development" | "production",
  allowedValidationCategories: readonly number[],
  validateBundleVersion: (version: string) => boolean | Promise<boolean>,
  overrides: { presence?: "if-present" | "required" } = {},
) {
  return appAttest({
    applications: [
      application(
        environment,
        allowedValidationCategories,
        validateBundleVersion,
        overrides.presence,
      ),
    ],
  });
}

function application(
  environment: "development" | "production",
  allowedValidationCategories: readonly number[],
  validateBundleVersion: (version: string) => boolean | Promise<boolean>,
  presence: "if-present" | "required" = "required",
) {
  return {
    appId: APP_ID,
    platform: "ios",
    environment,
    extensions: {
      presence,
      allowedValidationCategories,
      validateBundleVersion,
    },
  } as const;
}

function categoryBytes(category: number): Buffer {
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32LE(category);
  return bytes;
}

async function expectFailureReason(
  operation: () => Promise<unknown>,
  reason: string,
): Promise<void> {
  try {
    await operation();
  } catch (error) {
    expect(error).toBeInstanceOf(DeviceAttestationError);
    expect(error).toMatchObject({ reason });
    return;
  }
  expect.fail("Expected attestation verification to fail.");
}
