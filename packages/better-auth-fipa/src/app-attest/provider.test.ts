import { generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { readFile } from "node:fs/promises";

import cbor from "cbor";
import { afterEach, describe, expect, it, vi } from "vitest";

import { appAttest } from "./provider.js";
import { AUTHENTICATOR_DATA_FLAGS } from "./authenticator-data.js";
import type { StoredAttestationCredential } from "../types.js";
import { sha256 } from "../protocol/crypto.js";

const APP_ID = "1234567890.com.example.myapp";
const KEY_ID = Buffer.from(
  "zgSY9YSD+7TaDXssY6WlOPVS1K3Lmk+pFhlcSWE+ZV0=",
  "base64",
);

afterEach(() => {
  vi.useRealTimers();
});

describe("App Attest provider", () => {
  it("rejects application IDs beyond the portable schema bound", () => {
    expect(() =>
      appAttest({
        applications: [
          {
            appId: "a".repeat(256),
            platform: "ios",
            environment: "production",
            extensions: {
              presence: "required",
              allowedValidationCategories: [2, 4],
              validateBundleVersion: () => true,
            },
          },
        ],
      }),
    ).toThrow(/at most 255 characters/u);
  });

  it("verifies Apple's official production attestation sample", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-04-21T18:13:12.153Z"));
    const evidence = Buffer.from(
      (
        await readFile(
          new URL(
            "./fixtures/apple-attestation-object.base64",
            import.meta.url,
          ),
          "utf8",
        )
      ).trim(),
      "base64",
    );
    const onReceipt = vi.fn();
    const provider = appAttest({
      applications: [
        {
          appId: APP_ID,
          platform: "ios",
          environment: "production",
          extensions: {
            presence: "required",
            allowedValidationCategories: [1],
            validateBundleVersion: (version) => version === "1",
          },
        },
      ],
      receipt: { onReceipt, failureMode: "report" },
    });

    const result = await provider.verifyRegistration({
      applicationId: APP_ID,
      keyId: KEY_ID,
      // Apple's known-answer fixture uses these exact bytes as clientDataHash.
      clientDataHash: Buffer.from("example_server_challenge", "utf8"),
      evidence,
    });

    expect(result).toMatchObject({
      applicationId: APP_ID,
      environment: "production",
      counter: 0,
      validationCategory: 1,
      bundleVersion: "1",
      extensionsPresent: true,
    });
    expect(Buffer.from(result.publicKey, "base64")).toHaveLength(91);
    expect(onReceipt).toHaveBeenCalledOnce();
  });

  it("strictly decodes Apple key identifiers", () => {
    const provider = appAttest({
      applications: [
        {
          appId: APP_ID,
          platform: "ios",
          environment: "production",
          extensions: {
            presence: "required",
            allowedValidationCategories: [2, 4],
            validateBundleVersion: () => true,
          },
        },
      ],
    });

    expect(provider.decodeKeyId(KEY_ID.toString("base64"))).toEqual(KEY_ID);
    expect(() =>
      provider.decodeKeyId(Buffer.alloc(31).toString("base64")),
    ).toThrow(/rejected/u);
  });

  it("verifies assertions and App Store distribution metadata", async () => {
    const fixture = await createAssertionFixture({
      bundleVersion: "42",
      validationCategory: 4,
    });
    const provider = createAssertionProvider({
      presence: "required",
      allowedValidationCategories: [2, 4],
      validateBundleVersion: (version) => version === "42",
    });

    await expect(provider.verifyAssertion(fixture.input)).resolves.toEqual({
      counter: 1,
      validationCategory: 4,
      bundleVersion: "42",
      extensionsPresent: true,
    });
  });

  it("accepts an assertion without extensions only under compatibility policy", async () => {
    const fixture = await createAssertionFixture(undefined);
    const provider = createAssertionProvider({
      presence: "if-present",
      allowedValidationCategories: [2, 4],
      validateBundleVersion: () => true,
    });

    await expect(provider.verifyAssertion(fixture.input)).resolves.toEqual({
      counter: 1,
      extensionsPresent: false,
    });
  });

  it("verifies a production assertion whose fixed header has the AT bit set", async () => {
    const fixture = await createAssertionFixture(undefined, {
      flags: AUTHENTICATOR_DATA_FLAGS.AT,
    });
    const provider = appAttest({
      applications: [
        {
          appId: APP_ID,
          platform: "ios",
          environment: "production",
        },
      ],
    });

    await expect(provider.verifyAssertion(fixture.input)).resolves.toEqual({
      counter: 1,
      extensionsPresent: false,
    });
  });

  it("ignores distribution metadata when no extension policy is configured", async () => {
    const fixture = await createAssertionFixture({
      bundleVersion: "future-build",
      validationCategory: 5,
    });
    const provider = appAttest({
      applications: [
        {
          appId: APP_ID,
          platform: "ios",
          environment: "production",
        },
      ],
    });

    await expect(provider.verifyAssertion(fixture.input)).resolves.toEqual({
      counter: 1,
      extensionsPresent: true,
    });
  });

  it("accepts missing distribution metadata when no extension policy is configured", async () => {
    const fixture = await createAssertionFixture(undefined);
    const provider = appAttest({
      applications: [
        {
          appId: APP_ID,
          platform: "ios",
          environment: "production",
        },
      ],
    });

    await expect(provider.verifyAssertion(fixture.input)).resolves.toEqual({
      counter: 1,
      extensionsPresent: false,
    });
  });

  it.each([
    {
      name: "a replayed counter",
      mutate: (input: AssertionInput) => ({
        ...input,
        credential: { ...input.credential, counter: 1 },
      }),
      reason: "assertion_counter_not_advanced",
    },
    {
      name: "a different stored environment",
      mutate: (input: AssertionInput) => ({
        ...input,
        credential: {
          ...input.credential,
          environment: "development" as const,
        },
      }),
      reason: "stored_environment_mismatch",
    },
    {
      name: "a different key identifier",
      mutate: (input: AssertionInput) => ({
        ...input,
        keyId: Buffer.alloc(32, 0xff),
      }),
      reason: "credential_key_id_mismatch",
    },
    {
      name: "a missing stored public key",
      mutate: (input: AssertionInput) => ({
        ...input,
        credential: { ...input.credential, publicKey: null },
      }),
      reason: "missing_credential_public_key",
    },
    {
      name: "an invalid stored public key",
      mutate: (input: AssertionInput) => ({
        ...input,
        credential: {
          ...input.credential,
          publicKey: Buffer.from("not-spki").toString("base64"),
        },
      }),
      reason: "invalid_credential_public_key",
    },
  ])("rejects $name", async ({ mutate, reason }) => {
    const fixture = await createAssertionFixture({
      bundleVersion: "42",
      validationCategory: 4,
    });
    const provider = createAssertionProvider({
      presence: "required",
      allowedValidationCategories: [2, 4],
      validateBundleVersion: () => true,
    });

    await expectFailureReasonAsync(
      () => provider.verifyAssertion(mutate(fixture.input)),
      reason,
    );
  });

  it("rejects an assertion for a different App ID", async () => {
    const fixture = await createAssertionFixture(
      { bundleVersion: "42", validationCategory: 4 },
      { rpId: "1234567890.com.example.other" },
    );
    const provider = createAssertionProvider({
      presence: "required",
      allowedValidationCategories: [2, 4],
      validateBundleVersion: () => true,
    });

    await expectFailureReasonAsync(
      () => provider.verifyAssertion(fixture.input),
      "rp_id_hash_mismatch",
    );
  });

  it("rejects a mutated assertion signature", async () => {
    const fixture = await createAssertionFixture({
      bundleVersion: "42",
      validationCategory: 4,
    });
    const decoded = (await cbor.decodeFirst(fixture.input.evidence)) as {
      authenticatorData: Uint8Array;
      signature: Uint8Array;
    };
    const signature = Buffer.from(decoded.signature);
    const signatureIndex = signature.length - 1;
    signature[signatureIndex] = (signature[signatureIndex] ?? 0) ^ 1;
    const evidence = await cbor.encodeAsync({
      authenticatorData: decoded.authenticatorData,
      signature,
    });
    const provider = createAssertionProvider({
      presence: "required",
      allowedValidationCategories: [2, 4],
      validateBundleVersion: () => true,
    });

    await expectFailureReasonAsync(
      () => provider.verifyAssertion({ ...fixture.input, evidence }),
      "invalid_assertion_signature",
    );
  });

  it.each([
    {
      name: "disallowed category",
      extensions: { bundleVersion: "42", validationCategory: 5 },
      policy: {
        presence: "required" as const,
        allowedValidationCategories: [2, 4],
        validateBundleVersion: () => true,
      },
      reason: "validation_category_disallowed",
    },
    {
      name: "missing metadata",
      extensions: undefined,
      policy: {
        presence: "required" as const,
        allowedValidationCategories: [2, 4],
        validateBundleVersion: () => true,
      },
      reason: "extensions_required",
    },
    {
      name: "bundle version mismatch",
      extensions: { bundleVersion: "41", validationCategory: 4 },
      policy: {
        presence: "required" as const,
        allowedValidationCategories: [2, 4],
        validateBundleVersion: (version: string) => version === "42",
      },
      reason: "bundle_version_disallowed",
    },
  ])("rejects $name", async ({ extensions, policy, reason }) => {
    const fixture = await createAssertionFixture(extensions);
    const provider = createAssertionProvider(policy);

    await expectFailureReasonAsync(
      () => provider.verifyAssertion(fixture.input),
      reason,
    );
  });
});

function createAssertionProvider(extensions: {
  presence: "if-present" | "required";
  allowedValidationCategories: readonly number[];
  validateBundleVersion: (version: string) => boolean | Promise<boolean>;
}) {
  return appAttest({
    applications: [
      {
        appId: APP_ID,
        platform: "ios",
        environment: "production",
        extensions,
      },
    ],
  });
}

async function createAssertionFixture(
  extensions: { bundleVersion: string; validationCategory: number } | undefined,
  options: { rpId?: string; counter?: number; flags?: number } = {},
) {
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
  });
  const clientDataHash = sha256(Buffer.from("assertion-client-data", "utf8"));
  const authenticatorData = Buffer.concat([
    sha256(Buffer.from(options.rpId ?? APP_ID, "utf8")),
    Buffer.from([options.flags ?? 0]),
    counterBytes(options.counter ?? 1),
    ...(extensions === undefined
      ? []
      : [
          await cbor.encodeAsync({
            apple_bundle_version_01: extensions.bundleVersion,
            apple_validation_category_01: categoryBytes(
              extensions.validationCategory,
            ),
          }),
        ]),
  ]);
  const nonce = sha256(Buffer.concat([authenticatorData, clientDataHash]));
  const signature = sign("sha256", nonce, {
    key: privateKey,
    dsaEncoding: "der",
  });
  const evidence = await cbor.encodeAsync({
    signature,
    authenticatorData,
  });
  const keyId = keyIdentifier(publicKey);
  const credential: StoredAttestationCredential = {
    id: "credential-1",
    lookupKey: "lookup",
    provider: "app-attest",
    applicationId: APP_ID,
    environment: "production",
    publicKey: publicKey
      .export({ format: "der", type: "spki" })
      .toString("base64"),
    counter: 0,
    externallyBound: false,
    bindingVersion: 1,
    status: "active",
    extensionsPresent: false,
  };
  return {
    input: { credential, keyId, clientDataHash, evidence },
  };
}

type AssertionInput = Awaited<
  ReturnType<typeof createAssertionFixture>
>["input"];

function keyIdentifier(publicKey: KeyObject): Buffer {
  const jwk = publicKey.export({ format: "jwk" });
  if (!jwk.x || !jwk.y) {
    throw new TypeError("Generated EC key has no coordinates.");
  }
  return sha256(
    Buffer.concat([
      Buffer.from([0x04]),
      Buffer.from(jwk.x, "base64url"),
      Buffer.from(jwk.y, "base64url"),
    ]),
  );
}

function categoryBytes(category: number): Buffer {
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32LE(category);
  return bytes;
}

function counterBytes(counter: number): Buffer {
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32BE(counter);
  return bytes;
}

async function expectFailureReasonAsync(
  operation: () => Promise<unknown>,
  reason: string,
): Promise<void> {
  try {
    await operation();
  } catch (error) {
    expect(error).toMatchObject({ reason });
    return;
  }
  expect.fail("Expected attestation verification to fail.");
}
