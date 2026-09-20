import cbor from "cbor";
import { describe, expect, it } from "vitest";

import { DeviceAttestationError } from "../errors.js";
import {
  AUTHENTICATOR_DATA_FLAGS,
  parseAuthenticatorData,
} from "./authenticator-data.js";
import { parseAppAttestExtensions } from "./extensions.js";

const RP_ID_HASH = Buffer.alloc(32, 0x11);
const AAGUID = Buffer.alloc(16, 0x22);
const CREDENTIAL_ID = Buffer.alloc(32, 0x33);
const COSE_KEY = new Map<number, number | Buffer>([
  [1, 2],
  [3, -7],
  [-1, 1],
  [-2, Buffer.alloc(32, 0x44)],
  [-3, Buffer.alloc(32, 0x55)],
]);

describe("parseAuthenticatorData", () => {
  it("parses attested credential data and object-shaped extensions", async () => {
    const extensions = {
      apple_bundle_version_01: "42",
      apple_validation_category_01: Buffer.from([2, 0, 0, 0]),
    };
    const input = await createAttestationAuthenticatorData(extensions);

    const result = parseAuthenticatorData(input, {
      mode: "attestation",
      maxBytes: 4096,
    });

    expect(result.rpIdHash).toEqual(RP_ID_HASH);
    expect(result.counter).toBe(0);
    expect(result.flags).toBe(
      AUTHENTICATOR_DATA_FLAGS.AT | AUTHENTICATOR_DATA_FLAGS.ED,
    );
    expect(result.attestedCredentialData?.aaguid).toEqual(AAGUID);
    expect(result.attestedCredentialData?.credentialId).toEqual(CREDENTIAL_ID);
    expect(result.attestedCredentialData?.credentialPublicKey).toEqual(
      COSE_KEY,
    );
    expect(parseAppAttestExtensions(result.extensions)).toEqual({
      bundleVersion: "42",
      validationCategory: 2,
    });
  });

  it("parses assertion extensions immediately after the fixed fields", async () => {
    const extensionBytes = await cbor.encodeAsync({
      apple_bundle_version_01: "99",
      apple_validation_category_01: Buffer.from([4, 0, 0, 0]),
    });
    const input = Buffer.concat([
      createFixedAuthenticatorData(AUTHENTICATOR_DATA_FLAGS.ED, 7),
      extensionBytes,
    ]);

    const result = parseAuthenticatorData(input, {
      mode: "assertion",
      maxBytes: 4096,
    });

    expect(result.counter).toBe(7);
    expect(parseAppAttestExtensions(result.extensions)).toEqual({
      bundleVersion: "99",
      validationCategory: 4,
    });
  });

  it("uses the decoded COSE length instead of a fixed credential offset", async () => {
    const largerCoseKey = new Map(COSE_KEY);
    largerCoseKey.set(99, Buffer.alloc(97, 0x66));
    const extensionBytes = await cbor.encodeAsync({
      apple_bundle_version_01: "42",
      apple_validation_category_01: Buffer.from([2, 0, 0, 0]),
    });
    const input = await createAttestationAuthenticatorData(
      extensionBytes,
      await cbor.encodeAsync(largerCoseKey),
    );

    const result = parseAuthenticatorData(input, {
      mode: "attestation",
      maxBytes: 4096,
    });

    expect(result.attestedCredentialData?.credentialPublicKey).toEqual(
      largerCoseKey,
    );
    expect(parseAppAttestExtensions(result.extensions).validationCategory).toBe(
      2,
    );
  });

  it("rejects extension bytes when ED is clear", async () => {
    const input = Buffer.concat([
      createFixedAuthenticatorData(0, 1),
      await cbor.encodeAsync({ unexpected: true }),
    ]);

    expectFailureReason(
      () =>
        parseAuthenticatorData(input, {
          mode: "assertion",
          maxBytes: 4096,
        }),
      "unexpected_authenticator_data",
    );
  });

  it("parses one unflagged extension map for the App Attest profile", async () => {
    const extensionBytes = await cbor.encodeAsync({
      apple_bundle_version_01: "100",
      apple_validation_category_01: Buffer.from([4, 0, 0, 0]),
    });
    const input = Buffer.concat([
      createFixedAuthenticatorData(0, 8),
      extensionBytes,
    ]);

    const result = parseAuthenticatorData(input, {
      mode: "assertion",
      maxBytes: 4096,
      allowUnflaggedExtensions: true,
    });

    expect(result.flags).toBe(0);
    expect(parseAppAttestExtensions(result.extensions)).toEqual({
      bundleVersion: "100",
      validationCategory: 4,
    });
  });

  it("accepts Apple's fixed assertion data when the AT bit is set", () => {
    const input = createFixedAuthenticatorData(AUTHENTICATOR_DATA_FLAGS.AT, 9);

    const result = parseAuthenticatorData(input, {
      mode: "assertion",
      maxBytes: 4096,
    });

    expect(result.flags).toBe(AUTHENTICATOR_DATA_FLAGS.AT);
    expect(result.counter).toBe(9);
    expect(result.attestedCredentialData).toBeUndefined();
  });

  it("rejects actual attested credential bytes in an assertion", async () => {
    const input = await createAttestationAuthenticatorData();

    expectFailureReason(
      () =>
        parseAuthenticatorData(input, {
          mode: "assertion",
          maxBytes: 4096,
        }),
      "unexpected_authenticator_data",
    );
  });

  it("rejects attestation authenticator data without AT", () => {
    const input = createFixedAuthenticatorData(0, 0);

    expectFailureReason(
      () =>
        parseAuthenticatorData(input, {
          mode: "attestation",
          maxBytes: 4096,
        }),
      "missing_attested_credential_data",
    );
  });

  it("rejects an invalid credential length", () => {
    const credentialLength = Buffer.alloc(2);
    credentialLength.writeUInt16BE(512);
    const input = Buffer.concat([
      createFixedAuthenticatorData(AUTHENTICATOR_DATA_FLAGS.AT, 0),
      AAGUID,
      credentialLength,
      CREDENTIAL_ID,
    ]);

    expectFailureReason(
      () =>
        parseAuthenticatorData(input, {
          mode: "attestation",
          maxBytes: 4096,
        }),
      "invalid_credential_id_length",
    );
  });
});

async function createAttestationAuthenticatorData(
  extensions?: unknown,
  coseBytes?: Buffer,
): Promise<Buffer> {
  const flags =
    AUTHENTICATOR_DATA_FLAGS.AT |
    (extensions === undefined ? 0 : AUTHENTICATOR_DATA_FLAGS.ED);
  const credentialLength = Buffer.alloc(2);
  credentialLength.writeUInt16BE(CREDENTIAL_ID.length);
  const resolvedCoseBytes = coseBytes ?? (await cbor.encodeAsync(COSE_KEY));
  const extensionBytes =
    extensions === undefined
      ? Buffer.alloc(0)
      : Buffer.isBuffer(extensions)
        ? extensions
        : await cbor.encodeAsync(extensions);

  return Buffer.concat([
    createFixedAuthenticatorData(flags, 0),
    AAGUID,
    credentialLength,
    CREDENTIAL_ID,
    resolvedCoseBytes,
    extensionBytes,
  ]);
}

function createFixedAuthenticatorData(flags: number, counter: number): Buffer {
  const counterBytes = Buffer.alloc(4);
  counterBytes.writeUInt32BE(counter);
  return Buffer.concat([RP_ID_HASH, Buffer.from([flags]), counterBytes]);
}

function expectFailureReason(operation: () => unknown, reason: string): void {
  try {
    operation();
  } catch (error) {
    expect(error).toBeInstanceOf(DeviceAttestationError);
    expect((error as DeviceAttestationError).reason).toBe(reason);
    return;
  }

  expect.fail("Expected a DeviceAttestationError");
}
