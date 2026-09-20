import { describe, expect, it } from "vitest";

import { DeviceAttestationError } from "../errors.js";
import { verifyAppAttestPlatformPolicy } from "./platform-policy.js";

const MACOS_ACL_BLOB = Buffer.from(
  "MEAMAjExMDowCQwCb2uhAwEB/zAJDAJvYaEDAQH/MAsMBG9kZWyhAwEB/zAVDARvc2duoAYMBHJzZWMwBaYDAgEB",
  "base64",
);

describe("App Attest platform policy", () => {
  it("accepts iOS evidence without applying the macOS-only policy", () => {
    expect(() => verifyAppAttestPlatformPolicy("ios", undefined)).not.toThrow();
  });

  it("accepts Apple's exact macOS SIP and Full Security ACL Blob", () => {
    expect(() =>
      verifyAppAttestPlatformPolicy("macos", wrapAclBlob(MACOS_ACL_BLOB)),
    ).not.toThrow();
  });

  it("rejects macOS evidence without an ACL Blob", () => {
    expectFailureReason(
      () => verifyAppAttestPlatformPolicy("macos", undefined),
      "missing_macos_acl_blob",
    );
  });

  it("rejects a well-formed macOS ACL Blob with a different policy", () => {
    const mismatched = Buffer.from(MACOS_ACL_BLOB);
    mismatched[0] = (mismatched[0] ?? 0) ^ 1;
    expectFailureReason(
      () => verifyAppAttestPlatformPolicy("macos", wrapAclBlob(mismatched)),
      "macos_acl_policy_mismatch",
    );
  });

  it.each([
    Buffer.alloc(0),
    Buffer.from([0x31, 0]),
    Buffer.from([0x30, 0x03, 0xa3, 0x01, 0x04]),
    Buffer.from([0x30, 0x05, 0xa2, 0x03, 0x04, 0x01, 0]),
    Buffer.from([0x30, 0x05, 0xa3, 0x03, 0x05, 0x01, 0]),
    Buffer.from([0x30, 0x81, 0x05, 0xa3, 0x03, 0x04, 0x01, 0]),
    Buffer.concat([wrapAclBlob(MACOS_ACL_BLOB), Buffer.from([0])]),
  ])("rejects malformed macOS ACL Blob DER %#", (value) => {
    expectFailureReason(
      () =>
        verifyAppAttestPlatformPolicy("macos", Uint8Array.from(value).buffer),
      "invalid_macos_acl_blob",
    );
  });
});

function wrapAclBlob(value: Uint8Array): Buffer {
  const octets = derElement(0x04, value);
  const context = derElement(0xa3, octets);
  return derElement(0x30, context);
}

function derElement(tag: number, value: Uint8Array): Buffer {
  if (value.length >= 0x80) {
    throw new TypeError("Test DER helper supports short lengths only.");
  }
  return Buffer.concat([Buffer.from([tag, value.length]), Buffer.from(value)]);
}

function expectFailureReason(operation: () => unknown, reason: string): void {
  try {
    operation();
  } catch (error) {
    expect(error).toBeInstanceOf(DeviceAttestationError);
    expect(error).toMatchObject({ reason });
    return;
  }
  expect.fail("Expected platform policy verification to fail.");
}
