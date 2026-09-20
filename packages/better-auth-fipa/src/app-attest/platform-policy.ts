import { rejection } from "../errors.js";
import { equalBytes } from "../protocol/crypto.js";

/** Apple platform whose App Attest certificate policy the server accepts. */
export type AppAttestPlatform = "ios" | "macos";

const APPLE_MACOS_REQUIRED_ACL_BLOB = Buffer.from(
  "MEAMAjExMDowCQwCb2uhAwEB/zAJDAJvYaEDAQH/MAsMBG9kZWyhAwEB/zAVDARvc2duoAYMBHJzZWMwBaYDAgEB",
  "base64",
);

/**
 * Enforce Apple's signed platform policy before an attested key is trusted.
 *
 * Apple requires native macOS keys to carry OID 1.2.840.113635.100.8.6
 * containing this exact ACL Blob, which represents SIP and Full Security.
 */
export function verifyAppAttestPlatformPolicy(
  platform: AppAttestPlatform,
  aclBlobExtension: Uint8Array | ArrayBuffer | undefined,
): void {
  if (platform === "ios") {
    return;
  }
  if (!aclBlobExtension) {
    throw rejection("platform-policy", "missing_macos_acl_blob");
  }
  const aclBlob = decodeAclBlob(aclBlobExtension);
  if (!equalBytes(aclBlob, APPLE_MACOS_REQUIRED_ACL_BLOB)) {
    throw rejection("platform-policy", "macos_acl_policy_mismatch");
  }
}

function decodeAclBlob(input: Uint8Array | ArrayBuffer): Buffer {
  const bytes =
    input instanceof ArrayBuffer
      ? Buffer.from(input)
      : Buffer.from(input.buffer, input.byteOffset, input.byteLength);
  const sequence = readDerElement(bytes, 0, 0x30);
  if (sequence.end !== bytes.length) {
    throw invalidAclBlob();
  }
  const context = readDerElement(bytes, sequence.contentStart, 0xa3);
  if (context.end !== sequence.end) {
    throw invalidAclBlob();
  }
  const octets = readDerElement(bytes, context.contentStart, 0x04);
  if (octets.end !== context.end) {
    throw invalidAclBlob();
  }
  return Buffer.from(bytes.subarray(octets.contentStart, octets.end));
}

function readDerElement(
  bytes: Buffer,
  offset: number,
  expectedTag: number,
): { contentStart: number; end: number } {
  if (bytes[offset] !== expectedTag) {
    throw invalidAclBlob();
  }
  const firstLength = bytes[offset + 1];
  if (firstLength === undefined) {
    throw invalidAclBlob();
  }

  let length = 0;
  let contentStart = offset + 2;
  if (firstLength < 0x80) {
    length = firstLength;
  } else {
    const lengthBytes = firstLength & 0x7f;
    if (
      lengthBytes === 0 ||
      lengthBytes > 4 ||
      contentStart + lengthBytes > bytes.length ||
      bytes[contentStart] === 0
    ) {
      throw invalidAclBlob();
    }
    for (let index = 0; index < lengthBytes; index += 1) {
      length = length * 256 + (bytes[contentStart + index] ?? 0);
    }
    if (length < 0x80) {
      throw invalidAclBlob();
    }
    contentStart += lengthBytes;
  }
  const end = contentStart + length;
  if (end > bytes.length) {
    throw invalidAclBlob();
  }
  return { contentStart, end };
}

function invalidAclBlob() {
  return rejection("platform-policy", "invalid_macos_acl_blob");
}
