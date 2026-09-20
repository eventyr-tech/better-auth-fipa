import { rejection } from "../errors.js";

const STANDARD_BASE64 =
  /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u;
const BASE64URL = /^[A-Za-z0-9_-]*$/u;

export function decodeBase64Strict(
  value: string,
  options: {
    maxBytes: number;
    exactBytes?: number;
    label: string;
  },
): Buffer {
  assertEncodedLength(
    value.length,
    standardBase64Length(options.maxBytes),
    options,
  );
  if (!STANDARD_BASE64.test(value)) {
    throw rejection("request", `invalid_${options.label}_base64`);
  }

  assertByteLength(standardBase64DecodedLength(value), options);

  const decoded = Buffer.from(value, "base64");
  assertDecodedLength(decoded, options);

  if (decoded.toString("base64") !== value) {
    throw rejection("request", `non_canonical_${options.label}_base64`);
  }

  return decoded;
}

export function decodeBase64UrlStrict(
  value: string,
  options: {
    maxBytes: number;
    exactBytes?: number;
    label: string;
  },
): Buffer {
  assertEncodedLength(value.length, base64UrlLength(options.maxBytes), options);
  if (!BASE64URL.test(value) || value.length % 4 === 1) {
    throw rejection("request", `invalid_${options.label}_base64url`);
  }

  assertByteLength(base64UrlDecodedLength(value.length), options);

  const decoded = Buffer.from(value, "base64url");
  assertDecodedLength(decoded, options);

  if (decoded.toString("base64url") !== value) {
    throw rejection("request", `non_canonical_${options.label}_base64url`);
  }

  return decoded;
}

function assertDecodedLength(
  decoded: Buffer,
  options: {
    maxBytes: number;
    exactBytes?: number;
    label: string;
  },
): void {
  assertByteLength(decoded.length, options);
}

function assertEncodedLength(
  length: number,
  maximum: number,
  options: { label: string },
): void {
  if (length > maximum) {
    throw rejection("request", `${options.label}_too_large`, {
      encodedEvidenceCharacters: length,
    });
  }
}

function assertByteLength(
  length: number,
  options: {
    maxBytes: number;
    exactBytes?: number;
    label: string;
  },
): void {
  if (length > options.maxBytes) {
    throw rejection("request", `${options.label}_too_large`, {
      evidenceBytes: length,
    });
  }

  if (options.exactBytes !== undefined && length !== options.exactBytes) {
    throw rejection("request", `invalid_${options.label}_length`);
  }
}

/** Maximum canonical padded Base64 length for a decoded byte limit. */
export function standardBase64Length(maxBytes: number): number {
  requireByteLimit(maxBytes);
  const groups = Math.floor(maxBytes / 3);
  const length = groups * 4 + (maxBytes % 3 === 0 ? 0 : 4);
  if (!Number.isSafeInteger(length)) {
    throw new TypeError("The Base64 byte limit is too large to encode safely.");
  }
  return length;
}

function base64UrlLength(maxBytes: number): number {
  requireByteLimit(maxBytes);
  const groups = Math.floor(maxBytes / 3);
  const remainder = maxBytes % 3;
  const length = groups * 4 + (remainder === 0 ? 0 : remainder + 1);
  if (!Number.isSafeInteger(length)) {
    throw new TypeError("The Base64 byte limit is too large to encode safely.");
  }
  return length;
}

function standardBase64DecodedLength(value: string): number {
  const padding = value.endsWith("==") ? 2 : value.endsWith("=") ? 1 : 0;
  return (value.length / 4) * 3 - padding;
}

function base64UrlDecodedLength(length: number): number {
  const groups = Math.floor(length / 4);
  const remainder = length % 4;
  return groups * 3 + (remainder === 0 ? 0 : remainder - 1);
}

function requireByteLimit(maxBytes: number): void {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) {
    throw new TypeError(
      "Base64 byte limits must be non-negative safe integers.",
    );
  }
}
