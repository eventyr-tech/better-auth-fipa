import { rejection } from "../errors.js";

const BUNDLE_VERSION_KEY = "apple_bundle_version_01";
const VALIDATION_CATEGORY_KEY = "apple_validation_category_01";
const UINT32_MAX = 0xffff_ffff;

export interface AppAttestExtensions {
  bundleVersion: string;
  validationCategory: number;
}

export function parseAppAttestExtensions(
  container: unknown,
): AppAttestExtensions {
  if (!isExtensionContainer(container)) {
    throw rejection("distribution-metadata", "invalid_extensions_container");
  }

  const bundleVersion = readExtensionValue(container, BUNDLE_VERSION_KEY);
  const validationCategory = readExtensionValue(
    container,
    VALIDATION_CATEGORY_KEY,
  );

  if (typeof bundleVersion !== "string") {
    throw rejection("distribution-metadata", "invalid_bundle_version");
  }

  return {
    bundleVersion,
    validationCategory: decodeValidationCategory(validationCategory),
  };
}

function isExtensionContainer(
  value: unknown,
): value is Map<unknown, unknown> | Record<string, unknown> {
  if (value instanceof Map) {
    return true;
  }

  if (value === null || typeof value !== "object") {
    return false;
  }

  if (Array.isArray(value) || ArrayBuffer.isView(value)) {
    return false;
  }

  const prototype = Object.getPrototypeOf(value) as unknown;
  return prototype === Object.prototype || prototype === null;
}

function readExtensionValue(
  container: Map<unknown, unknown> | Record<string, unknown>,
  key: string,
): unknown {
  if (container instanceof Map) {
    if (!container.has(key)) {
      throw rejection("distribution-metadata", `missing_${key}`);
    }
    return container.get(key);
  }

  if (!Object.prototype.hasOwnProperty.call(container, key)) {
    throw rejection("distribution-metadata", `missing_${key}`);
  }

  return container[key];
}

function decodeValidationCategory(value: unknown): number {
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0 || value > UINT32_MAX) {
      throw rejection("distribution-metadata", "invalid_validation_category");
    }
    return value;
  }

  if (value instanceof Uint8Array) {
    if (value.byteLength !== 4) {
      throw rejection(
        "distribution-metadata",
        "invalid_validation_category_length",
      );
    }

    return Buffer.from(
      value.buffer,
      value.byteOffset,
      value.byteLength,
    ).readUInt32LE(0);
  }

  throw rejection("distribution-metadata", "invalid_validation_category_type");
}
