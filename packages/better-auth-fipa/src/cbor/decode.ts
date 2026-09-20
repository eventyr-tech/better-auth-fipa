import cbor from "cbor";

import { rejection } from "../errors.js";

export interface DecodedCborItem<T = unknown> {
  value: T;
  bytes: Buffer;
  length: number;
  unused: Buffer;
}

interface CborExtendedResult {
  value: unknown;
  bytes: Buffer;
  length: number;
  unused?: Buffer;
}

export function decodeSingleCbor<T = unknown>(
  input: Uint8Array,
  options: {
    label: string;
    maxDepth?: number;
    allowTrailing?: boolean;
  },
): DecodedCborItem<T> {
  let decoded: CborExtendedResult;

  try {
    decoded = cbor.decodeFirstSync(Buffer.from(input), {
      extendedResults: true,
      max_depth: options.maxDepth ?? 16,
      preventDuplicateKeys: true,
      preferMap: false,
      required: true,
    }) as CborExtendedResult;
  } catch {
    throw rejection("cbor", `invalid_${options.label}_cbor`);
  }

  const unused = decoded.unused ?? Buffer.alloc(0);
  if (!options.allowTrailing && unused.length !== 0) {
    throw rejection("cbor", `trailing_${options.label}_cbor`);
  }

  return {
    value: decoded.value as T,
    bytes: Buffer.from(decoded.bytes),
    length: decoded.length,
    unused: Buffer.from(unused),
  };
}
