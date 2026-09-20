import { rejection } from "../errors.js";
import { equalBytes } from "../protocol/crypto.js";

const COSE_KEY_TYPE = 1;
const COSE_ALGORITHM = 3;
const COSE_CURVE = -1;
const COSE_X = -2;
const COSE_Y = -3;

export function verifyAppAttestCoseKey(
  value: unknown,
  certifiedPublicKey: Uint8Array,
): void {
  if (!(value instanceof Map)) {
    throw rejection("authenticator-data", "invalid_cose_key_container");
  }
  if (value.size !== 5) {
    throw rejection("authenticator-data", "unexpected_cose_key_fields");
  }
  if (
    value.get(COSE_KEY_TYPE) !== 2 ||
    value.get(COSE_ALGORITHM) !== -7 ||
    value.get(COSE_CURVE) !== 1
  ) {
    throw rejection("authenticator-data", "invalid_cose_key_parameters");
  }

  const x = value.get(COSE_X) as unknown;
  const y = value.get(COSE_Y) as unknown;
  if (
    !(x instanceof Uint8Array) ||
    !(y instanceof Uint8Array) ||
    x.byteLength !== 32 ||
    y.byteLength !== 32
  ) {
    throw rejection("authenticator-data", "invalid_cose_key_coordinates");
  }

  const expected = Buffer.concat([
    Buffer.from([0x04]),
    Buffer.from(x),
    Buffer.from(y),
  ]);
  if (!equalBytes(expected, certifiedPublicKey)) {
    throw rejection("app-identity", "cose_certificate_key_mismatch");
  }
}
