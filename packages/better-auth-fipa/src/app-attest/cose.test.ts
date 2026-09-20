import { describe, expect, it } from "vitest";

import { DeviceAttestationError } from "../errors.js";
import { verifyAppAttestCoseKey } from "./cose.js";

const X = Buffer.alloc(32, 0x11);
const Y = Buffer.alloc(32, 0x22);
const CERTIFIED_KEY = Buffer.concat([Buffer.from([4]), X, Y]);

describe("App Attest COSE key", () => {
  it("accepts the exact ES256 P-256 key certified by Apple", () => {
    expect(() =>
      verifyAppAttestCoseKey(validCoseKey(), CERTIFIED_KEY),
    ).not.toThrow();
  });

  it.each([
    {
      name: "non-map container",
      value: {},
      reason: "invalid_cose_key_container",
    },
    {
      name: "unexpected field",
      value: new Map([...validCoseKey(), [99, 1]]),
      reason: "unexpected_cose_key_fields",
    },
    {
      name: "wrong key type",
      value: validCoseKey([[1, 3]]),
      reason: "invalid_cose_key_parameters",
    },
    {
      name: "wrong algorithm",
      value: validCoseKey([[3, -8]]),
      reason: "invalid_cose_key_parameters",
    },
    {
      name: "wrong curve",
      value: validCoseKey([[-1, 2]]),
      reason: "invalid_cose_key_parameters",
    },
    {
      name: "short x coordinate",
      value: validCoseKey([[-2, Buffer.alloc(31)]]),
      reason: "invalid_cose_key_coordinates",
    },
    {
      name: "non-byte y coordinate",
      value: validCoseKey([[-3, "not-bytes"]]),
      reason: "invalid_cose_key_coordinates",
    },
    {
      name: "different certified key",
      value: validCoseKey([[-3, Buffer.alloc(32, 0x33)]]),
      reason: "cose_certificate_key_mismatch",
    },
  ])("rejects $name", ({ value, reason }) => {
    expectFailureReason(
      () => verifyAppAttestCoseKey(value, CERTIFIED_KEY),
      reason,
    );
  });
});

function validCoseKey(
  overrides: ReadonlyArray<readonly [number, unknown]> = [],
): Map<number, unknown> {
  const result = new Map<number, unknown>([
    [1, 2],
    [3, -7],
    [-1, 1],
    [-2, X],
    [-3, Y],
  ]);
  for (const [key, value] of overrides) {
    result.set(key, value);
  }
  return result;
}

function expectFailureReason(operation: () => unknown, reason: string): void {
  try {
    operation();
  } catch (error) {
    expect(error).toBeInstanceOf(DeviceAttestationError);
    expect(error).toMatchObject({ reason });
    return;
  }
  expect.fail("Expected COSE verification to fail.");
}
