import cbor from "cbor";
import { describe, expect, it } from "vitest";

import { DeviceAttestationError } from "../errors.js";
import { decodeSingleCbor } from "./decode.js";

describe("bounded CBOR decoding", () => {
  it("returns exact consumed and unused bytes when trailing data is allowed", async () => {
    const first = await cbor.encodeAsync({ value: 1 });
    const trailing = await cbor.encodeAsync("second");
    const result = decodeSingleCbor(Buffer.concat([first, trailing]), {
      label: "fixture",
      allowTrailing: true,
    });

    expect(result.value).toEqual({ value: 1 });
    expect(result.bytes).toEqual(first);
    expect(result.length).toBe(first.length);
    expect(result.unused).toEqual(trailing);
  });

  it.each([
    {
      name: "truncated input",
      input: Buffer.from([0x5a, 0, 0, 0, 8, 1]),
      reason: "invalid_fixture_cbor",
    },
    {
      name: "duplicate map keys",
      input: Buffer.from([0xa2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02]),
      reason: "invalid_fixture_cbor",
    },
    {
      name: "a second CBOR item",
      input: Buffer.from([0x01, 0x02]),
      reason: "trailing_fixture_cbor",
    },
  ])("rejects $name", ({ input, reason }) => {
    expectFailureReason(
      () => decodeSingleCbor(input, { label: "fixture" }),
      reason,
    );
  });

  it("enforces the configured nesting depth", async () => {
    let value: unknown = "leaf";
    for (let depth = 0; depth < 10; depth += 1) {
      value = [value];
    }
    const encoded = await cbor.encodeAsync(value);

    expectFailureReason(
      () => decodeSingleCbor(encoded, { label: "fixture", maxDepth: 4 }),
      "invalid_fixture_cbor",
    );
  });

  it("fails closed with typed errors for deterministic malformed inputs", () => {
    let state = 0x5eeda11;
    for (let sample = 0; sample < 500; sample += 1) {
      state = (Math.imul(state, 1_664_525) + 1_013_904_223) >>> 0;
      const length = state % 96;
      const input = Buffer.alloc(length);
      for (let index = 0; index < input.length; index += 1) {
        state = (Math.imul(state, 1_664_525) + 1_013_904_223) >>> 0;
        input[index] = state & 0xff;
      }

      try {
        decodeSingleCbor(input, { label: "fuzz", maxDepth: 8 });
      } catch (error) {
        expect(error).toBeInstanceOf(DeviceAttestationError);
      }
    }
  });
});

function expectFailureReason(operation: () => unknown, reason: string): void {
  try {
    operation();
  } catch (error) {
    expect(error).toBeInstanceOf(DeviceAttestationError);
    expect(error).toMatchObject({ reason });
    return;
  }
  expect.fail("Expected CBOR decoding to fail.");
}
