import { describe, expect, it } from "vitest";

import { DeviceAttestationError } from "../errors.js";
import { parseAppAttestExtensions } from "./extensions.js";

describe("parseAppAttestExtensions", () => {
  it("parses the object shape emitted by cbor", () => {
    expect(
      parseAppAttestExtensions({
        apple_bundle_version_01: "42",
        apple_validation_category_01: Buffer.from([2, 0, 0, 0]),
      }),
    ).toEqual({
      bundleVersion: "42",
      validationCategory: 2,
    });
  });

  it("retains Map and numeric compatibility", () => {
    expect(
      parseAppAttestExtensions(
        new Map<string, unknown>([
          ["apple_bundle_version_01", "43"],
          ["apple_validation_category_01", 4],
        ]),
      ),
    ).toEqual({
      bundleVersion: "43",
      validationCategory: 4,
    });
  });

  it.each([Buffer.alloc(0), Buffer.alloc(1), Buffer.alloc(3), Buffer.alloc(5)])(
    "rejects category byte length %s",
    (category) => {
      expectFailureReason(
        () =>
          parseAppAttestExtensions({
            apple_bundle_version_01: "42",
            apple_validation_category_01: category,
          }),
        "invalid_validation_category_length",
      );
    },
  );

  it.each([-1, 1.5, Number.MAX_SAFE_INTEGER, 0x1_0000_0000])(
    "rejects invalid numeric category %s",
    (category) => {
      expectFailureReason(
        () =>
          parseAppAttestExtensions({
            apple_bundle_version_01: "42",
            apple_validation_category_01: category,
          }),
        "invalid_validation_category",
      );
    },
  );

  it.each(["2", null, {}, true])(
    "rejects unexpected category type %s",
    (category) => {
      expectFailureReason(
        () =>
          parseAppAttestExtensions({
            apple_bundle_version_01: "42",
            apple_validation_category_01: category,
          }),
        "invalid_validation_category_type",
      );
    },
  );

  it("keeps bundle version strictly string-valued", () => {
    expectFailureReason(
      () =>
        parseAppAttestExtensions({
          apple_bundle_version_01: 42,
          apple_validation_category_01: Buffer.from([2, 0, 0, 0]),
        }),
      "invalid_bundle_version",
    );
  });

  it("rejects missing metadata", () => {
    expectFailureReason(
      () =>
        parseAppAttestExtensions({
          apple_validation_category_01: Buffer.from([2, 0, 0, 0]),
        }),
      "missing_apple_bundle_version_01",
    );
  });

  it("does not read inherited properties", () => {
    const inherited = Object.create({
      apple_bundle_version_01: "42",
      apple_validation_category_01: Buffer.from([2, 0, 0, 0]),
    }) as Record<string, unknown>;

    expectFailureReason(
      () => parseAppAttestExtensions(inherited),
      "invalid_extensions_container",
    );
  });
});

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
