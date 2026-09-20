import { describe, expect, it, vi } from "vitest";

import { DeviceAttestationError } from "../errors.js";
import { decodeBase64Strict, decodeBase64UrlStrict } from "./base64.js";

describe("strict base64 decoding", () => {
  it("accepts canonical standard base64", () => {
    expect(
      decodeBase64Strict("AQIDBA==", {
        label: "evidence",
        maxBytes: 4,
        exactBytes: 4,
      }),
    ).toEqual(Buffer.from([1, 2, 3, 4]));
  });

  it("rejects oversized standard base64 before allocating the decoded buffer", () => {
    const bufferFrom = vi.spyOn(Buffer, "from");
    try {
      expectFailureReason(
        () =>
          decodeBase64Strict("AQIDBAU=", {
            label: "evidence",
            maxBytes: 4,
          }),
        "evidence_too_large",
      );
      expect(bufferFrom).not.toHaveBeenCalled();
    } finally {
      bufferFrom.mockRestore();
    }
  });

  it("rejects overlong standard base64 before syntax validation", () => {
    expectFailureReason(
      () =>
        decodeBase64Strict("*".repeat(12), {
          label: "evidence",
          maxBytes: 4,
        }),
      "evidence_too_large",
    );
  });

  it.each(["AQIDBA", "AQIDBA=", "AQIDBA===", "AQID BA==", "***="])(
    "rejects non-canonical standard base64 %s",
    (value) => {
      expect(() =>
        decodeBase64Strict(value, {
          label: "evidence",
          maxBytes: 100,
        }),
      ).toThrow(DeviceAttestationError);
    },
  );

  it("accepts unpadded canonical base64url", () => {
    expect(
      decodeBase64UrlStrict("AQIDBA", {
        label: "token",
        maxBytes: 4,
        exactBytes: 4,
      }),
    ).toEqual(Buffer.from([1, 2, 3, 4]));
  });

  it("rejects oversized base64url before allocating the decoded buffer", () => {
    const bufferFrom = vi.spyOn(Buffer, "from");
    try {
      expectFailureReason(
        () =>
          decodeBase64UrlStrict("AQIDBAU", {
            label: "token",
            maxBytes: 4,
          }),
        "token_too_large",
      );
      expect(bufferFrom).not.toHaveBeenCalled();
    } finally {
      bufferFrom.mockRestore();
    }
  });

  it.each(["AQIDBA==", "AQIDBA+", "AQID BA", "a"])(
    "rejects non-canonical base64url %s",
    (value) => {
      expect(() =>
        decodeBase64UrlStrict(value, {
          label: "token",
          maxBytes: 100,
        }),
      ).toThrow(DeviceAttestationError);
    },
  );
});

function expectFailureReason(operation: () => unknown, reason: string): void {
  try {
    operation();
  } catch (error) {
    expect(error).toBeInstanceOf(DeviceAttestationError);
    expect(error).toMatchObject({ reason });
    return;
  }
  expect.fail("Expected strict decoding to fail.");
}
