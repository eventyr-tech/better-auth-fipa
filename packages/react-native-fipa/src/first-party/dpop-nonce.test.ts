import { describe, expect, it } from "vitest";
import { rejectedDpopNonce } from "./dpop-nonce.ts";

const response = {
  status: 400,
  body: JSON.stringify({ error: "use_dpop_nonce" }),
  headers: { "DPoP-Nonce": "fresh-nonce" },
};

describe("explicit DPoP nonce rejection", () => {
  it("does not turn ordinary errors or nonce headers on success into retries", () => {
    for (const status of [200, 401, 403, 429, 500])
      expect(rejectedDpopNonce({ ...response, status }, false)).toBeUndefined();
    for (const body of ['{"error":"invalid_grant"}', "invalid-json", "null"])
      expect(rejectedDpopNonce({ ...response, body }, false)).toBeUndefined();
  });
  it.each(["", "bad nonce", "bad\nnonce", 'bad"nonce', "x".repeat(1025)])(
    "rejects missing or invalid nonce value %#",
    (nonce) =>
      expect(() =>
        rejectedDpopNonce(
          { ...response, headers: { "dpop-nonce": nonce } },
          false,
        ),
      ).toThrow(),
  );
  it("rejects ambiguous case-variant duplicate nonce headers", () => {
    expect(() =>
      rejectedDpopNonce(
        { ...response, headers: { "DPoP-Nonce": "one", "dpop-nonce": "two" } },
        false,
      ),
    ).toThrow();
  });
  it("requires one unambiguous DPoP authentication error on resources", () => {
    for (const challenge of [
      undefined,
      'Bearer error="use_dpop_nonce"',
      'DPoP error="invalid_token"',
      'DPoP error="use_dpop_nonce",',
      'DPoP error="use_dpop_nonce", error="other"',
      'DPoP error="use_dpop_nonce", Basic realm="other"',
      'DPoP error="use_dpop_nonce", broken',
    ]) {
      expect(
        rejectedDpopNonce(
          {
            ...response,
            status: 401,
            headers: {
              ...response.headers,
              ...(challenge ? { "WWW-Authenticate": challenge } : {}),
            },
          },
          true,
        ),
      ).toBeUndefined();
    }
    expect(
      rejectedDpopNonce(
        {
          ...response,
          status: 401,
          headers: {
            ...response.headers,
            "WWW-Authenticate":
              'DPoP realm="api, version 1", error=use_dpop_nonce',
          },
        },
        true,
      ),
    ).toBe("fresh-nonce");
  });
});
