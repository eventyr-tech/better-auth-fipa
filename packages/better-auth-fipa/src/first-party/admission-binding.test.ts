import { describe, expect, it } from "vitest";
import { hashOAuthBinding } from "../protocol/binding.js";
import {
  hashNativeAdmissionBinding,
  normalizeNativeAdmissionBinding,
  type NativeAdmissionBinding,
} from "./admission-binding.js";

const binding: NativeAdmissionBinding = {
  profile: "device-attestation-fipa-v1",
  mode: "native",
  issuer: "https://auth.example/api/auth",
  clientId: "mobile",
  provider: "apple-app-attest",
  applicationId: "TEAM.app",
  environment: "production",
  attemptId: "a".repeat(22),
  codeChallenge: "c".repeat(43),
  codeChallengeMethod: "S256",
  dpopJkt: "d".repeat(43),
  scopes: ["openid", "offline_access"],
  resources: ["https://api.example"],
  nonce: "nonce",
  acrValues: ["high", "low"],
  maxAge: 0,
};
const hash = (input: NativeAdmissionBinding) =>
  hashNativeAdmissionBinding(input).toString("base64url");

describe("native admission binding", () => {
  it("matches the fixed canonical vector and keeps the legacy binding bytes unchanged", () => {
    expect(hash(binding)).toBe("1DKg0DJjEuipZkhZ5EGvqbcW5oyLprD0m3YKm5Qe2XQ");
    expect(
      hashOAuthBinding({
        clientId: "mobile",
        redirectUri: "app://callback",
        codeChallenge: "challenge",
        codeChallengeMethod: "S256",
        dpopJkt: "thumbprint",
        scope: "openid offline_access",
        resources: ["https://api.example"],
        nonce: "nonce",
      }).toString("base64url"),
    ).toBe("EijLnEao-QQoTKysj0wWv5IWzJIqU3kO8--rQSdLbo8");
  });
  it("canonicalizes sets without reordering assurance preferences or mutating inputs", () => {
    expect(
      hash({ ...binding, scopes: ["offline_access", "openid", "openid"] }),
    ).toBe(hash(binding));
    expect(normalizeNativeAdmissionBinding(binding).scopes).toEqual([
      "offline_access",
      "openid",
    ]);
    expect(binding.scopes).toEqual(["openid", "offline_access"]);
    expect(hash({ ...binding, acrValues: ["low", "high"] })).not.toBe(
      hash(binding),
    );
  });
  it.each([
    { issuer: "https://other.example/api/auth" },
    { clientId: "another" },
    { applicationId: "OTHER.app" },
    { environment: "development" as const },
    { attemptId: "b".repeat(22) },
    { codeChallenge: "e".repeat(43) },
    { dpopJkt: "f".repeat(43) },
    { scopes: ["openid"] },
    { resources: ["https://other.example"] },
    { nonce: "other" },
    { maxAge: 1 },
  ])("binds every transaction field: %j", (change) => {
    expect(hash({ ...binding, ...change })).not.toBe(hash(binding));
  });
  it("keeps resources and nonce distinct and separates absent from explicit assurance fields", () => {
    const {
      nonce: _nonce,
      maxAge: _maxAge,
      acrValues: _acrValues,
      ...plain
    } = binding;
    void _nonce;
    void _maxAge;
    void _acrValues;
    expect(hash(plain)).not.toBe(hash({ ...plain, maxAge: 0 }));
    expect(hash(plain)).not.toBe(hash({ ...plain, acrValues: [] }));
    expect(
      hash({
        ...plain,
        resources: ["https://api.example", "https://second.example"],
        nonce: "https://third.example",
      }),
    ).not.toBe(
      hash({
        ...plain,
        resources: ["https://api.example"],
        nonce: "https://second.example",
      }),
    );
  });
  it("rejects redirect fields, unknown versions, malformed keys and PKCE, and unbounded inputs", () => {
    for (const change of [
      { redirectUri: "app://callback" },
      { profile: "v2" },
      { dpopJkt: "bad" },
      { codeChallengeMethod: "plain" },
      { attemptId: "short" },
      { scopes: ["two scopes"] },
      { resources: ["invalid"] },
    ]) {
      expect(() =>
        normalizeNativeAdmissionBinding({
          ...binding,
          ...change,
        } as NativeAdmissionBinding),
      ).toThrow();
    }
  });
});
