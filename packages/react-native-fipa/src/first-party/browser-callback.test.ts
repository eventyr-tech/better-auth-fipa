import { describe, expect, it } from "vitest";
import {
  authorizationCallback,
  registeredCallback,
} from "./browser-callback.ts";

describe("browser callback binding", () => {
  const expected = {
    redirectUri: "app.example:/callback?fixed=one",
    state: "state",
    issuer: "https://issuer.example/auth",
  };
  const callback =
    "app.example:/callback?fixed=one&code=one-use-code&state=state&iss=https%3A%2F%2Fissuer.example%2Fauth";
  it("requires the exact registered callback including fixed query fields", () => {
    expect(registeredCallback(expected.redirectUri)).toBe(expected.redirectUri);
    expect(registeredCallback("https://app.example/callback")).toBe(
      "https://app.example/callback",
    );
    expect(authorizationCallback(callback, expected)).toBe("one-use-code");
  });
  it.each([
    "not-url",
    "http://app.example/callback",
    "javascript:alert(1)",
    "data:text/plain,data",
    "file:///callback",
    "about:blank",
    "app.example:/callback#fragment",
    "https://user:pass@app.example/callback",
    "app.example:/callback?code=x",
    "app.example:/callback?state=x",
    "app.example:/callback?iss=x",
    "app.example:/callback?error=x",
  ])("rejects unsafe registration %s", (uri) => {
    expect(() => registeredCallback(uri)).toThrowError(
      expect.objectContaining({ code: "invalid_configuration" }),
    );
  });
  it.each([
    callback.replace("app.example:", "other:"),
    callback.replace("/callback?", "/else?"),
    callback.replace("fixed=one", "fixed=two"),
    callback.replace("state=state", "state=other"),
    callback.replace("issuer.example", "attacker.example"),
    `${callback}&code=second`,
    `${callback}&state=state`,
    `${callback}&iss=https%3A%2F%2Fissuer.example%2Fauth`,
    `${callback}&error=denied`,
    `${callback}&other=value`,
    `${callback}#fragment`,
    callback.replace("code=one-use-code", "code="),
    callback.replace("code=one-use-code", "absent=value"),
    callback.replace("state=state&", ""),
    callback.replace(/&iss=.*/, ""),
    "x".repeat(32769),
  ])("rejects callback substitution or ambiguity %#", (uri) => {
    expect(() => authorizationCallback(uri, expected)).toThrowError(
      expect.objectContaining({ code: "invalid_response" }),
    );
  });
  it("reports a bound OAuth error without leaking its value", () => {
    expect(() =>
      authorizationCallback(
        callback.replace("code=one-use-code", "error=secret-account-detail"),
        expected,
      ),
    ).toThrowError(
      expect.objectContaining({
        code: "browser_failed",
        message: "The authentication operation could not be completed.",
      }),
    );
  });
});
