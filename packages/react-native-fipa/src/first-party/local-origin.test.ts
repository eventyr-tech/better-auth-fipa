import { describe, expect, it } from "vitest";
import { normalizeIssuer } from "./adapter-operations.ts";

const localHosts = [
  "localhost",
  "eventyr.localhost",
  "deep.eventyr.localhost",
  "EVENTYR.LocalHost",
  "localhost.",
  "eventyr.localhost.",
  "a-b.localhost",
  "127.0.0.1",
  "[::1]",
];
const nonlocalHosts = [
  "notlocalhost",
  "localhost.example.com",
  "eventyr.localhost.evil.com",
  "evil-localhost",
  ".localhost",
  "a..localhost",
  "-a.localhost",
  "a-.localhost",
  "a_b.localhost",
  "localhost..",
  "eventyr.localhost..",
  "192.168.1.1",
  "127.0.0.2",
  "10.0.2.2",
];
describe("local HTTP issuer policy", () => {
  it.each(localHosts)(
    "accepts %s only with opt-in, with or without a port",
    (host) => {
      for (const port of ["", ":3000"]) {
        const url = `http://${host}${port}/api/auth`;
        expect(normalizeIssuer(url, true)).toBe(new URL(url).href);
        expect(() => normalizeIssuer(url)).toThrow(
          expect.objectContaining({ code: "invalid_configuration" }),
        );
        expect(() => normalizeIssuer(url, false)).toThrow();
      }
    },
  );
  it.each(nonlocalHosts)("rejects %s even with opt-in", (host) => {
    expect(() => normalizeIssuer(`http://${host}:3000`, true)).toThrow(
      expect.objectContaining({ code: "invalid_configuration" }),
    );
  });
  it("preserves credentials, query, fragment and protocol restrictions", () => {
    for (const url of [
      "http://user:pass@eventyr.localhost:3000",
      "http://eventyr.localhost/?query",
      "http://eventyr.localhost/#fragment",
      "ftp://eventyr.localhost",
    ]) {
      expect(() => normalizeIssuer(url, true)).toThrow();
    }
    expect(normalizeIssuer("https://example.com")).toBe("https://example.com");
  });
});
