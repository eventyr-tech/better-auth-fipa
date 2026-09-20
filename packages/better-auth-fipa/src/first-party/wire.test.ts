import { describe, expect, it } from "vitest";
import { FIRST_PARTY_PROFILE, parseFirstPartyWireRequest } from "./wire.js";

const prefix = `profile=${FIRST_PARTY_PROFILE}`;
const form = (
  body: string,
  contentType = "application/x-www-form-urlencoded",
) =>
  new Request(
    "https://auth.example/api/auth/first-party/authorization-challenge",
    { method: "POST", headers: { "content-type": contentType }, body },
  );
const parse = (request: Request, legacyEnabled = false) =>
  parseFirstPartyWireRequest(request, { legacyEnabled });

describe("shared first-party endpoint wire dispatch", () => {
  it("parses new requests and preserves repeated resources without mutating binding values", async () => {
    expect(
      await parse(
        form(
          `${prefix}&client_id=mobile&scope=openid+offline_access&resource=https%3A%2F%2Fapi.example&resource=urn%3Asecond`,
        ),
      ),
    ).toEqual({
      protocol: "fipa-v1",
      parameters: {
        profile: FIRST_PARTY_PROFILE,
        client_id: "mobile",
        scope: "openid offline_access",
        resource: ["https://api.example", "urn:second"],
      },
    });
  });

  it("accepts legacy JSON only when explicitly enabled", async () => {
    const body = JSON.stringify({
      client_id: "mobile",
      device_attestation: { key_id: "old" },
    });
    await expect(parse(form(body, "application/json"))).rejects.toMatchObject({
      statusCode: 415,
    });
    expect(await parse(form(body, "application/json"), true)).toEqual({
      protocol: "legacy-v1",
      parameters: JSON.parse(body) as unknown,
    });
  });

  it.each([
    "",
    "profile=unknown",
    `${prefix}&profile=${FIRST_PARTY_PROFILE}`,
    `${prefix}&client_id=a&client_id=b`,
    `${prefix}&%63lient_id=a&client_id=b`,
    `${prefix}&redirect_uri=old`,
    `${prefix}&__proto__=polluted`,
    `${prefix}&response=%GG`,
    `${prefix}&response=%FF`,
    `${prefix}&resource=`,
    `${prefix}&resource=a&resource=a`,
    `${prefix}${Array.from({ length: 9 }, (_, i) => `&resource=urn:${i}`).join("")}`,
  ])(
    "rejects ambiguous or invalid new requests even with compatibility enabled: %s",
    async (body) => {
      await expect(parse(form(body), true)).rejects.toMatchObject({
        statusCode: 400,
      });
    },
  );

  it("never routes a new profile marker through legacy JSON", async () => {
    await expect(
      parse(
        form(
          JSON.stringify({ profile: FIRST_PARTY_PROFILE }),
          "application/json",
        ),
        true,
      ),
    ).rejects.toMatchObject({ statusCode: 400 });
  });

  it.each(["null", "[]", "bad-json"])(
    "rejects invalid legacy objects: %s",
    async (body) => {
      await expect(
        parse(form(body, "application/json"), true),
      ).rejects.toMatchObject({ statusCode: 400 });
    },
  );

  it("rejects unsupported methods, media types, and character encodings", async () => {
    await expect(
      parse(new Request("https://auth.example", { method: "GET" })),
    ).rejects.toMatchObject({ statusCode: 405 });
    for (const type of [
      "text/plain",
      "application/x-www-form-urlencoded; charset=latin1",
      "",
    ]) {
      await expect(parse(form(prefix, type))).rejects.toMatchObject({
        statusCode: 415,
      });
    }
    await expect(
      parse(form(prefix, "application/x-www-form-urlencoded; charset=UTF-8")),
    ).resolves.toMatchObject({ protocol: "fipa-v1" });
  });

  it("bounds actual body bytes, not a claimed Content-Length", async () => {
    const request = form(`${prefix}&response=${"x".repeat(16384)}`);
    request.headers.set("content-length", "1");
    await expect(parse(request)).rejects.toMatchObject({ statusCode: 413 });
  });

  it("rejects malformed UTF-8 and absent bodies", async () => {
    const request = new Request("https://auth.example", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new Uint8Array([255]),
    });
    await expect(parse(request)).rejects.toMatchObject({ statusCode: 400 });
    await expect(
      parse(
        new Request("https://auth.example", {
          method: "POST",
          headers: { "content-type": "application/json" },
        }),
        true,
      ),
    ).rejects.toMatchObject({ statusCode: 400 });
  });
});
