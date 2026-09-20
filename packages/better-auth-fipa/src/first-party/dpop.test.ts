import { generateKeyPairSync, sign } from "node:crypto";
import { createInMemoryDpopReplayStore } from "@better-auth/core/oauth2";
import { describe, expect, it } from "vitest";
import { verifyFirstPartyDpop } from "./dpop.js";

const NOW = 1_800_000_000;
const ENDPOINT =
  "https://auth.example/api/auth/first-party/authorization-challenge";
const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });

function makeProof(
  overrides: Record<string, unknown> = {},
  header: Record<string, unknown> = {},
) {
  const encode = (value: unknown) =>
    Buffer.from(JSON.stringify(value)).toString("base64url");
  const unsigned = [
    encode({
      alg: "ES256",
      typ: "dpop+jwt",
      jwk: pair.publicKey.export({ format: "jwk" }),
      ...header,
    }),
    encode({
      htm: "POST",
      htu: ENDPOINT,
      iat: NOW,
      jti: "unique-proof",
      ...overrides,
    }),
  ].join(".");
  return `${unsigned}.${sign("sha256", Buffer.from(unsigned), { key: pair.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url")}`;
}
function input(proof = makeProof()) {
  return {
    headers: new Headers({ dpop: proof }),
    endpointUrl: ENDPOINT,
    method: "POST",
    replayStore: createInMemoryDpopReplayStore(),
    nowSeconds: NOW,
  };
}

describe("first-party challenge proof", () => {
  it("requires actual possession and rejects replay across calls", async () => {
    const request = input();
    const proof = await verifyFirstPartyDpop(request);
    expect(proof.jkt).toMatch(/^[A-Za-z0-9_-]{43}$/);
    await expect(verifyFirstPartyDpop(request)).rejects.toMatchObject({
      code: "invalid_dpop_proof",
    });
  });

  it("accepts the same server-bound key and a matching optional hint", async () => {
    const { jkt } = await verifyFirstPartyDpop(input());
    await expect(
      verifyFirstPartyDpop({
        ...input(makeProof({ jti: "next-step" })),
        expectedJkt: jkt,
        suppliedJkt: jkt,
      }),
    ).resolves.toMatchObject({ jkt });
  });

  it.each([
    { htm: "GET" },
    {
      htu: "https://attacker.example/api/auth/first-party/authorization-challenge",
    },
    { iat: NOW - 61 },
    { iat: NOW + 61 },
    { jti: "" },
  ])("rejects a signed proof with invalid claims %j", async (claims) => {
    await expect(
      verifyFirstPartyDpop(input(makeProof(claims))),
    ).rejects.toMatchObject({ code: "invalid_dpop_proof" });
  });

  it("rejects a conflicting server key or client-supplied hint", async () => {
    await expect(
      verifyFirstPartyDpop({ ...input(), expectedJkt: "another-key" }),
    ).rejects.toMatchObject({ code: "invalid_dpop_proof" });
    await expect(
      verifyFirstPartyDpop({ ...input(), suppliedJkt: "another-key" }),
    ).rejects.toMatchObject({ code: "invalid_dpop_proof" });
  });

  it("rejects missing and oversized proofs even when a thumbprint is supplied", async () => {
    for (const headers of [
      new Headers(),
      new Headers({ dpop: "x".repeat(8193) }),
    ]) {
      await expect(
        verifyFirstPartyDpop({ ...input(), headers, suppliedJkt: "key-hint" }),
      ).rejects.toMatchObject({ code: "invalid_dpop_proof" });
    }
  });

  it("rejects altered signatures and algorithms outside the profile", async () => {
    const valid = makeProof();
    const parts = valid.split(".");
    const signature = Buffer.from(parts[2]!, "base64url");
    signature[0] = signature[0]! ^ 1;
    parts[2] = signature.toString("base64url");
    await expect(
      verifyFirstPartyDpop(input(parts.join("."))),
    ).rejects.toMatchObject({ code: "invalid_dpop_proof" });
    await expect(
      verifyFirstPartyDpop(input(makeProof({}, { alg: "HS256" }))),
    ).rejects.toMatchObject({ code: "invalid_dpop_proof" });
  });

  it("fails closed when the replay database cannot reserve the proof", async () => {
    await expect(
      verifyFirstPartyDpop({
        ...input(),
        replayStore: {
          reserve: () => Promise.reject(new Error("database unavailable")),
        },
      }),
    ).rejects.toThrow("database unavailable");
  });
});
