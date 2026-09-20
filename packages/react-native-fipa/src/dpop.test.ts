import { describe, expect, it, vi } from "vitest";
import { createDpopClient } from "./dpop.ts";
import type { DpopNative } from "./types.ts";
import { serverError } from "./errors.ts";

describe("extracted DPoP integration", () => {
  function native() {
    return {
      generateProof: vi.fn().mockResolvedValue({
        proof: "proof",
        getPublicKeyThumbprint: () => Promise.resolve("jkt"),
      }),
      assertHardwareBacked: vi.fn().mockResolvedValue(undefined),
      deleteKeyPair: vi.fn().mockResolvedValue(undefined),
    } satisfies DpopNative;
  }
  it("preserves aliases, strips query/fragment, requires hardware, and forwards nonce and token", async () => {
    const adapter = native();
    const client = createDpopClient(
      "io.eventyr.mobile.dpop.user.v2.account-a",
      adapter,
    );
    await expect(
      client.generateProofAndThumbprint({
        method: "POST",
        url: "https://example.com/token?code=secret#fragment",
        nonce: "nonce",
        accessToken: "token",
      }),
    ).resolves.toEqual({ proof: "proof", thumbprint: "jkt" });
    expect(adapter.generateProof).toHaveBeenCalledWith({
      alias: "io.eventyr.mobile.dpop.user.v2.account-a",
      htm: "POST",
      htu: "https://example.com/token",
      nonce: "nonce",
      accessToken: "token",
      requireHardwareBacked: true,
    });
    await expect(
      client.generateProof({ method: "GET", url: "https://example.com" }),
    ).resolves.toBe("proof");
    await client.assertHardwareBacked();
    expect(adapter.deleteKeyPair).not.toHaveBeenCalled();
    await client.deleteKey();
    expect(adapter.deleteKeyPair).toHaveBeenCalledExactlyOnceWith(
      "io.eventyr.mobile.dpop.user.v2.account-a",
    );
  });
  it("rejects invalid aliases and URLs and contains native errors", async () => {
    const adapter = native();
    expect(() => createDpopClient("", adapter)).toThrow(TypeError);
    const client = createDpopClient("key", adapter);
    for (const url of [
      "file:///tmp",
      "https://user:secret@example.com",
      "bad-url",
    ]) {
      await expect(
        client.generateProof({ method: "POST", url }),
      ).rejects.toMatchObject({ code: "DEVICE_ATTESTATION_DPOP_ERROR" });
    }
    vi.mocked(adapter.generateProof).mockRejectedValue(
      new Error("SECRET alias"),
    );
    await expect(
      client.generateProof({ method: "GET", url: "https://example.com" }),
    ).rejects.toThrow("This app instance could not be verified.");
  });
  it("keeps only known public codes and handles retry seconds/dates and absent or malformed headers", () => {
    expect(
      serverError(new Response(null, { status: 429 }), { code: "SECRET" }),
    ).toMatchObject({ code: "DEVICE_ATTESTATION_RATE_LIMITED" });
    expect(
      serverError(new Response(null, { status: 500 }), null),
    ).toMatchObject({ code: "DEVICE_ATTESTATION_REQUEST_FAILED" });
    for (const value of ["5", new Date(Date.now() + 60_000).toUTCString()]) {
      expect(
        serverError(
          new Response(null, {
            status: 429,
            headers: { "Retry-After": value },
          }),
          {},
        ).retryAfterSeconds,
      ).toBeGreaterThan(0);
    }
    expect(
      serverError(
        new Response(null, {
          status: 429,
          headers: { "Retry-After": "invalid" },
        }),
        {},
      ).retryAfterSeconds,
    ).toBeUndefined();
  });
});
