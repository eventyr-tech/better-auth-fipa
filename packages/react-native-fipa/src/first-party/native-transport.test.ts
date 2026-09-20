import { describe, expect, it, vi } from "vitest";
import { createNativeProtocolTransport } from "./native-transport.ts";

function fixture() {
  const controller = new AbortController();
  const native = {
    randomToken: vi.fn().mockResolvedValue("a".repeat(43)),
    transaction: vi.fn().mockResolvedValue({
      id: "i".repeat(43),
      verifier: "v".repeat(43),
      challenge: "c".repeat(43),
    }),
    send: vi.fn().mockResolvedValue({
      url: "https://auth.test/api/auth",
      status: 200,
      headersJSON: "{}",
      body: "{}",
    }),
    cancel: vi.fn().mockResolvedValue(undefined),
  };
  const request = {
    url: "https://auth.test/api/auth",
    method: "POST" as const,
    headers: { DPoP: "test-proof" },
    body: "grant_type=refresh_token",
    signal: controller.signal,
    maximumResponseBytes: 65536,
  };
  return {
    native,
    controller,
    request,
    transport: createNativeProtocolTransport(native),
  };
}
describe("native protocol transport", () => {
  it("passes resource methods and absent bodies to native and decodes response headers", async () => {
    const f = fixture();
    f.native.send.mockResolvedValue({
      url: f.request.url,
      status: 401,
      headersJSON: '{"www-authenticate":"DPoP"}',
      body: "",
    });
    await expect(
      f.transport.send({ ...f.request, method: "GET", body: null }),
    ).resolves.toMatchObject({
      status: 401,
      headers: { "www-authenticate": "DPoP" },
    });
    expect(f.native.send.mock.calls[0]?.[4]).toBeNull();
    f.native.send.mockResolvedValue({
      url: f.request.url,
      status: 200,
      headersJSON: "[]",
      body: "{}",
    });
    await expect(f.transport.send(f.request)).rejects.toMatchObject({
      code: "invalid_response",
    });
  });
  it("uses native request bounds, cancellation IDs and crypto without a fetch fallback", async () => {
    const f = fixture();
    await expect(f.transport.send(f.request)).resolves.toMatchObject({
      status: 200,
      body: "{}",
    });
    expect(f.native.send).toHaveBeenCalledWith(
      "a".repeat(43),
      f.request.url,
      "POST",
      '{"DPoP":"test-proof"}',
      f.request.body,
      65536,
      30000,
      false,
    );
    await expect(f.transport.crypto.transaction()).resolves.toMatchObject({
      verifier: "v".repeat(43),
    });
    f.controller.abort();
    expect(f.native.cancel).not.toHaveBeenCalled();
  });
  it("never sends a pre-cancelled request", async () => {
    const f = fixture();
    f.controller.abort();
    await expect(f.transport.send(f.request)).rejects.toMatchObject({
      code: "cancelled",
    });
    expect(f.native.randomToken).not.toHaveBeenCalled();
    expect(f.native.send).not.toHaveBeenCalled();
  });
  it("checks cancellation again after allocating the native request ID", async () => {
    const f = fixture();
    f.native.randomToken.mockImplementation(() => {
      f.controller.abort();
      return Promise.resolve("a".repeat(43));
    });
    await expect(f.transport.send(f.request)).rejects.toMatchObject({
      code: "cancelled",
    });
    expect(f.native.send).not.toHaveBeenCalled();
  });
  it("finishes cancellation even if the bridge has stopped responding", async () => {
    const f = fixture();
    f.native.send.mockImplementation(() => {
      f.controller.abort();
      return new Promise<never>(() => undefined);
    });
    f.native.cancel.mockRejectedValue(new Error("native detail"));
    await expect(f.transport.send(f.request)).rejects.toMatchObject({
      code: "cancelled",
    });
    expect(f.native.cancel).toHaveBeenCalledWith("a".repeat(43));
  });
  it.each([
    ["http_redirect_rejected", "invalid_response"],
    ["http_response_too_large", "invalid_response"],
    ["http_cancelled", "cancelled"],
    ["unknown", "request_failed"],
  ])("redacts native error %s", async (code, expected) => {
    const f = fixture();
    f.native.send.mockRejectedValue({
      code,
      message: "refresh-token=secret",
      userInfo: "secret",
    });
    const error: unknown = await f.transport
      .send(f.request)
      .catch((value: unknown) => value);
    expect(error).toMatchObject({ code: expected });
    expect(JSON.stringify(error)).not.toContain("secret");
    expect(String(error)).not.toContain("secret");
  });
  it("rejects malformed native results and invalid runtime configuration", async () => {
    const f = fixture();
    f.native.send.mockResolvedValue({ status: 200 });
    await expect(f.transport.send(f.request)).rejects.toMatchObject({
      code: "invalid_response",
    });
    f.native.randomToken.mockResolvedValue("bad");
    await expect(f.transport.send(f.request)).rejects.toMatchObject({
      code: "request_failed",
    });
    f.native.transaction.mockResolvedValue({ verifier: "bad" });
    await expect(f.transport.crypto.transaction()).rejects.toMatchObject({
      code: "operation_failed",
    });
    expect(() =>
      createNativeProtocolTransport(f.native, { timeoutMilliseconds: 0 }),
    ).toThrow();
  });
});
