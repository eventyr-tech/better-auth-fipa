import { describe, expect, it, vi } from "vitest";
import type {
  FirstPartyClientPorts,
  NativeBinding,
  NativeIdentity,
} from "./client.ts";
import { FirstPartyClientError } from "./errors.ts";
import { createIOSKeyPorts } from "./ios-keys.ts";

function fixture() {
  let registered = false;
  const options = {
    issuer: "https://issuer.example/auth/",
    clientId: "mobile",
    applicationId: "TEAM.app",
    environment: "production" as const,
    keyIdStoragePrefix: "test.AppAttest.",
    aliases: vi.fn().mockResolvedValue({
      dpopAlias: "stable-alias",
      providerScope: "stable-scope",
    }),
  };
  const identity: NativeIdentity = {
    version: 1,
    dpopAlias: "stable-alias",
    dpopJkt: "j".repeat(43),
    providerKeyId: "key",
    providerScope: "stable-scope",
    providerRegistration: "generated",
  };
  const binding: NativeBinding = {
    profile: "device-attestation-fipa-v1",
    mode: "native",
    issuer: "https://issuer.example/auth",
    clientId: "mobile",
    applicationId: "TEAM.app",
    provider: "app-attest",
    environment: "production",
    attemptId: "a".repeat(43),
    codeChallenge: "c".repeat(43),
    codeChallengeMethod: "S256",
    dpopJkt: identity.dpopJkt,
    scopes: ["offline_access"],
    resources: [],
  };
  const controller = new AbortController();
  const context = {
    signal: controller.signal,
    saveIdentity: vi.fn((next: NativeIdentity) => {
      Object.assign(identity, next);
      return Promise.resolve();
    }),
  };
  const appAttest = {
    removeKey: vi.fn().mockResolvedValue(undefined),
    getKey: vi.fn().mockResolvedValue("key"),
    getOrCreateKey: vi.fn().mockResolvedValue({ keyId: "key", created: true }),
    generateEvidence: vi
      .fn<(key: string, data: string, operation: string) => Promise<string>>()
      .mockResolvedValue("ZXZpZGVuY2U="),
  };
  const dpop = {
    removeDpop: vi.fn().mockResolvedValue(undefined),
    prepareDpop: vi.fn().mockResolvedValue(identity.dpopJkt),
    inspectDpop: vi.fn().mockResolvedValue(identity.dpopJkt),
    signDpop: vi.fn().mockResolvedValue("header.claims.signature"),
  };
  const send = vi.fn<FirstPartyClientPorts["send"]>((request) => {
    let body: unknown = { challengeToken: "challenge", clientData: "Ynl0ZXM" };
    let status = 200;
    if (
      request.url.endsWith("/first-party/attestation/challenge") &&
      !registered
    ) {
      status = 400;
      body = { code: "DEVICE_ATTESTATION_CREDENTIAL_REQUIRED" };
    } else if (request.url.endsWith("/device-attestation/verify")) {
      registered = true;
      body = {
        credentialId: "credential",
        credentialState: "registered-unbound",
      };
    } else if (request.url.endsWith("/first-party/attestation/verify"))
      body = { grantToken: "grant" };
    return Promise.resolve({
      url: request.url,
      status,
      body: JSON.stringify(body),
    });
  });
  const native = { send, appAttest, dpop };
  const keys = createIOSKeyPorts(options, native);
  return {
    options,
    native,
    keys,
    identity,
    binding,
    context,
    controller,
    registered: () => {
      registered = true;
    },
  };
}

describe("iOS registration adapter", () => {
  it("removes only a confirmed retirement's exact local key references", async () => {
    const f = fixture();
    await expect(f.keys.remove(f.identity)).rejects.toMatchObject({
      code: "invalid_state",
    });
    expect(f.native.appAttest.removeKey).not.toHaveBeenCalled();
    await f.keys.remove({ ...f.identity, retired: true });
    expect(f.native.appAttest.removeKey).toHaveBeenCalledWith(
      "test.AppAttest.",
      "stable-scope",
      "key",
    );
    expect(f.native.dpop.removeDpop).toHaveBeenCalledWith(
      "stable-alias",
      "j".repeat(43),
    );
    f.native.appAttest.removeKey.mockRejectedValue(
      new Error("other identity now occupies the scope"),
    );
    await expect(
      f.keys.remove({ ...f.identity, retired: true }),
    ).rejects.toMatchObject({ code: "operation_failed" });
    expect(f.native.dpop.removeDpop).toHaveBeenCalledOnce();
  });
  it("prepares stable references, registers once and uses native signing with expected thumbprint", async () => {
    const f = fixture();
    await expect(f.keys.prepare("slot")).resolves.toEqual(f.identity);
    await expect(
      f.keys.admission(f.identity, f.binding, f.context),
    ).resolves.toBe("grant");
    expect(
      f.context.saveIdentity.mock.calls.map(
        ([identity]) => identity.providerRegistration,
      ),
    ).toEqual(["attesting", "registered"]);
    expect(
      f.native.appAttest.generateEvidence.mock.calls.map((args) => args[2]),
    ).toEqual(["register", "assert"]);
    await expect(
      f.keys.proof(f.identity, {
        url: "https://issuer.example/resource",
        method: "GET",
        accessToken: "token",
        nonce: "server-nonce",
      }),
    ).resolves.toBe("header.claims.signature");
    expect(f.native.dpop.signDpop).toHaveBeenCalledWith(
      "stable-alias",
      "j".repeat(43),
      "https://issuer.example/resource",
      "GET",
      "token",
      "server-nonce",
    );
    await f.keys.proof(f.identity, {
      url: "https://issuer.example/token",
      method: "POST",
    });
    expect(f.native.dpop.signDpop.mock.calls.at(-1)?.[4]).toBeNull();
    expect(f.native.appAttest.getOrCreateKey).toHaveBeenCalledOnce();
  });

  it("treats retained keys as unknown until a server assertion succeeds", async () => {
    const f = fixture();
    f.native.appAttest.getOrCreateKey.mockResolvedValue({
      keyId: "key",
      created: false,
    });
    const identity = await f.keys.prepare("slot");
    expect(identity.providerRegistration).toBe("unknown");
    Object.assign(f.identity, identity);
    f.registered();
    await expect(
      f.keys.admission(f.identity, f.binding, f.context),
    ).resolves.toBe("grant");
    expect(
      f.native.appAttest.generateEvidence.mock.calls.map((args) => args[2]),
    ).toEqual(["assert"]);
    expect(f.identity.providerRegistration).toBe("registered");
  });

  it.each(["unknown", "attesting", "registered", undefined] as const)(
    "never re-attests a missing server credential in state %s",
    async (state) => {
      const f = fixture();
      if (state) f.identity.providerRegistration = state;
      else delete f.identity.providerRegistration;
      await expect(
        f.keys.admission(f.identity, f.binding, f.context),
      ).rejects.toMatchObject({ code: "registration_recovery_required" });
      expect(f.native.appAttest.generateEvidence).not.toHaveBeenCalled();
      expect(f.context.saveIdentity).not.toHaveBeenCalled();
      expect(f.native.appAttest.getOrCreateKey).not.toHaveBeenCalled();
    },
  );

  it("does not cross the Apple operation boundary when journaling fails", async () => {
    const f = fixture();
    f.context.saveIdentity.mockRejectedValue(
      new FirstPartyClientError("vault_locked"),
    );
    await expect(
      f.keys.admission(f.identity, f.binding, f.context),
    ).rejects.toMatchObject({ code: "vault_locked" });
    expect(f.native.appAttest.generateEvidence).not.toHaveBeenCalled();
  });

  it("checks cancellation before Apple and after an unresponsive native result", async () => {
    const f = fixture();
    f.context.saveIdentity.mockImplementation(() => {
      f.controller.abort();
      return Promise.resolve();
    });
    await expect(
      f.keys.admission(f.identity, f.binding, f.context),
    ).rejects.toMatchObject({ code: "cancelled" });
    expect(f.native.appAttest.generateEvidence).not.toHaveBeenCalled();
    const g = fixture();
    g.registered();
    g.native.appAttest.generateEvidence.mockImplementation(() => {
      g.controller.abort();
      return Promise.resolve("ZXZpZGVuY2U=");
    });
    await expect(
      g.keys.admission(g.identity, g.binding, g.context),
    ).rejects.toMatchObject({ code: "cancelled" });
    expect(g.native.send).toHaveBeenCalledOnce();
  });

  it("refuses missing or mismatched retained native references without creating replacements", async () => {
    const f = fixture();
    f.native.appAttest.getKey.mockResolvedValue(null);
    await expect(f.keys.assertAvailable(f.identity)).rejects.toMatchObject({
      code: "registration_recovery_required",
    });
    f.native.appAttest.getKey.mockResolvedValue("key");
    f.native.dpop.inspectDpop.mockResolvedValue("x".repeat(43));
    await expect(
      f.keys.admission(f.identity, f.binding, f.context),
    ).rejects.toMatchObject({ code: "registration_recovery_required" });
    expect(f.native.dpop.prepareDpop).not.toHaveBeenCalled();
    expect(f.native.appAttest.getOrCreateKey).not.toHaveBeenCalled();
    expect(f.native.send).not.toHaveBeenCalled();
  });

  it("rejects wrong application, key or issuer binding before provider work", async () => {
    for (const changed of [
      { provider: "other" },
      { dpopJkt: "x".repeat(43) },
      { issuer: "https://other.example" },
      { clientId: "other" },
      { applicationId: "TEAM.other" },
      { environment: "development" as const },
    ]) {
      const f = fixture();
      await expect(
        f.keys.admission(f.identity, { ...f.binding, ...changed }, f.context),
      ).rejects.toMatchObject({ code: "invalid_state" });
      expect(f.native.send).not.toHaveBeenCalled();
    }
  });

  it("does not interpret network or server failures as missing registration", async () => {
    for (const status of [400, 401, 429, 500]) {
      const f = fixture();
      f.native.send.mockImplementationOnce((request) =>
        Promise.resolve({
          url: request.url,
          status,
          body: JSON.stringify({ code: "OTHER" }),
        }),
      );
      await expect(
        f.keys.admission(f.identity, f.binding, f.context),
      ).rejects.toMatchObject({ code: "request_failed" });
      expect(f.context.saveIdentity).not.toHaveBeenCalled();
      expect(f.native.appAttest.generateEvidence).not.toHaveBeenCalled();
    }
  });

  it("rejects redirected, oversized, malformed and incomplete challenge responses", async () => {
    for (const response of [
      { url: "https://other.example", status: 200, body: "{}" },
      { status: 302, body: "{}" },
      { status: 200, body: "x".repeat(65537) },
      { status: 200, body: "broken-json" },
      { status: 200, body: "{}" },
      { status: 0, body: "{}" },
    ]) {
      const f = fixture();
      f.native.send.mockImplementationOnce((request) =>
        Promise.resolve({ url: request.url, ...response }),
      );
      await expect(
        f.keys.admission(f.identity, f.binding, f.context),
      ).rejects.toMatchObject({ code: "invalid_response" });
      expect(f.native.appAttest.generateEvidence).not.toHaveBeenCalled();
    }
  });

  it("sanitizes native failures and rejects malformed native keys, evidence and proofs", async () => {
    const f = fixture();
    f.native.dpop.prepareDpop.mockRejectedValue(
      new Error("secret native detail"),
    );
    await expect(f.keys.prepare("slot")).rejects.toMatchObject({
      code: "operation_failed",
      message: "The authentication operation could not be completed.",
    });
    f.native.dpop.prepareDpop.mockResolvedValue("malformed");
    await expect(f.keys.prepare("slot")).rejects.toMatchObject({
      code: "invalid_response",
    });
    f.native.dpop.prepareDpop.mockResolvedValue("j".repeat(43));
    f.native.appAttest.getOrCreateKey.mockResolvedValue({
      keyId: "",
      created: true,
    });
    await expect(f.keys.prepare("slot")).rejects.toMatchObject({
      code: "invalid_response",
    });
    f.native.dpop.signDpop.mockResolvedValue("bad jwt");
    await expect(
      f.keys.proof(f.identity, { url: f.binding.issuer, method: "POST" }),
    ).rejects.toMatchObject({ code: "invalid_response" });
    f.native.appAttest.generateEvidence.mockResolvedValue("bad evidence");
    await expect(
      f.keys.admission(f.identity, f.binding, f.context),
    ).rejects.toMatchObject({ code: "invalid_response" });
  });

  it("rejects unsafe configuration and invalid slot aliases before creating keys", async () => {
    const f = fixture();
    for (const issuer of [
      "http://issuer.example",
      "https://user:pass@issuer.example",
      "https://issuer.example/#fragment",
      "not-url",
    ])
      expect(() =>
        createIOSKeyPorts({ ...f.options, issuer }, f.native),
      ).toThrow(FirstPartyClientError);
    expect(() =>
      createIOSKeyPorts(
        {
          ...f.options,
          issuer: "http://localhost:3000",
          allowInsecureLoopback: true,
        },
        f.native,
      ),
    ).not.toThrow();
    f.options.aliases.mockResolvedValue({
      dpopAlias: "",
      providerScope: "scope",
    });
    await expect(f.keys.prepare("slot")).rejects.toMatchObject({
      code: "invalid_configuration",
    });
    expect(f.native.dpop.prepareDpop).not.toHaveBeenCalled();
  });
});
