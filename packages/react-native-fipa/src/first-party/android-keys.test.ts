import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { androidRegistrationRequestHash } from "../../../better-auth-fipa/src/first-party/android-admission.js";
import { createAndroidKeyPorts } from "./android-keys.ts";
import type {
  FirstPartyClientPorts,
  NativeBinding,
  NativeIdentity,
} from "./client.ts";
import type { Spec as Android } from "../NativeAndroidIntegrity.ts";
import { FirstPartyClientError } from "./errors.ts";

function fixture() {
  let registered = false;
  let existing: string | null = null;
  const jkt = "j".repeat(43);
  const now = Date.now();
  const pending = {
    keyChallengeToken: "k".repeat(43),
    attestationChallenge: "n".repeat(42) + "A",
    issuedAt: new Date(now - 1000).toISOString(),
    expiresAt: new Date(now + 119000).toISOString(),
  };
  const options = {
    issuer: "https://issuer.example/auth/",
    clientId: "mobile",
    applicationId: "com.example.app",
    environment: "production" as const,
    cloudProjectNumber: "123456789012",
    securityLevel: "tee" as const,
    aliases: vi
      .fn()
      .mockResolvedValue({ dpopAlias: "alias", providerScope: "scope" }),
  };
  const integrity = {
    inspectKey: vi.fn<Android["inspectKey"]>(() => Promise.resolve(existing)),
    createKey: vi.fn<Android["createKey"]>(() => {
      existing = jkt;
      return Promise.resolve(jkt);
    }),
    certificateChain: vi
      .fn<Android["certificateChain"]>()
      .mockResolvedValue(Array(5).fill("Y2VydA==") as string[]),
    removeKey: vi.fn<Android["removeKey"]>().mockResolvedValue(undefined),
    signDpop: vi
      .fn<Android["signDpop"]>()
      .mockResolvedValue("header.payload.signature"),
    sha256Utf8: vi.fn<Android["sha256Utf8"]>((value) =>
      Promise.resolve(createHash("sha256").update(value).digest("base64url")),
    ),
    standardIntegrity: vi
      .fn<Android["standardIntegrity"]>()
      .mockResolvedValue("opaque-standard-token"),
  };
  const identity: NativeIdentity = {
    version: 1,
    dpopAlias: "alias",
    providerScope: "scope",
    dpopJkt: jkt,
    providerKeyId: jkt,
    providerRegistration: "generated",
    androidEnrollment: pending,
  };
  const binding: NativeBinding = {
    profile: "device-attestation-fipa-v1",
    mode: "native",
    issuer: "https://issuer.example/auth",
    clientId: options.clientId,
    provider: "android-hardware",
    applicationId: options.applicationId,
    environment: "production",
    attemptId: "a".repeat(43),
    codeChallenge: "c".repeat(43),
    codeChallengeMethod: "S256",
    dpopJkt: jkt,
    scopes: ["profile", "offline_access", "profile"],
    resources: ["https://resource.example/b", "https://resource.example/a"],
  };
  const controller = new AbortController();
  const context = {
    signal: controller.signal,
    saveIdentity: vi.fn((next: NativeIdentity) => {
      Object.assign(identity, next);
      return Promise.resolve();
    }),
  };
  const send = vi.fn<FirstPartyClientPorts["send"]>((request) => {
    let body: unknown,
      status = 200;
    if (request.url.endsWith("/key-challenge")) body = pending;
    else if (request.url.endsWith("/attestation/challenge")) {
      if (!registered) {
        status = 400;
        body = { code: "DEVICE_ATTESTATION_CREDENTIAL_REQUIRED" };
      } else
        body = {
          challengeToken: "t".repeat(43),
          requestHash: "h".repeat(43),
          issuedAt: pending.issuedAt,
          expiresAt: pending.expiresAt,
        };
    } else {
      registered = true;
      body = { grantToken: "grant" };
    }
    return Promise.resolve({
      url: request.url,
      status,
      body: JSON.stringify(body),
    });
  });
  const native = { integrity, send };
  return {
    options,
    pending,
    native,
    keys: createAndroidKeyPorts(options, native),
    identity,
    binding,
    context,
    controller,
    existing: () => {
      existing = jkt;
    },
    registered: () => {
      existing = jkt;
      registered = true;
    },
  };
}

describe("Android registration adapter", () => {
  it("treats expiry of an enrolled key's admission as a retryable request failure, not key recovery", async () => {
    const f = fixture();
    f.registered();
    f.pending.expiresAt = new Date(Date.now() - 1).toISOString();
    await expect(
      f.keys.admission(f.identity, f.binding, f.context),
    ).rejects.toMatchObject({ code: "request_failed" });
    expect(f.native.integrity.createKey).not.toHaveBeenCalled();
    expect(f.native.integrity.standardIntegrity).not.toHaveBeenCalled();
  });
  it("gets a server nonce before key creation and persists its handle in the prepared identity", async () => {
    const f = fixture();
    expect(await f.keys.prepare("slot", f.context)).toEqual(f.identity);
    expect(f.native.integrity.createKey).toHaveBeenCalledWith(
      "alias",
      f.pending.attestationChallenge,
      "tee",
    );
    expect(f.native.send.mock.invocationCallOrder[0]).toBeLessThan(
      f.native.integrity.createKey.mock.invocationCallOrder[0]!,
    );
    expect(f.native.send.mock.calls[0]![0].headers.DPoP).toBeUndefined();
    await expect(
      f.keys.admission(f.identity, f.binding, f.context),
    ).resolves.toBe("grant");
    expect(f.native.integrity.standardIntegrity).toHaveBeenCalledWith(
      f.options.cloudProjectNumber,
      androidRegistrationRequestHash(f.binding, f.pending.attestationChallenge),
    );
    expect(
      f.context.saveIdentity.mock.calls.map(
        ([value]) => value.providerRegistration,
      ),
    ).toEqual(["attesting", "registered"]);
    const requests = f.native.send.mock.calls
      .slice(1)
      .map(([request]) => request);
    expect(requests.map((request) => request.headers.DPoP)).toEqual([
      "header.payload.signature",
      "header.payload.signature",
    ]);
    expect(
      f.native.integrity.signDpop.mock.calls.map((args) => args[2]),
    ).toEqual(requests.map((request) => request.url));
    expect(JSON.parse(requests[1]!.body!)).toEqual({
      binding: f.binding,
      keyChallengeToken: f.pending.keyChallengeToken,
      certificateChain: Array(5).fill("Y2VydA=="),
      integrityToken: "opaque-standard-token",
    });
  });

  it("resumes a durable generated identity after SDK restart without creating a second key", async () => {
    const f = fixture();
    const identity = JSON.parse(
      JSON.stringify(await f.keys.prepare("slot")),
    ) as NativeIdentity;
    const restarted = createAndroidKeyPorts(f.options, f.native);
    await expect(
      restarted.admission(identity, f.binding, f.context),
    ).resolves.toBe("grant");
    expect(f.native.integrity.createKey).toHaveBeenCalledOnce();
  });

  it("recovers a lost successful registration response through a fresh signed admission", async () => {
    const f = fixture();
    f.existing();
    const send = f.native.send.getMockImplementation()!;
    f.native.send.mockImplementation(async (request) => {
      const result = await send(request);
      if (request.url.endsWith("/android/register"))
        throw new Error("lost response containing secret");
      return result;
    });
    await expect(
      f.keys.admission(f.identity, f.binding, f.context),
    ).rejects.toMatchObject({ code: "request_failed" });
    expect(f.identity.providerRegistration).toBe("attesting");
    await expect(
      f.keys.admission(f.identity, f.binding, f.context),
    ).resolves.toBe("grant");
    expect(
      f.native.send.mock.calls.filter(([request]) =>
        request.url.endsWith("/android/register"),
      ),
    ).toHaveLength(1);
    expect(f.native.integrity.standardIntegrity.mock.calls.at(-1)).toEqual([
      f.options.cloudProjectNumber,
      "h".repeat(43),
    ]);
    expect(f.native.integrity.certificateChain).toHaveBeenCalledOnce();
    expect(f.native.integrity.createKey).not.toHaveBeenCalled();
  });

  it.each(["unknown", "registered", "attesting", undefined] as const)(
    "never reenrolls a missing credential in state %s",
    async (state) => {
      const f = fixture();
      f.existing();
      if (state) f.identity.providerRegistration = state;
      else delete f.identity.providerRegistration;
      await expect(
        f.keys.admission(f.identity, f.binding, f.context),
      ).rejects.toMatchObject({ code: "registration_recovery_required" });
      expect(f.native.integrity.standardIntegrity).not.toHaveBeenCalled();
      expect(f.native.integrity.createKey).not.toHaveBeenCalled();
    },
  );

  it("inspects orphaned existing keys and proves registration without replacing them", async () => {
    const f = fixture();
    f.registered();
    const identity = await f.keys.prepare("slot");
    expect(identity.providerRegistration).toBe("unknown");
    expect(identity.androidEnrollment).toBeUndefined();
    expect(f.native.send).not.toHaveBeenCalled();
    await expect(
      f.keys.admission(identity, f.binding, f.context),
    ).resolves.toBe("grant");
    expect(f.native.integrity.createKey).not.toHaveBeenCalled();
    expect(f.native.integrity.certificateChain).not.toHaveBeenCalled();
  });

  it("requires explicit recovery when enrollment metadata is missing or expired", async () => {
    for (const kind of [
      "absent",
      "expired",
      "reversed",
      "oversized",
      "future",
    ] as const) {
      const f = fixture();
      f.existing();
      if (kind === "absent") delete f.identity.androidEnrollment;
      if (kind === "expired")
        f.pending.expiresAt = new Date(Date.now() - 1).toISOString();
      if (kind === "reversed")
        f.pending.issuedAt = new Date(
          Date.parse(f.pending.expiresAt) + 1,
        ).toISOString();
      if (kind === "oversized")
        f.pending.expiresAt = new Date(Date.now() + 600000).toISOString();
      if (kind === "future") {
        f.pending.issuedAt = new Date(Date.now() + 600000).toISOString();
        f.pending.expiresAt = new Date(Date.now() + 610000).toISOString();
      }
      await expect(
        f.keys.admission(f.identity, f.binding, f.context),
      ).rejects.toMatchObject({ code: "registration_recovery_required" });
      expect(f.native.integrity.standardIntegrity).not.toHaveBeenCalled();
    }
  });

  it("does not consume the enrollment handle when native Play fails or journaling fails", async () => {
    const f = fixture();
    f.existing();
    f.native.integrity.standardIntegrity.mockRejectedValueOnce(
      new Error("secret provider detail"),
    );
    await expect(
      f.keys.admission(f.identity, f.binding, f.context),
    ).rejects.toMatchObject({ code: "operation_failed" });
    expect(f.context.saveIdentity).not.toHaveBeenCalled();
    f.context.saveIdentity.mockRejectedValueOnce(
      new FirstPartyClientError("vault_locked"),
    );
    await expect(
      f.keys.admission(f.identity, f.binding, f.context),
    ).rejects.toMatchObject({ code: "vault_locked" });
    expect(
      f.native.send.mock.calls.every(([request]) =>
        request.url.endsWith("/attestation/challenge"),
      ),
    ).toBe(true);
  });

  it("rejects missing or changed keys and cross-application bindings before requesting evidence", async () => {
    const f = fixture();
    await expect(f.keys.assertAvailable(f.identity)).rejects.toMatchObject({
      code: "registration_recovery_required",
    });
    f.native.integrity.inspectKey.mockResolvedValue("x".repeat(43));
    await expect(f.keys.assertAvailable(f.identity)).rejects.toMatchObject({
      code: "registration_recovery_required",
    });
    f.existing();
    for (const changed of [
      { provider: "app-attest" },
      { dpopJkt: "x".repeat(43) },
      { issuer: "https://other.example" },
      { clientId: "other" },
      { applicationId: "other" },
      { environment: "development" as const },
    ]) {
      await expect(
        f.keys.admission(f.identity, { ...f.binding, ...changed }, f.context),
      ).rejects.toMatchObject({ code: "invalid_state" });
    }
    await expect(
      f.keys.assertAvailable({ ...f.identity, providerKeyId: "other" }),
    ).rejects.toMatchObject({ code: "invalid_state" });
    expect(f.native.send).not.toHaveBeenCalled();
  });

  it("removes only the exact retired key and binds access-token proofs", async () => {
    const f = fixture();
    await expect(f.keys.remove(f.identity)).rejects.toMatchObject({
      code: "invalid_state",
    });
    expect(f.native.integrity.removeKey).not.toHaveBeenCalled();
    await f.keys.remove({ ...f.identity, retired: true });
    expect(f.native.integrity.removeKey).toHaveBeenCalledWith(
      "alias",
      f.identity.dpopJkt,
    );
    await f.keys.proof(f.identity, {
      url: "https://resource.example/me",
      method: "GET",
      accessToken: "token",
      nonce: "server-nonce",
    });
    expect(f.native.integrity.signDpop).toHaveBeenCalledWith(
      "alias",
      f.identity.dpopJkt,
      "https://resource.example/me",
      "GET",
      "token",
      "server-nonce",
    );
  });

  it("never interprets HTTP or network failures as permission to enroll", async () => {
    for (const status of [400, 401, 429, 500]) {
      const f = fixture();
      f.existing();
      f.native.send.mockImplementationOnce((request) =>
        Promise.resolve({ url: request.url, status, body: '{"code":"OTHER"}' }),
      );
      await expect(
        f.keys.admission(f.identity, f.binding, f.context),
      ).rejects.toMatchObject({ code: "request_failed" });
      expect(f.native.integrity.standardIntegrity).not.toHaveBeenCalled();
    }
  });

  it("bounds and validates HTTP responses before using a server challenge", async () => {
    for (const response of [
      { url: "https://other.example", status: 200, body: "{}" },
      { status: 302, body: "{}" },
      { status: 200, body: "x".repeat(65537) },
      { status: 200, body: "not-json" },
      { status: 200, body: "{}" },
      { status: 199, body: "{}" },
      { status: 600, body: "{}" },
    ]) {
      const f = fixture();
      f.existing();
      f.native.send.mockImplementationOnce((request) =>
        Promise.resolve({ url: request.url, ...response }),
      );
      await expect(
        f.keys.admission(f.identity, f.binding, f.context),
      ).rejects.toMatchObject({ code: "invalid_response" });
      expect(f.native.integrity.standardIntegrity).not.toHaveBeenCalled();
    }
  });

  it("rejects malformed native outputs without leaking native errors", async () => {
    const f = fixture();
    f.native.integrity.inspectKey.mockResolvedValueOnce("malformed");
    await expect(f.keys.prepare("slot")).rejects.toMatchObject({
      code: "invalid_response",
    });
    f.native.integrity.createKey.mockRejectedValueOnce(new Error("secret"));
    await expect(f.keys.prepare("slot")).rejects.toMatchObject({
      code: "operation_failed",
      message: "The authentication operation could not be completed.",
    });
    f.native.integrity.createKey.mockResolvedValueOnce("malformed");
    await expect(f.keys.prepare("slot")).rejects.toMatchObject({
      code: "invalid_response",
    });
    f.existing();
    f.native.integrity.certificateChain.mockResolvedValueOnce(["YQ=="]);
    await expect(
      f.keys.admission(f.identity, f.binding, f.context),
    ).rejects.toMatchObject({ code: "invalid_response" });
    f.native.integrity.sha256Utf8.mockResolvedValueOnce("bad-hash");
    await expect(
      f.keys.admission(f.identity, f.binding, f.context),
    ).rejects.toMatchObject({ code: "invalid_response" });
    f.native.integrity.standardIntegrity.mockResolvedValueOnce("");
    await expect(
      f.keys.admission(f.identity, f.binding, f.context),
    ).rejects.toMatchObject({ code: "invalid_response" });
    f.native.integrity.signDpop.mockResolvedValueOnce("not a proof");
    await expect(
      f.keys.proof(f.identity, { url: f.binding.issuer, method: "POST" }),
    ).rejects.toMatchObject({ code: "invalid_response" });
  });

  it("checks cancellation around network, key creation, Play and journaling boundaries", async () => {
    for (const boundary of [
      "before",
      "network",
      "key",
      "play",
      "journal",
    ] as const) {
      const f = fixture();
      if (boundary === "before") f.controller.abort();
      if (boundary === "network")
        f.native.send.mockImplementationOnce(() => {
          f.controller.abort();
          return Promise.reject(new Error("cancelled"));
        });
      if (boundary === "key")
        f.native.integrity.createKey.mockImplementationOnce(() => {
          f.controller.abort();
          return Promise.resolve(f.identity.dpopJkt);
        });
      if (["before", "network", "key"].includes(boundary))
        await expect(f.keys.prepare("slot", f.context)).rejects.toMatchObject({
          code: "cancelled",
        });
      else {
        f.existing();
        if (boundary === "play")
          f.native.integrity.standardIntegrity.mockImplementationOnce(() => {
            f.controller.abort();
            return Promise.resolve("token");
          });
        else
          f.context.saveIdentity.mockImplementationOnce(() => {
            f.controller.abort();
            return Promise.resolve();
          });
        await expect(
          f.keys.admission(f.identity, f.binding, f.context),
        ).rejects.toMatchObject({ code: "cancelled" });
        expect(f.native.send.mock.calls).toHaveLength(1);
      }
    }
  });

  it("validates configuration and preserves 64-bit project numbers as decimal strings", async () => {
    const f = fixture();
    for (const change of [
      { issuer: "http://issuer.example" },
      { issuer: "https://user:pass@issuer.example" },
      { issuer: "https://issuer.example/?query" },
      { issuer: "https://issuer.example/#fragment" },
      { issuer: "bad" },
      { clientId: "" },
      { applicationId: "" },
      { cloudProjectNumber: "01" },
      { cloudProjectNumber: "1.5" },
      { cloudProjectNumber: "9223372036854775808" },
      { securityLevel: "software" },
      { environment: "development" },
    ]) {
      expect(() =>
        createAndroidKeyPorts(
          { ...f.options, ...change } as typeof f.options,
          f.native,
        ),
      ).toThrow(FirstPartyClientError);
    }
    expect(() =>
      createAndroidKeyPorts(
        { ...f.options, cloudProjectNumber: "9223372036854775807" },
        f.native,
      ),
    ).not.toThrow();
    expect(() =>
      createAndroidKeyPorts(
        {
          ...f.options,
          issuer: "http://localhost:3000",
          allowInsecureLoopback: true,
        },
        f.native,
      ),
    ).not.toThrow();
    f.options.aliases.mockResolvedValueOnce({
      dpopAlias: "",
      providerScope: "scope",
    });
    await expect(f.keys.prepare("slot")).rejects.toMatchObject({
      code: "invalid_configuration",
    });
    expect(f.native.integrity.createKey).not.toHaveBeenCalled();
  });
});

it.each(["prepare", "admission"] as const)(
  "reports cancellation when native %s fails after abort",
  async (operation) => {
    const f = fixture();
    const fail = () => {
      f.controller.abort();
      return Promise.reject(new Error("native detail"));
    };
    if (operation === "prepare") {
      f.native.integrity.createKey.mockImplementationOnce(fail);
      await expect(f.keys.prepare("slot", f.context)).rejects.toMatchObject({
        code: "cancelled",
      });
    } else {
      f.registered();
      f.native.integrity.standardIntegrity.mockImplementationOnce(fail);
      await expect(
        f.keys.admission(f.identity, f.binding, f.context),
      ).rejects.toMatchObject({ code: "cancelled" });
    }
  },
);
