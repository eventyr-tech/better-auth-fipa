import { createHash, generateKeyPairSync, sign, verify } from "node:crypto";
import { betterAuth } from "better-auth";
import {
  createDeviceAttestation,
  type DeviceAttestationProvider,
} from "@eventyr-tech/better-auth-fipa";
import { describe, expect, it, vi } from "vitest";
import { createAppAttestClient } from "./client.ts";
import { DeviceAttestationClientError } from "./errors.ts";
import type {
  AppAttestNative,
  AppAttestKey,
  OAuthAuthorizationBinding,
} from "./types.ts";

const binding: OAuthAuthorizationBinding = {
  clientId: "mobile",
  redirectUri: "example:/callback",
  codeChallenge: "c".repeat(43),
  codeChallengeMethod: "S256",
  dpopJkt: "d".repeat(43),
  scope: "openid profile",
};
const options = {
  authBaseURL: "http://localhost:3000/api/auth",
  applicationId: "TEAM.example",
  keyIdStoragePrefix: "Example.v1.",
};
const response = (
  body: unknown,
  status = 200,
  headers?: Record<string, string>,
) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });

function bridge() {
  return {
    getOrCreateKey: vi
      .fn<AppAttestNative["getOrCreateKey"]>()
      .mockResolvedValue({ created: true, keyId: "key" }),
    generateEvidence: vi
      .fn<AppAttestNative["generateEvidence"]>()
      .mockResolvedValue("evidence"),
    resetKey: vi.fn<AppAttestNative["resetKey"]>().mockResolvedValue(undefined),
  };
}
function registrationAndGrant(
  fetch: ReturnType<typeof vi.fn<typeof globalThis.fetch>>,
) {
  return fetch
    .mockResolvedValueOnce(
      response({ challengeToken: "register", clientData: "YQ" }),
    )
    .mockResolvedValueOnce(
      response({
        credentialId: "credential",
        credentialState: "registered-unbound",
      }),
    )
    .mockResolvedValueOnce(
      response({ challengeToken: "assert", clientData: "Yg" }),
    )
    .mockResolvedValueOnce(
      response({ grantToken: "grant", credentialState: "asserted" }),
    );
}

describe("extracted App Attest lifecycle", () => {
  it("registers before asserting, preserves binding, URL and native scope, and omits cookies", async () => {
    const native = bridge();
    const fetch = registrationAndGrant(vi.fn<typeof globalThis.fetch>());
    const client = createAppAttestClient({ ...options, fetch }, native);
    await expect(client.prepareOAuthGrant("account-a", binding)).resolves.toBe(
      "grant",
    );
    expect(native.getOrCreateKey).toHaveBeenCalledWith(
      "Example.v1.",
      "account-a",
    );
    expect(native.generateEvidence.mock.calls).toEqual([
      ["key", "YQ", "register"],
      ["key", "Yg", "assert"],
    ]);
    expect(fetch.mock.calls[0]?.[0]).toBe(
      "http://localhost:3000/api/auth/device-attestation/challenge",
    );
    expect(fetch.mock.calls[0]?.[1]).toMatchObject({
      credentials: "omit",
      redirect: "error",
    });
    expect(JSON.parse(fetch.mock.calls[2]?.[1]?.body as string)).toEqual({
      provider: "app-attest",
      applicationId: "TEAM.example",
      operation: "assert",
      purpose: "oauth-authorization",
      keyId: "key",
      binding,
    });
  });

  it("probes a retained key after a lost registration response instead of re-attesting", async () => {
    const native = bridge();
    native.getOrCreateKey.mockResolvedValue({
      created: false,
      keyId: "retained",
    });
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValueOnce(
        response({ challengeToken: "assert", clientData: "Yg" }),
      )
      .mockResolvedValueOnce(
        response({ grantToken: "grant", credentialState: "asserted" }),
      );
    await createAppAttestClient(
      { ...options, fetch },
      native,
    ).prepareOAuthGrant("a", binding);
    expect(native.generateEvidence).toHaveBeenCalledExactlyOnceWith(
      "retained",
      "Yg",
      "assert",
    );
    expect(native.resetKey).not.toHaveBeenCalled();
  });

  it("replaces a server-missing key exactly once", async () => {
    const native = bridge();
    native.getOrCreateKey
      .mockResolvedValueOnce({ created: false, keyId: "old" })
      .mockResolvedValueOnce({ created: true, keyId: "new" });
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValueOnce(
        response({ code: "DEVICE_ATTESTATION_CREDENTIAL_REQUIRED" }, 403),
      );
    registrationAndGrant(fetch);
    await expect(
      createAppAttestClient({ ...options, fetch }, native).prepareOAuthGrant(
        "a",
        binding,
      ),
    ).resolves.toBe("grant");
    expect(native.resetKey).toHaveBeenCalledExactlyOnceWith("Example.v1.", "a");
    expect(
      native.generateEvidence.mock.calls.every(([key]) => key === "new"),
    ).toBe(true);
  });

  it("preserves issuance purpose and advanced evidence without a second verify", async () => {
    const native = bridge();
    const fetch = registrationAndGrant(vi.fn<typeof globalThis.fetch>());
    const client = createAppAttestClient({ ...options, fetch }, native);
    const issuance = {
      namespace: "demo",
      subject: "ceremony",
      dpopJkt: binding.dpopJkt,
    };
    await client.prepareCredentialIssuanceGrant("device", issuance);
    expect(JSON.parse(fetch.mock.calls[2]?.[1]?.body as string)).toMatchObject({
      purpose: "credential-issuance",
      binding: issuance,
    });
    native.getOrCreateKey.mockResolvedValue({ created: false, keyId: "key" });
    fetch.mockResolvedValueOnce(
      response({ challengeToken: "advanced", clientData: "Yw" }),
    );
    await expect(client.prepareOAuthEvidence("a", binding)).resolves.toEqual({
      challengeToken: "advanced",
      keyId: "key",
      evidence: "evidence",
    });
    expect(fetch).toHaveBeenCalledTimes(5);
  });

  it.each([403, 429, 500])(
    "does not reset keys or retry a failed request (%s)",
    async (status) => {
      const native = bridge();
      native.getOrCreateKey.mockResolvedValue({ created: false, keyId: "key" });
      const fetch = vi
        .fn<typeof globalThis.fetch>()
        .mockResolvedValue(
          response(
            { code: "DEVICE_ATTESTATION_REJECTED", message: "secret" },
            status,
            { "X-Retry-After": "37" },
          ),
        );
      await expect(
        createAppAttestClient({ ...options, fetch }, native).prepareOAuthGrant(
          "a",
          binding,
        ),
      ).rejects.toMatchObject({
        status,
        retryAfterSeconds: 37,
        message: "This app instance could not be verified.",
      });
      expect(native.resetKey).not.toHaveBeenCalled();
      expect(fetch).toHaveBeenCalledTimes(1);
    },
  );

  it("rejects malformed successes, network failures and native exceptions without leaking details", async () => {
    for (const mode of [
      "shape",
      "registration",
      "grant",
      "json",
      "network",
      "native",
    ]) {
      const native = bridge();
      const fetch = vi.fn<typeof globalThis.fetch>();
      if (mode === "network")
        fetch.mockRejectedValue(new Error("SECRET request body"));
      else if (mode === "native")
        native.getOrCreateKey.mockRejectedValue(new Error("SECRET key ID"));
      else if (mode === "json")
        fetch.mockResolvedValue(new Response("bad json"));
      else if (mode === "registration")
        fetch
          .mockResolvedValueOnce(
            response({ challengeToken: "a", clientData: "YQ" }),
          )
          .mockResolvedValueOnce(response({ credentialState: "asserted" }));
      else if (mode === "grant") {
        native.getOrCreateKey.mockResolvedValue({
          created: false,
          keyId: "key",
        });
        fetch
          .mockResolvedValueOnce(
            response({ challengeToken: "a", clientData: "YQ" }),
          )
          .mockResolvedValueOnce(response({ credentialState: "asserted" }));
      } else fetch.mockResolvedValue(response({ clientData: "YQ" }));
      const error = await createAppAttestClient({ ...options, fetch }, native)
        .prepareOAuthGrant("a", binding)
        .catch((error: unknown) => error);
      expect(error).toBeInstanceOf(DeviceAttestationClientError);
      expect(JSON.stringify(error)).not.toContain("SECRET");
    }
  });

  it("serializes across client instances until the host consumes evidence, and releases failed locks", async () => {
    const native = bridge();
    native.getOrCreateKey.mockResolvedValue({ created: false, keyId: "key" });
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockImplementation(() =>
        Promise.resolve(response({ challengeToken: "a", clientData: "YQ" })),
      );
    const first = createAppAttestClient({ ...options, fetch }, native);
    const second = createAppAttestClient({ ...options, fetch }, native);
    let release!: () => void;
    let entered!: () => void;
    const started = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const hold = new Promise<void>((resolve) => {
      release = resolve;
    });
    const attempt = first.withOAuthEvidence("a", binding, async () => {
      entered();
      await hold;
      throw new Error("host failure");
    });
    await started;
    const following = second.resetKey("a");
    expect(native.resetKey).not.toHaveBeenCalled();
    release();
    await expect(attempt).rejects.toThrow("host failure");
    await following;
    expect(native.resetKey).toHaveBeenCalledOnce();
  });

  it("validates configuration and empty credential scopes", async () => {
    for (const authBaseURL of [
      "file:///tmp",
      "https://user:password@example.com",
      "https://example.com?secret=1",
      "https://example.com#fragment",
    ]) {
      expect(() =>
        createAppAttestClient({ ...options, authBaseURL }, bridge()),
      ).toThrow(TypeError);
    }
    expect(() =>
      createAppAttestClient({ ...options, applicationId: "" }, bridge()),
    ).toThrow(TypeError);
    await expect(
      createAppAttestClient(options, bridge()).resetKey(""),
    ).rejects.toThrow(TypeError);
  });
});

describe("client to real Better Auth plugin contract", () => {
  it("registers, returns, isolates accounts, consumes purpose-bound grants, and recovers after retirement", async () => {
    // Synthetic native evidence exercises transport/state; it is not an Apple attestation fixture.
    const keys = new Map<
      string,
      ReturnType<typeof generateKeyPairSync> & { counter: number }
    >();
    const scopes = new Map<string, string>();
    const native: AppAttestNative = {
      getOrCreateKey(prefix, scope): Promise<AppAttestKey> {
        const storageKey = prefix + scope;
        const prior = scopes.get(storageKey);
        if (prior) return Promise.resolve({ created: false, keyId: prior });
        const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
        const keyId = createHash("sha256")
          .update(pair.publicKey.export({ type: "spki", format: "der" }))
          .digest("base64");
        keys.set(keyId, { ...pair, counter: 0 });
        scopes.set(storageKey, keyId);
        return Promise.resolve({ created: true, keyId });
      },
      generateEvidence(keyId, data, operation) {
        const key = keys.get(keyId)!;
        const counter = operation === "register" ? 0 : ++key.counter;
        const hash = createHash("sha256")
          .update(Buffer.from(data, "base64url"))
          .digest();
        return Promise.resolve(
          Buffer.from(
            JSON.stringify({
              counter,
              signature: sign(
                "sha256",
                Buffer.concat([hash, Buffer.from(String(counter))]),
                key.privateKey,
              ).toString("base64"),
            }),
          ).toString("base64"),
        );
      },
      resetKey(prefix, scope) {
        scopes.delete(prefix + scope);
        return Promise.resolve();
      },
    };
    const provider: DeviceAttestationProvider = {
      id: "app-attest",
      maxEvidenceBytes: 4096,
      decodeKeyId: (value) => Buffer.from(value, "base64"),
      verifyRegistration(input) {
        const key = keys.get(Buffer.from(input.keyId).toString("base64"))!;
        return Promise.resolve({
          applicationId: input.applicationId,
          environment: "development",
          counter: 0,
          extensionsPresent: false,
          publicKey: key.publicKey
            .export({ type: "spki", format: "der" })
            .toString("base64"),
        });
      },
      verifyAssertion(input) {
        const evidence = JSON.parse(Buffer.from(input.evidence).toString()) as {
          counter: number;
          signature: string;
        };
        const key = keys.get(Buffer.from(input.keyId).toString("base64"))!;
        expect(
          verify(
            "sha256",
            Buffer.concat([
              Buffer.from(input.clientDataHash),
              Buffer.from(String(evidence.counter)),
            ]),
            key.publicKey,
            Buffer.from(evidence.signature, "base64"),
          ),
        ).toBe(true);
        expect(evidence.counter).toBeGreaterThan(input.credential.counter);
        return Promise.resolve({
          counter: evidence.counter,
          extensionsPresent: false,
        });
      },
    };
    const composition = createDeviceAttestation({
      providers: [provider],
      purposes: {
        credentialRegistration: {},
        oauthAuthorization: {
          protectedClientIds: ["mobile"],
          requireDpopJkt: true,
        },
        credentialIssuance: {
          allowedNamespaces: ["demo"],
          requireDpopJkt: true,
        },
      },
    });
    const auth = betterAuth({
      baseURL: "http://localhost:3000",
      secret: "reference-test-secret-at-least-32-characters",
      plugins: [composition.serverPlugin],
    });
    const fetch: typeof globalThis.fetch = (input, init) =>
      auth.handler(new Request(input, init));
    const client = createAppAttestClient({ ...options, fetch }, native);
    const first = await client.prepareOAuthGrant("a", binding);
    const consumed = await composition.consumeOAuthAuthorizationGrant({
      grantToken: first,
      binding,
      userId: "user-a",
    });
    await expect(
      composition.consumeOAuthAuthorizationGrant({
        grantToken: first,
        binding,
        userId: "user-a",
      }),
    ).rejects.toThrow();
    const second = await client.prepareOAuthGrant("a", binding);
    expect(
      (
        await composition.consumeOAuthAuthorizationGrant({
          grantToken: second,
          binding,
          userId: "user-a",
        })
      ).credentialId,
    ).toBe(consumed.credentialId);
    const other = await client.prepareOAuthGrant("b", binding);
    expect(
      (
        await composition.consumeOAuthAuthorizationGrant({
          grantToken: other,
          binding,
          userId: "user-b",
        })
      ).credentialId,
    ).not.toBe(consumed.credentialId);
    const wrongUser = await client.prepareOAuthGrant("a", binding);
    await expect(
      composition.consumeOAuthAuthorizationGrant({
        grantToken: wrongUser,
        binding,
        userId: "user-b",
      }),
    ).rejects.toThrow();
    const issuance = {
      namespace: "demo",
      subject: "ceremony",
      dpopJkt: binding.dpopJkt,
    };
    const grant = await client.prepareCredentialIssuanceGrant(
      "device",
      issuance,
    );
    await expect(
      composition.consumeCredentialIssuanceGrant({
        grantToken: grant,
        binding: issuance,
      }),
    ).resolves.toHaveProperty("credentialId");
    const wrongPurpose = await client.prepareCredentialIssuanceGrant(
      "device",
      issuance,
    );
    await expect(
      composition.consumeOAuthAuthorizationGrant({
        grantToken: wrongPurpose,
        binding,
        userId: "user-a",
      }),
    ).rejects.toThrow();
    const context = await auth.$context;
    await context.adapter.update({
      model: "deviceAttestationCredential",
      where: [{ field: "id", value: consumed.credentialId }],
      update: { status: "revoked", revocationReason: "user" },
    });
    const recovery = await client.prepareOAuthGrant("a", binding);
    expect(
      (
        await composition.consumeOAuthAuthorizationGrant({
          grantToken: recovery,
          binding,
          userId: "user-a",
        })
      ).credentialId,
    ).not.toBe(consumed.credentialId);
  });
});
