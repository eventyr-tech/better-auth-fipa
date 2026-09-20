import { createAuthEndpoint } from "better-auth/api";
import {
  requireNativeAccess,
  type NativeTokenOptions,
} from "../../../better-auth-fipa/src/first-party/token-lifecycle.js";
import { createAndroidFirstPartyClient } from "./android-client.ts";
import { createMemorySessionVaultCollection } from "../test-fixtures/session-vault.ts";
import { createHash, randomBytes, randomUUID, sign } from "node:crypto";
import { oauthProvider } from "@better-auth/oauth-provider";
import type { BetterAuthPlugin } from "better-auth";
import { getTestInstance } from "better-auth/test";
import { twoFactor } from "better-auth/plugins";
import { describe, expect, it, vi } from "vitest";
import { createAndroidHardwareProvider } from "../../../better-auth-fipa/src/android/provider.js";
import {
  policy,
  signer,
} from "../../../better-auth-fipa/src/android/fixtures/key-description.fixture.js";
import { attestedKey } from "../../../better-auth-fipa/src/android/fixtures/attested-key.fixture.js";
import { createNativeFirstPartyPlugin } from "../../../better-auth-fipa/src/first-party/plugin.js";
import { createAndroidKeyPorts } from "./android-keys.ts";
import type {
  FirstPartyClientPorts,
  NativeBinding,
  NativeIdentity,
} from "./client.ts";

/** Actual SDK/server HTTP, DPoP verification, X.509 verification and SQL storage.
 * The native key and Google verdict are test doubles, not device evidence. */
async function nativeFixture() {
  let key: Awaited<ReturnType<typeof attestedKey>> | undefined;
  const verdicts = new Map<string, unknown>();
  let lastHash = "";
  let lostResponse = false;
  let lostTokenResponse = false;
  const google: typeof fetch = (url, init) => {
    if (url === "https://android.googleapis.com/attestation/root")
      return Promise.resolve(
        Response.json([key!.root], {
          headers: {
            "cache-control": "max-age=3600",
            date: new Date().toUTCString(),
          },
        }),
      );
    if (url === "https://android.googleapis.com/attestation/status")
      return Promise.resolve(
        Response.json(
          { entries: {} },
          {
            headers: {
              "cache-control": "max-age=3600",
              date: new Date().toUTCString(),
            },
          },
        ),
      );
    const value = (
      JSON.parse(init!.body as string) as { integrity_token: string }
    ).integrity_token;
    const verdict = verdicts.get(value);
    verdicts.delete(value);
    return Promise.resolve(Response.json(verdict ?? {}));
  };
  const provider = createAndroidHardwareProvider(
    {
      key: policy,
      play: {
        packageName: policy.packageName,
        policyVersion: "test-v1",
        signingCertificateSets: [[signer.toString("base64url")]],
        minimumVersionCode: "42",
        maxAgeSeconds: 120,
        clockSkewSeconds: 0,
        requireStrongIntegrity: false,
        getAccessToken: () => Promise.resolve("test-only-token"),
      },
    },
    { fetch: google },
  );
  const oauthOptions = {
    loginPage: "/login",
    consentPage: "/consent",
    disableJwtPlugin: true,
    scopes: ["offline_access"],
  };
  const oauth = oauthProvider(oauthOptions);
  let browserOTP = "";
  const nativeOptions: NativeTokenOptions = {
    browser: { loginPage: "/login" },
    oauth: oauthOptions,
    applications: [
      {
        clientId: "android-mobile",
        provider,
        applicationId: policy.packageName,
        environment: "production",
        scopes: ["offline_access"],
        resources: [],
      },
    ],
    lifetimes: {
      sessionIdleSeconds: 600,
      sessionAbsoluteSeconds: 3600,
      familyLifetimeSeconds: 3600,
      evidenceMaxAgeSeconds: 300,
    },
    accessTokenSeconds: 300,
    maximumAssuranceAgeSeconds: 3600,
  };
  const { auth, testUser } = await getTestInstance(
    {
      plugins: [
        twoFactor({
          otpOptions: {
            sendOTP: ({ otp }) => {
              browserOTP = otp;
              return Promise.resolve();
            },
          },
        }),
        {
          ...oauth,
          endpoints: oauth.endpoints as unknown as NonNullable<
            BetterAuthPlugin["endpoints"]
          >,
        },
        createNativeFirstPartyPlugin(nativeOptions),
        {
          id: "android-sdk-resource",
          endpoints: {
            sdkResource: createAuthEndpoint(
              "/sdk-resource",
              { method: "GET", requireRequest: true },
              async (ctx) => {
                const access = await requireNativeAccess(ctx, nativeOptions, {
                  headers: ctx.request.headers,
                  method: ctx.request.method,
                  url: `${ctx.context.baseURL}/sdk-resource`,
                  scopes: ["offline_access"],
                });
                return ctx.json({ userId: access.userId });
              },
            ),
          },
        },
      ],
    },
    { testWith: "sqlite", transaction: true },
  );
  const ctx = await auth.$context;
  const completeBrowser = async (url: string) => {
    const cookies = new Map<string, string>();
    const request = async (url: string, body?: object) => {
      const response = await auth.handler(
        new Request(url, {
          method: body ? "POST" : "GET",
          headers: {
            "content-type": "application/json",
            origin: new URL(ctx.baseURL).origin,
            cookie: [...cookies]
              .map(([key, value]) => `${key}=${value}`)
              .join("; "),
          },
          ...(body ? { body: JSON.stringify(body) } : {}),
        }),
      );
      for (const header of response.headers.getSetCookie()) {
        const pair = header.split(";")[0]!;
        const index = pair.indexOf("="),
          name = pair.slice(0, index),
          value = pair.slice(index + 1);
        if (value) cookies.set(name, value);
        else cookies.delete(name);
      }
      return response;
    };
    expect((await request(url)).status).toBe(302);
    const password = await request(`${ctx.baseURL}/sign-in/email`, {
      email: testUser.email,
      password: testUser.password,
    });
    expect(await password.json()).toMatchObject({ twoFactorRedirect: true });
    expect(
      (await request(`${ctx.baseURL}/two-factor/send-otp`, {})).status,
    ).toBe(200);
    expect(
      (
        await request(`${ctx.baseURL}/two-factor/verify-otp`, {
          code: browserOTP,
        })
      ).status,
    ).toBe(200);
    const completed = await request(
      `${ctx.baseURL}/first-party/browser/complete`,
    );
    expect(completed.status).toBe(302);
    return completed.headers.get("location")!;
  };
  await ctx.adapter.create({
    model: "oauthClient",
    data: {
      clientId: "android-mobile",
      redirectUris: ["example:/callback"],
      tokenEndpointAuthMethod: "none",
      grantTypes: ["authorization_code", "refresh_token"],
      scopes: ["offline_access"],
      disabled: false,
    },
  });
  const requests: Array<{
    path: string;
    status: number;
    dpop: string | undefined;
  }> = [];
  const send: FirstPartyClientPorts["send"] = async (request) => {
    const response = await auth.handler(
      new Request(request.url, {
        method: request.method,
        headers: request.headers,
        body: request.body,
        signal: request.signal,
      }),
    );
    requests.push({
      path: new URL(request.url).pathname,
      status: response.status,
      dpop: request.headers.DPoP,
    });
    if (
      lostTokenResponse &&
      request.url.endsWith("/oauth2/token") &&
      response.status === 200
    ) {
      lostTokenResponse = false;
      throw new Error("test lost token response");
    }
    if (
      lostResponse &&
      request.url.endsWith("/android/register") &&
      response.status === 200
    ) {
      lostResponse = false;
      throw new Error("test lost response");
    }
    return {
      url: request.url,
      status: response.status,
      body: await response.text(),
    };
  };
  const options = {
    issuer: ctx.baseURL,
    clientId: "android-mobile",
    applicationId: policy.packageName,
    environment: "production" as const,
    cloudProjectNumber: "123456789012",
    securityLevel: "tee" as const,
    // Better Auth's test server uses a synthetic loopback origin.
    allowInsecureLoopback: true,
    aliases: () =>
      Promise.resolve({ dpopAlias: "slot-key", providerScope: "slot-scope" }),
  };
  const native = {
    send,
    integrity: {
      inspectKey: () => Promise.resolve(key?.jkt ?? null),
      createKey: vi.fn(async (_alias: string, nonce: string) => {
        if (key) throw new Error("No replacement");
        key = await attestedKey(Buffer.from(nonce, "base64url"));
        return key.jkt;
      }),
      certificateChain: () => Promise.resolve(key!.chain),
      removeKey: vi.fn((_alias: string, expected: string) => {
        expect(expected).toBe(key!.jkt);
        key = undefined;
        return Promise.resolve();
      }),
      sha256Utf8: (value: string) =>
        Promise.resolve(createHash("sha256").update(value).digest("base64url")),
      signDpop: (
        _alias: string,
        jkt: string,
        url: string,
        method: string,
        accessToken?: string | null,
      ) => {
        expect(jkt).toBe(key!.jkt);
        const enc = (value: unknown) =>
          Buffer.from(JSON.stringify(value)).toString("base64url");
        const endpoint = new URL(url);
        endpoint.search = "";
        endpoint.hash = "";
        const input = `${enc({ alg: "ES256", typ: "dpop+jwt", jwk: key!.jwk })}.${enc({ htu: endpoint.href, htm: method, iat: Math.floor(Date.now() / 1000), jti: randomUUID(), ...(accessToken ? { ath: createHash("sha256").update(accessToken).digest("base64url") } : {}) })}`;
        return Promise.resolve(
          `${input}.${sign("sha256", Buffer.from(input), { key: key!.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url")}`,
        );
      },
      standardIntegrity: (_project: string, requestHash: string) => {
        expect(requestHash).not.toBe(lastHash);
        lastHash = requestHash;
        const value = randomUUID();
        verdicts.set(value, {
          tokenPayloadExternal: {
            requestDetails: {
              requestPackageName: policy.packageName,
              requestHash,
              timestampMillis: String(Date.now()),
            },
            appIntegrity: {
              appRecognitionVerdict: "PLAY_RECOGNIZED",
              packageName: policy.packageName,
              certificateSha256Digest: [signer.toString("base64url")],
              versionCode: "42",
            },
            accountDetails: { appLicensingVerdict: "LICENSED" },
            deviceIntegrity: {
              deviceRecognitionVerdict: ["MEETS_DEVICE_INTEGRITY"],
            },
          },
        });
        return Promise.resolve(value);
      },
    },
  };
  return {
    auth,
    testUser,
    ctx,
    native,
    options,
    requests,
    completeBrowser,
    loseRegistrationResponse: () => {
      lostResponse = true;
    },
    loseTokenResponse: () => {
      lostTokenResponse = true;
    },
  };
}

async function fixture() {
  const base = await nativeFixture();
  const { ctx, native, options, requests } = base;
  const keys = createAndroidKeyPorts(options, native);
  const identity = await keys.prepare("slot");
  const binding: NativeBinding = {
    profile: "device-attestation-fipa-v1",
    mode: "native",
    issuer: ctx.baseURL,
    clientId: options.clientId,
    provider: "android-hardware",
    applicationId: policy.packageName,
    environment: "production",
    dpopJkt: identity.dpopJkt,
    attemptId: "a".repeat(43),
    codeChallenge: "c".repeat(43),
    codeChallengeMethod: "S256",
    scopes: ["offline_access"],
    resources: [],
  };
  const context = {
    signal: new AbortController().signal,
    saveIdentity: (next: NativeIdentity) => {
      Object.assign(identity, next);
      return Promise.resolve();
    },
  };
  return {
    ctx,
    keys,
    identity,
    binding,
    context,
    requests,
    native,
    options,
    loseRegistrationResponse: base.loseRegistrationResponse,
  };
}

describe("Android SDK/server admission contract", () => {
  it("enrolls the actual proof key once, then verifies fresh standard evidence after restart", async () => {
    const f = await fixture();
    await expect(
      f.keys.admission(f.identity, f.binding, f.context),
    ).resolves.toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(f.identity.providerRegistration).toBe("registered");
    const restored = JSON.parse(JSON.stringify(f.identity)) as NativeIdentity;
    const restarted = createAndroidKeyPorts(f.options, f.native);
    await expect(
      restarted.admission(restored, f.binding, f.context),
    ).resolves.toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(f.native.integrity.createKey).toHaveBeenCalledOnce();
    expect(f.requests.map((request) => request.status)).toEqual([
      200, 400, 200, 200, 200,
    ]);
    expect(
      f.requests
        .slice(1)
        .every((request) => request.dpop?.split(".").length === 3),
    ).toBe(true);
    const rows = await f.ctx.adapter.findMany<{
      dpopJkt: string;
      status: string;
    }>({ model: "firstPartyAndroidKey" });
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      dpopJkt: f.identity.dpopJkt,
      status: "active",
    });
  });

  it("recovers a committed enrollment after a lost response without reusing its one-time nonce", async () => {
    const f = await fixture();
    f.loseRegistrationResponse();
    await expect(
      f.keys.admission(f.identity, f.binding, f.context),
    ).rejects.toMatchObject({ code: "request_failed" });
    expect(f.identity.providerRegistration).toBe("attesting");
    await expect(
      f.keys.admission(f.identity, f.binding, f.context),
    ).resolves.toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(
      f.requests.filter((request) =>
        request.path.endsWith("/android/register"),
      ),
    ).toHaveLength(1);
    expect(f.native.integrity.createKey).toHaveBeenCalledOnce();
  });
});

async function composedFixture() {
  const f = await nativeFixture();
  const storage = createMemorySessionVaultCollection();
  const forbidden = vi.fn(() =>
    Promise.reject(new Error("iOS-only signing path")),
  );
  const random = () => randomBytes(32).toString("base64url");
  const transport: Parameters<
    typeof createAndroidFirstPartyClient
  >[1]["transport"] = {
    randomToken: () => Promise.resolve(random()),
    transaction: () => {
      const verifier = random();
      return Promise.resolve({
        id: random(),
        verifier,
        challenge: createHash("sha256").update(verifier).digest("base64url"),
      });
    },
    prepareDpop: forbidden,
    inspectDpop: forbidden,
    removeDpop: forbidden,
    signDpop: forbidden,
    send: async (_id, url, method, headersJSON, body, maximumResponseBytes) => {
      const response = await f.native.send({
        url,
        method: method as "POST",
        headers: JSON.parse(headersJSON) as Record<string, string>,
        body,
        maximumResponseBytes,
        signal: new AbortController().signal,
      });
      return {
        ...response,
        headersJSON: JSON.stringify(response.headers ?? {}),
      };
    },
    cancel: () => Promise.resolve(),
    openBrowser: vi.fn(() =>
      Promise.reject(
        Object.assign(new Error("Unavailable"), {
          code: "browser_unavailable",
        }),
      ),
    ),
    cancelBrowser: vi.fn(() => Promise.resolve()),
  };
  const config = {
    issuer: f.ctx.baseURL,
    clientId: f.options.clientId,
    applicationId: f.options.applicationId,
    environment: "production" as const,
    scopes: ["offline_access"],
    resources: [],
    allowInsecureLoopback: true,
    browser: { redirectUri: "example:/callback" },
    android: {
      cloudProjectNumber: f.options.cloudProjectNumber,
      securityLevel: "tee" as const,
    },
  };
  const native = {
    integrity: f.native.integrity,
    transport,
    vault: storage.native,
    recovery: {
      prepare: () => Promise.resolve(null),
      recover: () => Promise.resolve(false),
    },
  };
  const make = (configuration = config) =>
    createAndroidFirstPartyClient(configuration, native);
  const sdk = make();
  const login = async (client: typeof sdk, slot: string) => {
    const step = await client.start(slot);
    if (step.kind !== "interaction-required")
      throw new Error("Expected interaction");
    return client.respond(slot, {
      flowId: step.flowId,
      stepId: step.step.id,
      response: {
        kind: "password",
        email: f.testUser.email,
        password: f.testUser.password,
      },
    });
  };
  return {
    ...f,
    storage,
    transport,
    forbidden,
    config,
    native,
    sdk,
    make,
    login,
  };
}

describe("composed Android native lifecycle", () => {
  it("logs in with its attested proof key, refreshes after restart, accesses resources, logs out and retires", async () => {
    const f = await composedFixture();
    expect(f.requests).toHaveLength(0);
    expect(f.native.integrity.createKey).not.toHaveBeenCalled();
    const slot = await f.sdk.accounts.create();
    expect(slot).toMatchObject({ status: "pending", hasSession: false });
    const signedIn = await f.login(f.sdk, slot.slotId);
    expect(signedIn).toMatchObject({ kind: "authenticated" });
    expect(await f.sdk.accounts.list()).toMatchObject([
      { status: "saved", hasSession: true },
    ]);
    const restarted = f.make();
    await expect(restarted.restore(slot.slotId)).resolves.toEqual(signedIn);
    const resource = await restarted.fetch(
      slot.slotId,
      `${f.config.issuer}/sdk-resource`,
    );
    expect(resource.status).toBe(200);
    const user = await f.ctx.adapter.findOne<{ id: string }>({
      model: "user",
      where: [{ field: "email", value: f.testUser.email }],
    });
    expect(JSON.parse(resource.body)).toEqual({ userId: user!.id });
    expect(f.native.integrity.createKey).toHaveBeenCalledOnce();
    const tokenRequests = f.requests.filter((value) =>
      value.path.endsWith("/oauth2/token"),
    );
    expect(tokenRequests.length).toBeGreaterThanOrEqual(2);
    expect(
      tokenRequests.every((value) => value.status === 200 && value.dpop),
    ).toBe(true);
    for (const { record } of f.storage.records.values()) {
      expect(record.identityJSON ?? "").not.toContain(f.testUser.password);
      expect(record.sessionJSON ?? "").not.toContain("access_token");
      expect(record.sessionJSON ?? "").not.toContain("accessToken");
    }
    await expect(restarted.logout(slot.slotId)).resolves.toMatchObject({
      remote: "confirmed",
      keys: "retained",
    });
    expect(await restarted.accounts.list()).toMatchObject([
      { status: "saved", hasSession: false },
    ]);
    await expect(restarted.restore(slot.slotId)).resolves.toMatchObject({
      kind: "signed-out",
    });
    await expect(f.login(restarted, slot.slotId)).resolves.toMatchObject({
      kind: "authenticated",
    });
    expect(f.native.integrity.createKey).toHaveBeenCalledOnce();
    await expect(restarted.retire(slot.slotId)).resolves.toMatchObject({
      remote: "confirmed",
      keys: "removed",
    });
    expect(f.native.integrity.removeKey).toHaveBeenCalledOnce();
    expect(await restarted.accounts.list()).toMatchObject([
      { status: "retired", keysRemoved: true },
    ]);
    await restarted.accounts.forget(slot.slotId);
    await expect(restarted.start(slot.slotId)).rejects.toMatchObject({
      code: "invalid_request",
    });
    expect(f.forbidden).not.toHaveBeenCalled();
    expect("importIOSKeys" in restarted.accounts).toBe(false);
    expect("resumeImport" in restarted.accounts).toBe(false);
  });

  it("recovers a lost enrollment response through the durable identity without generating or attesting another key", async () => {
    const f = await composedFixture();
    const slot = await f.sdk.accounts.create();
    f.loseRegistrationResponse();
    await expect(f.sdk.start(slot.slotId)).rejects.toMatchObject({
      code: "request_failed",
    });
    const restarted = f.make();
    await expect(f.login(restarted, slot.slotId)).resolves.toMatchObject({
      kind: "authenticated",
    });
    expect(f.native.integrity.createKey).toHaveBeenCalledOnce();
    expect(
      f.requests.filter((value) => value.path.endsWith("/android/register")),
    ).toHaveLength(1);
    expect(f.forbidden).not.toHaveBeenCalled();
  });

  it("requires a fresh login after an ambiguous refresh rather than reusing the consumed token", async () => {
    const f = await composedFixture();
    const slot = await f.sdk.accounts.create();
    await f.login(f.sdk, slot.slotId);
    f.loseTokenResponse();
    await expect(f.make().restore(slot.slotId)).rejects.toMatchObject({
      code: "request_failed",
    });
    const count = f.requests.length;
    await expect(f.make().restore(slot.slotId)).resolves.toMatchObject({
      kind: "signed-out",
    });
    expect(f.requests).toHaveLength(count);
    await expect(f.login(f.make(), slot.slotId)).resolves.toMatchObject({
      kind: "authenticated",
    });
    expect(f.native.integrity.createKey).toHaveBeenCalledOnce();
  });

  it("fences recovered slots and preserves their keys without transferring account authority", async () => {
    const f = await composedFixture();
    const slot = await f.sdk.accounts.create();
    await f.login(f.sdk, slot.slotId);
    const replacement = await f.sdk.accounts.recover(slot.slotId);
    expect(replacement).toMatchObject({ status: "pending", hasSession: false });
    expect(replacement.slotId).not.toBe(slot.slotId);
    expect(replacement.account).toBeUndefined();
    expect(f.native.integrity.removeKey).not.toHaveBeenCalled();
    expect(f.native.integrity.createKey).toHaveBeenCalledOnce();
    const count = f.requests.length;
    await expect(f.sdk.start(slot.slotId)).rejects.toMatchObject({
      code: "reauthentication_required",
    });
    await expect(
      f.sdk.fetch(slot.slotId, `${f.config.issuer}/sdk-resource`),
    ).rejects.toMatchObject({ code: "reauthentication_required" });
    expect(f.requests).toHaveLength(count);
    expect((await f.make().accounts.recover(slot.slotId)).slotId).toBe(
      replacement.slotId,
    );
  });

  it("isolates account catalogs and rejects unowned slots before touching native keys or the network", async () => {
    const f = await composedFixture();
    const slot = await f.sdk.accounts.create();
    const isolated = createAndroidFirstPartyClient(
      { ...f.config, storageNamespace: "another-installation" },
      f.native,
    );
    await expect(isolated.accounts.list()).resolves.toEqual([]);
    await expect(isolated.start(slot.slotId)).rejects.toMatchObject({
      code: "invalid_request",
    });
    await expect(
      f.sdk.start(randomBytes(32).toString("base64url")),
    ).rejects.toMatchObject({ code: "invalid_request" });
    expect(f.requests).toHaveLength(0);
    expect(f.native.integrity.createKey).not.toHaveBeenCalled();
  });

  it("surfaces inaccessible storage without resetting it or preparing replacement keys", async () => {
    const f = await composedFixture();
    const acquire = vi.fn(() =>
      Promise.reject(
        Object.assign(new Error("Unavailable"), { code: "vault_unavailable" }),
      ),
    );
    const sdk = createAndroidFirstPartyClient(f.config, {
      ...f.native,
      vault: { ...f.native.vault, acquire },
    });
    await expect(sdk.accounts.create()).rejects.toMatchObject({
      code: "vault_unavailable",
    });
    expect(f.requests).toHaveLength(0);
    expect(f.native.integrity.createKey).not.toHaveBeenCalled();
    expect(f.native.integrity.removeKey).not.toHaveBeenCalled();
  });

  it.each([false, true])(
    "completes browser MFA with the same Android DPoP key and rejects callback substitution (%s)",
    async (substitute) => {
      const f = await composedFixture();
      await f.ctx.adapter.update({
        model: "user",
        where: [{ field: "email", value: f.testUser.email }],
        update: { twoFactorEnabled: true },
      });
      const slot = await f.sdk.accounts.create();
      const step = await f.login(f.sdk, slot.slotId);
      expect(step).toMatchObject({
        kind: "browser-required",
        step: { kind: "browser-required" },
      });
      if (step.kind !== "browser-required")
        throw new Error("Expected browser MFA");
      const openBrowser = vi.fn(
        async (_id: string, url: string, redirectUri: string) => {
          expect(redirectUri).toBe(f.config.browser.redirectUri);
          expect(
            [...f.storage.records.values()].every(
              ({ record }) => record.lease === null,
            ),
          ).toBe(true);
          const callback = await f.completeBrowser(url);
          if (!substitute) return callback;
          const wrong = new URL(callback);
          wrong.searchParams.set("state", "substituted");
          return wrong.href;
        },
      );
      const sdk = createAndroidFirstPartyClient(f.config, {
        ...f.native,
        transport: { ...f.transport, openBrowser },
      });
      const result = sdk.openBrowser(slot.slotId, {
        flowId: step.flowId,
        stepId: step.step.id,
      });
      if (substitute) {
        await expect(result).rejects.toMatchObject({
          code: "invalid_response",
        });
        expect(
          f.requests.filter((value) => value.path.endsWith("/oauth2/token")),
        ).toHaveLength(0);
      } else {
        await expect(result).resolves.toMatchObject({ kind: "authenticated" });
        await expect(
          sdk.fetch(slot.slotId, `${f.config.issuer}/sdk-resource`),
        ).resolves.toMatchObject({ status: 200 });
      }
      expect(openBrowser).toHaveBeenCalledOnce();
      expect(f.native.integrity.createKey).toHaveBeenCalledOnce();
      expect(f.forbidden).not.toHaveBeenCalled();
    },
  );

  it("rejects unsupported Android policies before native side effects", async () => {
    const f = await composedFixture();
    for (const android of [
      { cloudProjectNumber: "123", securityLevel: "software" },
      { cloudProjectNumber: "9223372036854775808", securityLevel: "tee" },
      { cloudProjectNumber: 123, securityLevel: "tee" },
      undefined,
    ]) {
      expect(() =>
        createAndroidFirstPartyClient(
          { ...f.config, android } as never,
          f.native,
        ),
      ).toThrow(expect.objectContaining({ code: "invalid_configuration" }));
    }
    expect(() =>
      createAndroidFirstPartyClient(
        { ...f.config, environment: "development" } as never,
        f.native,
      ),
    ).toThrow(expect.objectContaining({ code: "invalid_configuration" }));
    expect(f.requests).toHaveLength(0);
    expect(f.native.integrity.createKey).not.toHaveBeenCalled();
  });
});
