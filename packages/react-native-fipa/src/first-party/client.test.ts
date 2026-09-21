import { developmentProvider } from "../../../better-auth-fipa/src/development.js";
import { androidIdentitySchema } from "./android-identity.ts";
import { iosIdentitySchema } from "./ios-identity.ts";
import { createMemorySessionVault as vault } from "../test-fixtures/session-vault.ts";
import {
  createHash,
  generateKeyPairSync,
  randomBytes,
  randomUUID,
  sign,
} from "node:crypto";
import { oauthProvider } from "@better-auth/oauth-provider";
import { getTestInstance } from "better-auth/test";
import {
  APIError,
  createAuthEndpoint,
  createAuthMiddleware,
} from "better-auth/api";
import { emailOTP, twoFactor } from "better-auth/plugins";
import type { BetterAuthPlugin } from "better-auth";
import { describe, expect, it, vi } from "vitest";
import { z } from "zod";
import { FirstPartyClientError } from "./errors.ts";
import { createIOSFirstPartyClient } from "./ios-client.ts";
import {
  createDeviceAttestation,
  type DeviceAttestationProvider,
} from "@eventyr-tech/better-auth-fipa";
import { createNativeFirstPartyPlugin } from "../../../better-auth-fipa/src/first-party/plugin.js";
import {
  createFirstPartyClientCore,
  type FirstPartyClientPorts,
  type ClientState,
} from "./client.ts";
import type { SessionVaultNative } from "./session-coordinator.ts";
import { createIOSKeyPorts } from "./ios-keys.ts";
import {
  requireNativeAccess,
  type NativeTokenOptions,
} from "../../../better-auth-fipa/src/first-party/token-lifecycle.js";

const random = () => randomBytes(32).toString("base64url");
const hash = (value: string | Uint8Array) =>
  createHash("sha256").update(value).digest();
async function fixture(
  options: { ios?: boolean; emailOTP?: boolean; development?: boolean } = {},
) {
  const deployment = {
    allowDevelopmentAuthentication: true,
    target: "local-e2e" as "local-e2e" | "production",
  };
  const app = "TEAM.sdk";
  const providerKey = randomBytes(32).toString("base64");
  const softwareKey = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const softwareEvidence = (keyId: string, data: string, operation: string) =>
    Buffer.from(
      JSON.stringify({
        version: 1,
        provider: "development",
        operation,
        jwk: softwareKey.publicKey.export({ format: "jwk" }),
        signature: sign(
          "sha256",
          Buffer.from(
            `fipa/development/v1\n${operation}\n${keyId}\n${hash(Buffer.from(data, "base64url")).toString("base64")}`,
          ),
          { key: softwareKey.privateKey, dsaEncoding: "ieee-p1363" },
        ).toString("base64url"),
      }),
    ).toString("base64");
  const provider: DeviceAttestationProvider = options.development
    ? developmentProvider({
        enabled: true,
        authorize: () =>
          deployment.allowDevelopmentAuthentication &&
          deployment.target === "local-e2e",
        environment: "development",
        applicationIds: [app],
      })
    : {
        id: options.ios ? "app-attest" : "sdk-test",
        maxEvidenceBytes: 1024,
        decodeKeyId: (value) => Buffer.from(value, "base64"),
        verifyRegistration: () =>
          Promise.resolve({
            applicationId: app,
            environment: "production",
            publicKey: "fixture",
            counter: 0,
            extensionsPresent: false,
          }),
        verifyAssertion: ({ credential, clientDataHash, evidence }) => {
          if (!Buffer.from(evidence).equals(Buffer.from(clientDataHash)))
            return Promise.reject(new Error("bad evidence"));
          return Promise.resolve({
            counter: credential.counter + 1,
            extensionsPresent: false,
          });
        },
      };
  const oauthOptions = {
    loginPage: "/login",
    consentPage: "/consent",
    disableJwtPlugin: true,
    scopes: ["offline_access"],
  };
  const low = createDeviceAttestation({
    providers: [provider],
    purposes: {
      credentialRegistration: {},
      oauthAuthorization: {
        requireDpopJkt: true,
        protectedClientIds: ["mobile"],
      },
    },
  });
  const oauth = oauthProvider(oauthOptions);
  let browserOTP = "";
  const sentOTP: { email: string; otp: string }[] = [];
  const nativeOptions: NativeTokenOptions = {
    ...(options.emailOTP
      ? {
          emailOTP: {
            recipient: {
              maxRequests: 2,
              windowSeconds: 3600,
              minimumIntervalSeconds: 60,
            },
            credential: {
              maxRequests: 3,
              windowSeconds: 3600,
              minimumIntervalSeconds: 10,
            },
          },
        }
      : {}),
    browser: { loginPage: "/login" },
    oauth: oauthOptions,
    applications: [
      {
        clientId: "mobile",
        provider,
        applicationId: app,
        environment: options.development ? "development" : "production",
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
  const resource = { calls: 0, effects: 0, forceBrowser: false };
  const { auth, testUser } = await getTestInstance(
    {
      plugins: [
        low.serverPlugin,
        ...(options.emailOTP
          ? [
              emailOTP({
                storeOTP: "hashed",
                disableSignUp: true,
                sendVerificationOTP: (value) => {
                  sentOTP.push(value);
                  return Promise.resolve();
                },
              }) as BetterAuthPlugin,
            ]
          : []),
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
          id: "sdk-resource-fixture",
          hooks: {
            before: [
              {
                matcher: (ctx) => ctx.path === "/sign-in/email",
                handler: createAuthMiddleware(() => {
                  if (resource.forceBrowser)
                    throw new APIError("FORBIDDEN", {
                      message: "Browser interaction required",
                    });
                  return Promise.resolve();
                }),
              },
            ],
          },
          endpoints: {
            sdkResource: createAuthEndpoint(
              "/sdk-resource",
              {
                method: ["GET", "POST"],
                disableBody: true,
                requireRequest: true,
              },
              async (ctx) => {
                resource.calls++;
                const result = await requireNativeAccess(ctx, nativeOptions, {
                  headers: ctx.request.headers,
                  method: ctx.request.method,
                  url: `${ctx.context.baseURL}/sdk-resource`,
                  scopes: ["offline_access"],
                });
                if (ctx.request.method === "POST") resource.effects++;
                return ctx.json({
                  userId: result.userId,
                  effects: resource.effects,
                });
              },
            ),
          },
        },
      ],
    },
    { testWith: "sqlite", transaction: true },
  );
  const context = await auth.$context;
  const cookies = new Map<string, string>();
  const browserRequest = async (path: string, body?: object) => {
    const response = await auth.handler(
      new Request(`${context.baseURL}${path}`, {
        method: body ? "POST" : "GET",
        headers: {
          "content-type": "application/json",
          origin: new URL(context.baseURL).origin,
          cookie: [...cookies]
            .map(([key, value]) => `${key}=${value}`)
            .join("; "),
        },
        ...(body ? { body: JSON.stringify(body) } : {}),
      }),
    );
    for (const header of response.headers.getSetCookie()) {
      const pair = header.split(";")[0]!;
      const equals = pair.indexOf("=");
      const name = pair.slice(0, equals),
        value = pair.slice(equals + 1);
      if (value) cookies.set(name, value);
      else cookies.delete(name);
    }
    return response;
  };
  if (!options.ios) {
    const registration = z.object({ challengeToken: z.string() }).parse(
      await auth.api.createDeviceAttestationChallenge!({
        body: {
          provider: provider.id,
          applicationId: app,
          keyId: providerKey,
          operation: "register",
          purpose: "credential-registration",
        },
      }),
    );
    await auth.api.verifyDeviceAttestation!({
      body: {
        challengeToken: registration.challengeToken,
        keyId: providerKey,
        evidence: Buffer.from("fixture").toString("base64"),
      },
    });
  }
  await context.adapter.create({
    model: "oauthClient",
    data: {
      clientId: "mobile",
      redirectUris: ["example:/callback"],
      tokenEndpointAuthMethod: "none",
      grantTypes: ["authorization_code", "refresh_token"],
      scopes: ["offline_access"],
      disabled: false,
    },
  });
  const key = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const jwk = key.publicKey.export({ format: "jwk" });
  const jkt = hash(
    JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }),
  ).toString("base64url");
  const storage = vault();
  const requests: Parameters<FirstPartyClientPorts["send"]>[0][] = [];
  const responses: Record<string, unknown>[] = [];
  const controls = {
    beforeSend: undefined as ((url: string) => void) | undefined,
    missingKey: false,
    loseTokenResponse: false,
    loseRegistrationResponse: false,
    failNativeAttestation: false,
    nativeRegistrations: 0,
    removed: 0,
    failRemoval: false,
  };
  const post = (path: string, body: unknown) =>
    auth.handler(
      new Request(`${context.baseURL}${path}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
      }),
    );
  const ports: FirstPartyClientPorts = {
    vault: storage.native,
    crypto: {
      transaction: () => {
        const verifier = random();
        return Promise.resolve({
          id: random(),
          verifier,
          challenge: hash(verifier).toString("base64url"),
        });
      },
    },
    keys: {
      identitySchema: z.union([iosIdentitySchema, androidIdentitySchema]),
      remove: vi.fn(() => {
        expect(JSON.parse(storage.record.identityJSON!)).toMatchObject({
          retired: true,
        });
        if (controls.failRemoval)
          return Promise.reject(new Error("locked key store"));
        controls.removed++;
        controls.missingKey = true;
        return Promise.resolve();
      }),
      prepare: vi.fn(() =>
        Promise.resolve({
          version: 1 as const,
          dpopAlias: "stable-slot-key",
          dpopJkt: jkt,
          providerKeyId: providerKey,
          providerScope: "stable-scope",
        }),
      ),
      assertAvailable: () =>
        controls.missingKey
          ? Promise.reject(new Error("key missing"))
          : Promise.resolve(),
      proof: (_identity, request) => {
        const encode = (value: unknown) =>
          Buffer.from(JSON.stringify(value)).toString("base64url");
        const bytes = `${encode({ typ: "dpop+jwt", alg: "ES256", jwk })}.${encode(
          {
            htm: request.method,
            htu: request.url.split(/[?#]/u)[0],
            iat: Math.floor(Date.now() / 1000),
            jti: randomUUID(),
            ...(request.nonce === undefined ? {} : { nonce: request.nonce }),
            ...(request.accessToken
              ? { ath: hash(request.accessToken).toString("base64url") }
              : {}),
          },
        )}`;
        return Promise.resolve(
          `${bytes}.${sign("sha256", Buffer.from(bytes), { key: key.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url")}`,
        );
      },
      admission: async (_identity, binding) => {
        const challenge = (await (
          await post("/first-party/attestation/challenge", {
            binding,
            keyId: providerKey,
          })
        ).json()) as { challengeToken: string; clientData: string };
        const verified = (await (
          await post("/first-party/attestation/verify", {
            clientId: "mobile",
            keyId: providerKey,
            challengeToken: challenge.challengeToken,
            evidence: hash(
              Buffer.from(challenge.clientData, "base64url"),
            ).toString("base64"),
          })
        ).json()) as { grantToken: string };
        return verified.grantToken;
      },
    },
    send: async (request) => {
      requests.push(request);
      controls.beforeSend?.(request.url);
      const response = await auth.handler(
        new Request(request.url, {
          method: request.method,
          headers: request.headers,
          body: request.body,
          signal: request.signal,
        }),
      );
      const body = await response.text();
      responses.push(JSON.parse(body) as Record<string, unknown>);
      if (controls.loseTokenResponse && request.url.endsWith("/oauth2/token"))
        throw new Error("ambiguous network failure");
      if (
        controls.loseRegistrationResponse &&
        request.url.endsWith("/device-attestation/verify")
      )
        throw new Error("lost registration response");
      return {
        url: request.url,
        status: response.status,
        body,
        headers: Object.fromEntries(response.headers.entries()),
      };
    },
  };
  const config = {
    browser: { redirectUri: "example:/callback" },
    issuer: context.baseURL,
    clientId: "mobile",
    applicationId: app,
    provider: provider.id,
    environment: options.development
      ? ("development" as const)
      : ("production" as const),
    storageNamespace: "test-sdk",
    scopes: ["offline_access"],
    resources: [],
    allowInsecureLoopback: true,
  };
  const completeBrowser = async (url: string) => {
    const authorization = new URL(url);
    expect(authorization.origin).toBe(new URL(context.baseURL).origin);
    expect(authorization.pathname).toBe(
      `${new URL(context.baseURL).pathname}/oauth2/authorize`,
    );
    expect([...authorization.searchParams.keys()]).toEqual([
      "client_id",
      "request_uri",
    ]);
    expect(storage.record.lease).toBeNull();
    expect(JSON.parse(storage.record.sessionJSON!)).toHaveProperty("browser");
    const opened = await browserRequest(
      `/oauth2/authorize${authorization.search}`,
    );
    expect(opened.status).toBe(302);
    const password = await browserRequest("/sign-in/email", {
      email: testUser.email,
      password: testUser.password,
    });
    expect(await password.json()).toMatchObject({ twoFactorRedirect: true });
    expect((await browserRequest("/two-factor/send-otp", {})).status).toBe(200);
    expect(
      (await browserRequest("/two-factor/verify-otp", { code: browserOTP }))
        .status,
    ).toBe(200);
    const completed = await browserRequest("/first-party/browser/complete");
    expect(completed.status).toBe(302);
    return completed.headers.get("location")!;
  };
  ports.browser = { open: ({ url }) => completeBrowser(url) };
  if (options.ios) {
    let keyExists = false;
    const original = ports.keys;
    ports.keys = createIOSKeyPorts(
      {
        ...config,
        provider: options.development ? "development" : "app-attest",
        keyIdStoragePrefix: "fixture.app-attest.",
        aliases: () =>
          Promise.resolve({
            dpopAlias: "stable-slot-key",
            providerScope: "stable-scope",
          }),
      },
      {
        send: ports.send,
        appAttest: {
          removeKey: () => {
            keyExists = false;
            return Promise.resolve();
          },
          getKey: () => Promise.resolve(keyExists ? providerKey : null),
          getOrCreateKey: () => {
            const created = !keyExists;
            keyExists = true;
            return Promise.resolve({ keyId: providerKey, created });
          },
          generateEvidence: (_key, data, operation) => {
            if (options.development)
              return Promise.resolve(softwareEvidence(_key, data, operation));
            if (operation === "register") {
              controls.nativeRegistrations++;
              // An irreversible Apple operation must have a durable journal first.
              expect(JSON.parse(storage.record.identityJSON!)).toMatchObject({
                providerRegistration: "attesting",
              });
              if (controls.failNativeAttestation)
                return Promise.reject(new Error("ambiguous Apple result"));
              return Promise.resolve(Buffer.from("fixture").toString("base64"));
            }
            return Promise.resolve(
              hash(Buffer.from(data, "base64url")).toString("base64"),
            );
          },
        },
        dpop: {
          removeDpop: () =>
            original.remove({
              version: 1,
              dpopAlias: "stable-slot-key",
              dpopJkt: jkt,
              providerKeyId: providerKey,
              providerScope: "stable-scope",
              retired: true,
            }),
          prepareDpop: () => Promise.resolve(jkt),
          inspectDpop: () =>
            controls.missingKey
              ? Promise.reject(new Error("missing"))
              : Promise.resolve(jkt),
          signDpop: async (_alias, _jkt, url, method, accessToken, nonce) =>
            original.proof(await original.prepare("slot"), {
              url,
              method,
              ...(accessToken ? { accessToken } : {}),
              ...(nonce === null ? {} : { nonce }),
            }),
        },
      },
    );
  }
  const client = createFirstPartyClientCore(config, ports);
  const respond = (step: ClientState, password = testUser.password) => {
    if (step.kind !== "interaction-required")
      throw new Error("expected interaction");
    return client.respond("slot", {
      flowId: step.flowId,
      stepId: step.step.id,
      response: { kind: "password", email: testUser.email, password },
    });
  };
  return {
    client,
    ports,
    config,
    storage,
    requests,
    responses,
    controls,
    context,
    auth,
    respond,
    resource,
    testUser,
    completeBrowser,
    sentOTP,
    nativeOptions,
    softwareEvidence,
    deployment,
  };
}

describe("FiPA client against real Better Auth endpoints", () => {
  it.each(["authorization", "refresh"] as const)(
    "revokes only the issued family after failed %s storage",
    async (grant) => {
      const f = await fixture();
      const step = await f.client.start("slot");
      if (grant === "refresh") await f.respond(step);
      f.storage.faults.rejectTokenCommit = true;
      await expect(
        grant === "refresh" ? f.client.restore("slot") : f.respond(step),
      ).rejects.toMatchObject({
        code: "vault_storage_failed",
        cleanup: "complete",
        remoteCleanup: "confirmed",
      });
      const cleanup = f.requests.filter((request) =>
        request.url.endsWith("/first-party/logout"),
      );
      expect(cleanup).toHaveLength(1);
      expect(JSON.parse(cleanup[0]!.body!)).toEqual({ scope: "family" });
      expect(
        await f.context.adapter.count({
          model: "firstPartyTokenFamily",
          where: [{ field: "status", value: "active" }],
        }),
      ).toBe(0);
      expect(
        await f.context.adapter.count({ model: "oauthRefreshToken" }),
      ).toBe(0);
      expect(f.storage.record.sessionJSON).toBeNull();
    },
  );

  it.each(["rejection", "lost-response", "local-uncertain"] as const)(
    "reports unconfirmed failed-commit revocation after %s",
    async (failure) => {
      const f = await fixture();
      const step = await f.client.start("slot");
      f.storage.faults.rejectTokenCommit = true;
      const send = f.ports.send;
      let cleanupCalls = 0;
      f.ports.send = async (request) => {
        if (!request.url.endsWith("/first-party/logout")) return send(request);
        cleanupCalls++;
        if (failure === "lost-response") {
          await send(request);
          throw new Error("lost revocation response");
        }
        return { url: request.url, status: 503, body: "{}", headers: {} };
      };
      if (failure === "local-uncertain")
        f.storage.native.abandon = () =>
          Promise.reject(new FirstPartyClientError("vault_unavailable"));
      await expect(f.respond(step)).rejects.toMatchObject({
        code: "vault_storage_failed",
        remoteCleanup: "unconfirmed",
        cleanup: failure === "local-uncertain" ? "uncertain" : "complete",
      });
      expect(cleanupCalls).toBe(failure === "local-uncertain" ? 0 : 1);
      expect(
        await f.context.adapter.count({
          model: "firstPartyTokenFamily",
          where: [{ field: "status", value: "active" }],
        }),
      ).toBe(failure === "lost-response" ? 0 : 1);
    },
  );

  it("preserves a replacement runtime's committed rotation after an ambiguous earlier commit", async () => {
    const f = await fixture();
    const step = await f.client.start("slot");
    const replacement = createFirstPartyClientCore(f.config, f.ports);
    const commit = f.storage.native.commit;
    f.storage.native.commit = async (...args) => {
      const generation = await commit(...args);
      if (args[5]?.includes('"phase":"active"')) {
        f.storage.native.commit = commit;
        await replacement.restore("slot");
        throw new FirstPartyClientError("vault_storage_failed");
      }
      return generation;
    };
    await expect(f.respond(step)).rejects.toMatchObject({
      code: "vault_storage_failed",
      cleanup: "not-owned",
      remoteCleanup: "unconfirmed",
    });
    expect(
      f.requests.filter((request) =>
        request.url.endsWith("/first-party/logout"),
      ),
    ).toHaveLength(0);
    await expect(
      replacement.fetch("slot", `${f.config.issuer}/sdk-resource`),
    ).resolves.toMatchObject({ status: 200 });
    expect(
      await f.context.adapter.count({
        model: "firstPartyTokenFamily",
        where: [{ field: "status", value: "active" }],
      }),
    ).toBe(1);
  });

  it("bounds failed-commit revocation even when transport never settles", async () => {
    const f = await fixture();
    const step = await f.client.start("slot");
    f.storage.faults.rejectTokenCommit = true;
    const send = f.ports.send;
    let entered!: () => void;
    const started = new Promise<void>((resolve) => {
      entered = resolve;
    });
    let cleanupSignal: AbortSignal | undefined;
    f.ports.send = (request) => {
      if (!request.url.endsWith("/first-party/logout")) return send(request);
      cleanupSignal = request.signal;
      entered();
      return new Promise(() => {});
    };
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    try {
      const failed = expect(f.respond(step)).rejects.toMatchObject({
        remoteCleanup: "unconfirmed",
      });
      await started;
      await vi.advanceTimersByTimeAsync(10_001);
      await failed;
      expect(cleanupSignal?.aborted).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });

  const nonceStages = [
    "initial",
    "continuation",
    "code",
    "refresh",
    "resource",
  ] as const;
  type NonceStage = (typeof nonceStages)[number];
  const isNonceStage = (
    request: Parameters<FirstPartyClientPorts["send"]>[0],
    stage: NonceStage,
  ) => {
    const form = new URLSearchParams(request.body ?? "");
    if (stage === "resource") return request.url.endsWith("/sdk-resource");
    if (stage === "code" || stage === "refresh")
      return (
        request.url.endsWith("/oauth2/token") &&
        form.get("grant_type") ===
          (stage === "code" ? "authorization_code" : "refresh_token")
      );
    return (
      request.url.endsWith("/first-party/authorization-challenge") &&
      form.has("auth_session") === (stage === "continuation")
    );
  };
  const runNonceStage = async (
    f: Awaited<ReturnType<typeof fixture>>,
    stage: NonceStage,
  ) => {
    const step = await f.client.start("slot");
    if (stage === "initial") return step;
    const loggedIn = await f.respond(step);
    if (stage === "refresh") return f.client.restore("slot");
    if (stage === "resource")
      return f.client.fetch("slot", `${f.config.issuer}/sdk-resource`, {
        method: "POST",
        body: "one-effect",
      });
    return loggedIn;
  };
  const proofBody = (proof: string) =>
    JSON.parse(
      Buffer.from(proof.split(".")[1]!, "base64url").toString(),
    ) as Record<string, unknown>;
  const nonceResponse = (url: string, resource: boolean) => ({
    url,
    status: resource ? 401 : 400,
    headers: {
      "DPoP-Nonce": "server-nonce",
      ...(resource
        ? { "WWW-Authenticate": 'DPoP realm="api", error="use_dpop_nonce"' }
        : {}),
    },
    body: JSON.stringify({ error: "use_dpop_nonce" }),
  });

  it.each(nonceStages)(
    "retries one explicit DPoP nonce rejection at %s with a fresh bound proof",
    async (stage) => {
      const f = await fixture();
      const send = f.ports.send;
      const attempts: Parameters<FirstPartyClientPorts["send"]>[0][] = [];
      f.ports.send = async (request) => {
        if (!isNonceStage(request, stage)) return send(request);
        attempts.push(request);
        if (attempts.length === 1)
          return nonceResponse(request.url, stage === "resource");
        expect(proofBody(request.headers.DPoP!).nonce).toBe("server-nonce");
        return send(request);
      };
      const result = await runNonceStage(f, stage);
      if (stage === "resource") {
        expect(result).toMatchObject({ status: 200 });
        expect(f.resource.effects).toBe(1);
      } else {
        expect(result).toMatchObject({
          kind: stage === "initial" ? "interaction-required" : "authenticated",
        });
      }
      expect(attempts).toHaveLength(2);
      expect(proofBody(attempts[0]!.headers.DPoP!).nonce).toBeUndefined();
      const first = proofBody(attempts[0]!.headers.DPoP!);
      const second = proofBody(attempts[1]!.headers.DPoP!);
      expect(second.jti).not.toBe(first.jti);
      expect(second.htm).toBe(first.htm);
      expect(second.htu).toBe(first.htu);
      expect(second.ath).toBe(first.ath);
      expect(attempts[1]!.body).toBe(attempts[0]!.body);
      expect(
        f.requests.filter((request) => isNonceStage(request, stage)),
      ).toHaveLength(1);
    },
  );

  it.each(nonceStages)(
    "stops after a repeated DPoP nonce rejection at %s",
    async (stage) => {
      const f = await fixture();
      const send = f.ports.send;
      let attempts = 0;
      f.ports.send = (request) => {
        if (!isNonceStage(request, stage)) return send(request);
        attempts++;
        return Promise.resolve(
          nonceResponse(request.url, stage === "resource"),
        );
      };
      await expect(runNonceStage(f, stage)).rejects.toMatchObject({
        code: "request_failed",
      });
      expect(attempts).toBe(2);
    },
  );

  it.each([
    "missing",
    "malformed",
    "redirect",
    "timeout",
    "lost-response",
  ] as const)(
    "does not replay a code exchange after a %s nonce/transport failure",
    async (failure) => {
      const f = await fixture();
      const send = f.ports.send;
      let attempts = 0;
      f.ports.send = async (request) => {
        if (!isNonceStage(request, "code")) return send(request);
        attempts++;
        if (failure === "lost-response") {
          await send(request);
          throw new Error("lost response");
        }
        if (failure === "timeout") throw new Error("timeout");
        const response = nonceResponse(request.url, false);
        if (failure === "missing") return { ...response, headers: {} };
        if (failure === "malformed")
          return { ...response, headers: { "dpop-nonce": "bad nonce" } };
        return { ...response, url: "https://another.example/token" };
      };
      await expect(runNonceStage(f, "code")).rejects.toBeDefined();
      expect(attempts).toBe(1);
    },
  );

  it("does not carry a nonce to a different resource server", async () => {
    const f = await fixture();
    await f.respond(await f.client.start("slot"));
    const client = createFirstPartyClientCore(
      {
        ...f.config,
        resources: ["https://one.example", "https://two.example"],
      },
      f.ports,
    );
    const send = f.ports.send;
    const proofs: { url: string; nonce: unknown }[] = [];
    f.ports.send = (request) => {
      if (
        !request.url.startsWith("https://one.example") &&
        !request.url.startsWith("https://two.example")
      )
        return send(request);
      const nonce = proofBody(request.headers.DPoP!).nonce;
      proofs.push({ url: request.url, nonce });
      return Promise.resolve(
        request.url.startsWith("https://one.example") && nonce === undefined
          ? nonceResponse(request.url, true)
          : { url: request.url, status: 200, headers: {}, body: "ok" },
      );
    };
    await client.fetch("slot", "https://one.example/me");
    await client.fetch("slot", "https://two.example/me");
    expect(proofs).toEqual([
      { url: "https://one.example/me", nonce: undefined },
      { url: "https://one.example/me", nonce: "server-nonce" },
      { url: "https://two.example/me", nonce: undefined },
    ]);
  });

  it("persists enrollment metadata under the slot lease and forbids changing it during admission", async () => {
    const f = await fixture();
    const prepare = f.ports.keys.prepare;
    const pending = {
      keyChallengeToken: random(),
      attestationChallenge: random(),
      issuedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 120000).toISOString(),
    };
    f.ports.keys.prepare = vi.fn<FirstPartyClientPorts["keys"]["prepare"]>(
      async (slot, context) => {
        expect(context?.signal).toBeInstanceOf(AbortSignal);
        expect(context?.signal.aborted).toBe(false);
        return {
          ...(await prepare(slot)),
          providerRegistration: "generated",
          androidEnrollment: pending,
        };
      },
    );
    const admission = f.ports.keys.admission;
    f.ports.keys.admission = async (identity, binding, context) => {
      expect(JSON.parse(f.storage.record.identityJSON!)).toMatchObject({
        androidEnrollment: pending,
      });
      await expect(
        context.saveIdentity({
          ...identity,
          androidEnrollment: { ...pending, keyChallengeToken: random() },
        }),
      ).rejects.toMatchObject({ code: "invalid_state" });
      await context.saveIdentity({
        ...identity,
        providerRegistration: "attesting",
      });
      const grant = await admission(identity, binding, context);
      await context.saveIdentity({
        ...identity,
        providerRegistration: "registered",
      });
      return grant;
    };
    const start = await f.client.start("slot");
    expect(JSON.parse(f.storage.record.identityJSON!)).toMatchObject({
      androidEnrollment: pending,
      providerRegistration: "registered",
    });
    expect(
      await createFirstPartyClientCore(f.config, f.ports).restore("slot"),
    ).toEqual(start);
    expect(f.ports.keys.prepare).toHaveBeenCalledOnce();
  });
  it.each([false, true])(
    "runs the native OTP lifecycle without persisting submitted email or OTP and restores its typed continuation (development: %s)",
    async (development) => {
      const f = await fixture({ emailOTP: true, ios: true, development });
      const start = await f.client.start("slot");
      if (start.kind !== "interaction-required")
        throw new Error("expected method selection");
      expect(start.step).toMatchObject({
        kind: "authentication",
        methods: ["password", "email-otp"],
      });
      const sent = await f.client.respond("slot", {
        flowId: start.flowId,
        stepId: start.step.id,
        response: { kind: "email-otp-request", email: f.testUser.email },
      });
      if (sent.kind !== "interaction-required")
        throw new Error("expected OTP step");
      expect(sent.step.kind).toBe("email-otp");
      expect(f.sentOTP).toHaveLength(1);
      expect(f.storage.record.sessionJSON).not.toContain(f.testUser.email);
      const restarted = createFirstPartyClientCore(f.config, f.ports);
      expect(await restarted.restore("slot")).toEqual(sent);
      const wrong = await restarted.respond("slot", {
        flowId: sent.flowId,
        stepId: sent.step.id,
        response: { kind: "email-otp", otp: "invalid-code" },
      });
      if (wrong.kind !== "interaction-required")
        throw new Error("expected retry step");
      expect(wrong.failure).toBe("invalid_credentials");
      expect(f.storage.record.sessionJSON).not.toContain("invalid-code");
      const result = await restarted.respond("slot", {
        flowId: wrong.flowId,
        stepId: wrong.step.id,
        response: { kind: "email-otp", otp: f.sentOTP[0]!.otp },
      });
      expect(result.kind).toBe("authenticated");
      const stored = JSON.parse(f.storage.record.sessionJSON!) as Record<
        string,
        unknown
      >;
      expect(stored).not.toHaveProperty("otp");
      expect(stored).not.toHaveProperty("email");
      expect(
        await restarted.fetch("slot", `${f.config.issuer}/sdk-resource`),
      ).toMatchObject({ status: 200 });
      expect(
        await createFirstPartyClientCore(f.config, f.ports).restore("slot"),
      ).toMatchObject({ kind: "authenticated" });
      expect(await restarted.logout("slot")).toMatchObject({
        remote: "confirmed",
        keys: "retained",
      });
    },
  );

  it("persists resend guidance and rejects responses not offered by the current step before HTTP", async () => {
    const f = await fixture({ emailOTP: true });
    const initial = await f.client.start("slot");
    if (initial.kind !== "interaction-required")
      throw new Error("expected selection");
    const requests = f.requests.length;
    await expect(
      f.client.respond("slot", {
        flowId: initial.flowId,
        stepId: initial.step.id,
        response: { kind: "email-otp", otp: "123456" },
      }),
    ).rejects.toMatchObject({ code: "invalid_state" });
    expect(f.requests).toHaveLength(requests);
    const sent = await f.client.respond("slot", {
      flowId: initial.flowId,
      stepId: initial.step.id,
      response: { kind: "email-otp-request", email: f.testUser.email },
    });
    if (sent.kind !== "interaction-required") throw new Error("expected OTP");
    const limited = await f.client.respond("slot", {
      flowId: sent.flowId,
      stepId: sent.step.id,
      response: { kind: "email-otp-resend" },
    });
    if (limited.kind !== "interaction-required")
      throw new Error("expected rate-limited OTP");
    expect(limited.failure).toBe("temporarily_unavailable");
    expect(limited.retryAt).toBeGreaterThan(Date.now());
    expect(limited.step.id).not.toBe(sent.step.id);
    expect(f.sentOTP).toHaveLength(1);
    expect(
      await createFirstPartyClientCore(f.config, f.ports).restore("slot"),
    ).toEqual(limited);
    const done = await f.client.respond("slot", {
      flowId: limited.flowId,
      stepId: limited.step.id,
      response: { kind: "email-otp", otp: f.sentOTP[0]!.otp },
    });
    expect(done.kind).toBe("authenticated");
    expect(done).not.toHaveProperty("retryAt");
  });

  it("fences a damaged slot for explicit recovery without deleting or replacing its keys", async () => {
    const f = await fixture({ ios: true });
    await f.respond(await f.client.start("slot"));
    const identity = JSON.parse(f.storage.record.identityJSON!) as object;
    f.controls.missingKey = true;
    await f.client.beginRecovery("slot");
    expect(JSON.parse(f.storage.record.identityJSON!)).toEqual({
      ...identity,
      superseded: true,
    });
    expect(f.storage.record.sessionJSON).toBeNull();
    expect(f.controls.removed).toBe(0);
    await expect(f.client.inspect("slot")).resolves.toMatchObject({
      status: "recovery-required",
      hasSession: false,
    });
    await expect(f.client.start("slot")).rejects.toMatchObject({
      code: "reauthentication_required",
    });
    await expect(f.client.restore("slot")).rejects.toMatchObject({
      code: "reauthentication_required",
    });
    await expect(f.client.beginRecovery("slot")).resolves.toBeUndefined();
    expect(f.controls.nativeRegistrations).toBe(1);
  });

  it("preserves ambiguous App Attest registration history when abandoning a prepared slot", async () => {
    const f = await fixture({ ios: true });
    f.controls.failNativeAttestation = true;
    await expect(f.client.start("slot")).rejects.toBeDefined();
    expect(JSON.parse(f.storage.record.identityJSON!)).toHaveProperty(
      "providerRegistration",
      "attesting",
    );
    await f.client.beginRecovery("slot");
    expect(JSON.parse(f.storage.record.identityJSON!)).toMatchObject({
      providerRegistration: "attesting",
      superseded: true,
    });
    expect(f.controls.nativeRegistrations).toBe(1);
    expect(f.controls.removed).toBe(0);
  });

  it("prevents a late resource response from reviving a slot superseded for recovery", async () => {
    const f = await fixture();
    await f.respond(await f.client.start("slot"));
    let started!: () => void;
    const waiting = new Promise<void>((resolve) => {
      started = resolve;
    });
    let complete!: (
      value: Awaited<ReturnType<FirstPartyClientPorts["send"]>>,
    ) => void;
    f.ports.send = () => {
      started();
      return new Promise((resolve) => {
        complete = resolve;
      });
    };
    const request = f.client
      .fetch("slot", `${f.config.issuer}/sdk-resource`)
      .catch((error: unknown) => error);
    await waiting;
    await f.client.beginRecovery("slot");
    await expect(request).resolves.toMatchObject({ code: "cancelled" });
    complete({
      url: `${f.config.issuer}/sdk-resource`,
      status: 200,
      body: "{}",
    });
    expect(f.storage.record.sessionJSON).toBeNull();
    await expect(f.client.inspect("slot")).resolves.toMatchObject({
      status: "recovery-required",
    });
  });

  it.each([
    [false, false, false],
    [true, false, false],
    [true, true, false],
    [true, true, true],
  ])(
    "composes the iOS SDK (retained keys: %s, interrupted import: %s, recover import: %s)",
    async (imported, interrupted, recoverImport) => {
      const f = await fixture({ ios: true });
      const nativeConfig = { ...f.config, provider: "hardware" as const };
      const indexStorage = vault();
      const identity = await f.ports.keys.prepare("slot");
      const reference = {
        keyIdStoragePrefix: "EventyrAppAttestKeyId.v2.",
        credentialScope: "retained-scope",
        dpopAlias: "io.eventyr.mobile.dpop.user.v2.retained-scope",
      };
      if (imported) {
        const registration = z.object({ challengeToken: z.string() }).parse(
          await f.auth.api.createDeviceAttestationChallenge!({
            body: {
              provider: "app-attest",
              applicationId: f.config.applicationId,
              keyId: identity.providerKeyId,
              operation: "register",
              purpose: "credential-registration",
            },
          }),
        );
        await f.auth.api.verifyDeviceAttestation!({
          body: {
            challengeToken: registration.challengeToken,
            keyId: identity.providerKeyId,
            evidence: Buffer.from("fixture").toString("base64"),
          },
        });
        const owner = await f.context.adapter.findOne<{ id: string }>({
          model: "user",
          where: [{ field: "email", value: f.testUser.email }],
        });
        await f.context.adapter.updateMany({
          model: "deviceAttestationCredential",
          where: [],
          update: {
            userId: owner!.id,
            bindingVersion: 1,
            boundAt: new Date(),
            unboundExpiresAt: null,
          },
        });
      }

      const nativeVault = new Proxy(f.storage.native, {
        get(_target, name: keyof SessionVaultNative) {
          return (...args: unknown[]) => {
            const source = String(args[0]).includes(
              "device-attestation-catalog/v1",
            )
              ? indexStorage.native
              : f.storage.native;
            return Reflect.apply(source[name], source, args) as unknown;
          };
        },
      });
      let exists = true;
      const prepareDpop = vi.fn(() => Promise.resolve(identity.dpopJkt));
      const getOrCreateKey = vi.fn(() =>
        Promise.resolve({ keyId: identity.providerKeyId, created: true }),
      );
      const native: Parameters<typeof createIOSFirstPartyClient>[1] = {
        vault: nativeVault,
        appAttest: {
          getKey: () => Promise.resolve(exists ? identity.providerKeyId : null),
          getOrCreateKey,
          generateEvidence: (_key, data, operation) =>
            Promise.resolve(
              operation === "register"
                ? Buffer.from("fixture").toString("base64")
                : hash(Buffer.from(data, "base64url")).toString("base64"),
            ),
          resetKey: () => Promise.reject(new Error("must not reset")),
          removeKey: () => {
            exists = false;
            return Promise.resolve();
          },
        },
        transport: {
          randomToken: () => Promise.resolve(random()),
          transaction: () => f.ports.crypto.transaction(),
          prepareDpop,
          inspectDpop: () => Promise.resolve(identity.dpopJkt),
          removeDpop: vi.fn(() => Promise.resolve()),
          signDpop: (alias, expected, url, method, accessToken) => {
            if (imported) expect(alias).toBe(reference.dpopAlias);
            else
              expect(alias).toMatch(
                /^fipa\.v1\.[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43}$/,
              );
            expect(expected).toBe(identity.dpopJkt);
            return f.ports.keys.proof(identity, {
              url,
              method,
              ...(accessToken ? { accessToken } : {}),
            });
          },
          send: async (
            _id,
            url,
            method,
            headersJSON,
            body,
            maximumResponseBytes,
          ) => {
            const response = await f.ports.send({
              url,
              method: method as "POST",
              headers: JSON.parse(headersJSON) as Record<string, string>,
              body,
              maximumResponseBytes,
              signal: new AbortController().signal,
            });
            return {
              url: response.url,
              status: response.status,
              body: response.body,
              headersJSON: JSON.stringify(response.headers ?? {}),
            };
          },
          cancel: () => Promise.resolve(),
          openBrowser: (_id, url) => f.completeBrowser(url),
          cancelBrowser: () => Promise.resolve(),
        },
      };
      const compose = () => createIOSFirstPartyClient(nativeConfig, native);
      const sdk = compose();
      let account: Awaited<ReturnType<typeof sdk.accounts.create>>;
      if (interrupted) {
        const commit = f.storage.native.commit;
        f.storage.native.commit = () => {
          f.storage.native.commit = commit;
          return Promise.reject(
            new FirstPartyClientError("vault_storage_failed"),
          );
        };
        await expect(
          sdk.accounts.importIOSKeys(reference),
        ).rejects.toMatchObject({ code: "vault_storage_failed" });
        const [reserved] = await sdk.accounts.list();
        expect(reserved?.status).toBe("import-required");
        if (recoverImport) {
          const replacement = await sdk.accounts.recover(reserved!.slotId);
          expect(replacement.slotId).not.toBe(reserved!.slotId);
          expect(replacement.hasSession).toBe(false);
          await expect(sdk.start(reserved!.slotId)).rejects.toMatchObject({
            code: "reauthentication_required",
          });
          expect(prepareDpop).not.toHaveBeenCalled();
          expect(getOrCreateKey).not.toHaveBeenCalled();
          expect(f.storage.record.identityJSON).toBeNull();
          return;
        }
        account = await sdk.accounts.resumeImport();
        expect(account.slotId).toBe(reserved!.slotId);
      } else
        account = imported
          ? await sdk.accounts.importIOSKeys(reference)
          : await sdk.accounts.create();
      if (imported) {
        await expect(sdk.restore(account.slotId)).resolves.toEqual({
          kind: "signed-out",
          slotId: account.slotId,
        });
        expect(f.requests).toHaveLength(0);
        expect(JSON.parse(f.storage.record.identityJSON!)).toMatchObject({
          providerStoragePrefix: reference.keyIdStoragePrefix,
          providerScope: reference.credentialScope,
          dpopAlias: reference.dpopAlias,
          providerRegistration: "unknown",
        });
      }
      if (imported)
        expect(await sdk.accounts.importIOSKeys(reference)).toEqual(account);
      else expect(await sdk.accounts.create()).toEqual(account);
      const step = await sdk.start(account.slotId);
      if (step.kind !== "interaction-required")
        throw new Error("expected password");
      const signedIn = await sdk.respond(account.slotId, {
        flowId: step.flowId,
        stepId: step.step.id,
        response: {
          kind: "password",
          email: f.testUser.email,
          password: f.testUser.password,
        },
      });
      expect(signedIn.kind).toBe("authenticated");
      const restarted = compose();
      await expect(restarted.restore(account.slotId)).resolves.toEqual(
        signedIn,
      );
      await expect(
        restarted.fetch(account.slotId, `${f.config.issuer}/sdk-resource`),
      ).resolves.toMatchObject({ status: 200 });
      expect(await restarted.accounts.list()).toMatchObject([
        { status: "saved", hasSession: true },
      ]);
      expect(prepareDpop).toHaveBeenCalledTimes(imported ? 0 : 1);
      expect(getOrCreateKey).toHaveBeenCalledTimes(imported ? 0 : 1);
      await expect(restarted.retire(account.slotId)).resolves.toMatchObject({
        remote: "confirmed",
        keys: "removed",
      });
      expect(await restarted.accounts.list()).toMatchObject([
        { status: "retired", keysRemoved: true },
      ]);
      await restarted.accounts.forget(account.slotId);
      expect(await restarted.accounts.list()).toEqual([]);
      await expect(restarted.start(account.slotId)).rejects.toMatchObject({
        code: "invalid_request",
      });
      expect(prepareDpop).toHaveBeenCalledTimes(imported ? 0 : 1);
    },
  );

  it("persists only the server-confirmed subject and retains its binding after logout", async () => {
    const f = await fixture();
    await expect(f.client.inspect("slot")).resolves.toMatchObject({
      status: "pending",
      hasSession: false,
    });
    expect(f.ports.keys.prepare).not.toHaveBeenCalled();
    const result = await f.respond(await f.client.start("slot"));
    if (result.kind !== "authenticated")
      throw new Error("expected authenticated");
    const user = await f.context.adapter.findOne<{ id: string }>({
      model: "user",
      where: [{ field: "email", value: f.testUser.email }],
    });
    const credential = await f.context.adapter.findOne<{
      id: string;
      userId: string;
    }>({ model: "firstPartyCredential", where: [] });
    expect(result.account).toEqual({
      subject: user!.id,
      credentialId: credential!.id,
    });
    expect(credential!.userId).toBe(user!.id);
    await expect(f.client.inspect("slot")).resolves.toMatchObject({
      status: "saved",
      account: result.account,
      hasSession: true,
    });
    await f.client.logout("slot");
    await expect(f.client.inspect("slot")).resolves.toMatchObject({
      status: "saved",
      account: result.account,
      hasSession: false,
    });
    expect(f.storage.record.identityJSON).not.toContain(f.testUser.email);
  });

  it.each(["sub", "credential_id"] as const)(
    "rejects a refresh that substitutes the confirmed %s",
    async (field) => {
      const f = await fixture();
      const result = await f.respond(await f.client.start("slot"));
      const identity = f.storage.record.identityJSON;
      const send = f.ports.send;
      f.ports.send = async (request) => {
        const response = await send(request);
        if (!request.url.endsWith("/oauth2/token")) return response;
        const body = JSON.parse(response.body) as {
          first_party_account: Record<string, string>;
        };
        body.first_party_account[field] = "substituted-account";
        return { ...response, body: JSON.stringify(body) };
      };
      await expect(f.client.restore("slot")).rejects.toMatchObject({
        code: "invalid_response",
      });
      expect(f.storage.record.sessionJSON).toBeNull();
      expect(f.storage.record.identityJSON).toBe(identity);
      if (result.kind !== "authenticated")
        throw new Error("expected authenticated");
      await expect(f.client.inspect("slot")).resolves.toMatchObject({
        status: "saved",
        account: result.account,
        hasSession: false,
      });
    },
  );

  it("does not persist a confirmed subject when the issuance commit fails", async () => {
    const f = await fixture();
    const step = await f.client.start("slot");
    f.storage.faults.rejectTokenCommit = true;
    await expect(f.respond(step)).rejects.toMatchObject({
      code: "vault_storage_failed",
    });
    expect(JSON.parse(f.storage.record.identityJSON!)).not.toHaveProperty(
      "account",
    );
  });

  it("cancels a new login without losing prior access and reconciles the server handle", async () => {
    const f = await fixture();
    await f.respond(await f.client.start("slot"));
    const active = JSON.parse(f.storage.record.sessionJSON!) as {
      refreshToken: string;
      authSession: string;
    };
    const step = await f.client.start("slot");
    expect(step).toMatchObject({
      kind: "interaction-required",
      hasSession: true,
    });
    expect(JSON.parse(f.storage.record.sessionJSON!)).toHaveProperty(
      "sharesSession",
      true,
    );
    await expect(f.client.cancel("slot")).resolves.toMatchObject({
      kind: "authenticated",
    });
    expect(JSON.parse(f.storage.record.sessionJSON!)).toMatchObject({
      phase: "active",
      refreshToken: active.refreshToken,
    });
    expect(JSON.parse(f.storage.record.sessionJSON!)).not.toHaveProperty(
      "detachedInteraction",
    );
    await expect(
      f.client.fetch("slot", `${f.config.issuer}/sdk-resource`),
    ).resolves.toMatchObject({ status: 200 });
    await expect(f.client.start("slot")).resolves.toMatchObject({
      kind: "interaction-required",
      hasSession: true,
    });
    expect(JSON.parse(f.storage.record.sessionJSON!)).toHaveProperty(
      "sharesSession",
      true,
    );
  });

  it("keeps prior access after offline cancellation and starts an independent next interaction", async () => {
    const f = await fixture();
    await f.respond(await f.client.start("slot"));
    await f.client.start("slot");
    const send = f.ports.send;
    f.ports.send = () => Promise.reject(new Error("offline"));
    await expect(f.client.cancel("slot")).resolves.toMatchObject({
      kind: "authenticated",
    });
    expect(JSON.parse(f.storage.record.sessionJSON!)).toHaveProperty(
      "detachedInteraction",
      true,
    );
    f.ports.send = send;
    await expect(
      f.client.fetch("slot", `${f.config.issuer}/sdk-resource`),
    ).resolves.toMatchObject({ status: 200 });
    const count = f.requests.length;
    await f.client.start("slot");
    const challenge = f.requests
      .slice(count)
      .find((request) =>
        request.url.endsWith("/first-party/authorization-challenge"),
      );
    expect(new URLSearchParams(challenge!.body ?? "").has("auth_session")).toBe(
      false,
    );
    expect(JSON.parse(f.storage.record.sessionJSON!)).not.toHaveProperty(
      "sharesSession",
    );
  });

  it("uses and refreshes prior access while a pending login remains resumable", async () => {
    const f = await fixture();
    await f.respond(await f.client.start("slot"));
    const step = await f.client.start("slot");
    // A new runtime has no access cache and must rotate the old family first.
    const restarted = createFirstPartyClientCore(f.config, f.ports);
    await expect(
      restarted.fetch("slot", `${f.config.issuer}/sdk-resource`),
    ).resolves.toMatchObject({ status: 200 });
    expect(JSON.parse(f.storage.record.sessionJSON!)).toMatchObject({
      phase: "interaction",
      sharesSession: true,
    });
    await expect(f.respond(step)).resolves.toMatchObject({
      kind: "authenticated",
    });
  });

  it("treats cancellation without a pending login as a session-preserving no-op", async () => {
    const f = await fixture();
    await f.respond(await f.client.start("slot"));
    const active = JSON.parse(f.storage.record.sessionJSON!) as object;
    const count = f.requests.length;
    await expect(f.client.cancel("slot")).resolves.toMatchObject({
      kind: "authenticated",
    });
    expect(JSON.parse(f.storage.record.sessionJSON!)).toEqual(active);
    expect(f.requests).toHaveLength(count);
  });

  it.each(["challenge", "token", "commit"] as const)(
    "preserves prior access when a new login fails at %s",
    async (boundary) => {
      const f = await fixture();
      await f.respond(await f.client.start("slot"));
      const active = JSON.parse(f.storage.record.sessionJSON!) as {
        refreshToken: string;
      };
      const step = await f.client.start("slot");
      const send = f.ports.send;
      f.ports.send = async (request) => {
        const response = await send(request);
        if (
          (boundary === "challenge" &&
            request.url.endsWith("/first-party/authorization-challenge")) ||
          (boundary === "token" && request.url.endsWith("/oauth2/token"))
        )
          throw new Error("lost response");
        return response;
      };
      f.storage.faults.rejectTokenCommit = boundary === "commit";
      await expect(f.respond(step)).rejects.toBeDefined();
      expect(JSON.parse(f.storage.record.sessionJSON!)).toMatchObject({
        phase: "active",
        refreshToken: active.refreshToken,
        detachedInteraction: true,
      });
      f.storage.faults.rejectTokenCommit = false;
      f.ports.send = send;
      await expect(
        f.client.fetch("slot", `${f.config.issuer}/sdk-resource`),
      ).resolves.toMatchObject({ status: 200 });
    },
  );

  it("never restores the old family when a pending login's resource refresh has an uncertain result", async () => {
    const f = await fixture();
    await f.respond(await f.client.start("slot"));
    await f.client.start("slot");
    const send = f.ports.send;
    f.ports.send = async (request) => {
      const response = await send(request);
      if (request.url.endsWith("/oauth2/token"))
        throw new Error("lost refresh response");
      return response;
    };
    const restarted = createFirstPartyClientCore(f.config, f.ports);
    await expect(
      restarted.fetch("slot", `${f.config.issuer}/sdk-resource`),
    ).rejects.toBeDefined();
    expect(f.storage.record.sessionJSON).toBeNull();
    expect(f.storage.record.recoverySessionJSON).toBeNull();
    await expect(restarted.cancel("slot")).resolves.toMatchObject({
      kind: "signed-out",
    });
  });

  it.each(["challenge", "token"] as const)(
    "cancels in-flight %s work without accepting its late completion",
    async (boundary) => {
      const f = await fixture();
      await f.respond(await f.client.start("slot"));
      const active = JSON.parse(f.storage.record.sessionJSON!) as {
        refreshToken: string;
      };
      const step = await f.client.start("slot");
      let started!: () => void;
      const waiting = new Promise<void>((resolve) => {
        started = resolve;
      });
      let complete!: () => void;
      const release = new Promise<void>((resolve) => {
        complete = resolve;
      });
      const send = f.ports.send;
      f.ports.send = async (request) => {
        const result = await send(request);
        if (
          (boundary === "challenge" &&
            request.url.endsWith("/first-party/authorization-challenge")) ||
          (boundary === "token" && request.url.endsWith("/oauth2/token"))
        ) {
          // Only hold the original response, not best-effort cancellation.
          f.ports.send = send;
          started();
          await release;
        }
        return result;
      };
      const operation = f.respond(step).catch((error: unknown) => error);
      await waiting;
      await expect(f.client.cancel("slot")).resolves.toMatchObject({
        kind: "authenticated",
      });
      await expect(operation).resolves.toMatchObject({ code: "cancelled" });
      const retained = f.storage.record.sessionJSON;
      complete();
      await new Promise<void>((resolve) => setTimeout(resolve, 0));
      expect(f.storage.record.sessionJSON).toBe(retained);
      expect(JSON.parse(retained!)).toMatchObject({
        refreshToken: active.refreshToken,
      });
      await expect(
        f.client.fetch("slot", `${f.config.issuer}/sdk-resource`),
      ).resolves.toMatchObject({ status: 200 });
    },
  );

  it("recovers the previous family when cancellation races the new login's committed tokens", async () => {
    const f = await fixture();
    await f.respond(await f.client.start("slot"));
    const active = JSON.parse(f.storage.record.sessionJSON!) as {
      refreshToken: string;
    };
    const step = await f.client.start("slot");
    if (step.kind !== "interaction-required")
      throw new Error("expected password step");
    const controller = new AbortController();
    const commit = f.storage.native.commit;
    f.storage.native.commit = async (...args) => {
      const generation = await commit(...args);
      controller.abort();
      return generation;
    };
    await expect(
      f.client.respond(
        "slot",
        {
          flowId: step.flowId,
          stepId: step.step.id,
          response: {
            kind: "password",
            email: f.testUser.email,
            password: f.testUser.password,
          },
        },
        controller.signal,
      ),
    ).rejects.toMatchObject({ code: "cancelled" });
    f.storage.native.commit = commit;
    expect(JSON.parse(f.storage.record.sessionJSON!)).toMatchObject({
      phase: "active",
      refreshToken: active.refreshToken,
    });
    await expect(
      f.client.fetch("slot", `${f.config.issuer}/sdk-resource`),
    ).resolves.toMatchObject({ status: 200 });
  });

  it.each([false, true])(
    "cancels browser reauthentication and respects account-security changes: %s",
    async (securityChanged) => {
      const f = await fixture();
      await f.respond(await f.client.start("slot"));
      f.resource.forceBrowser = true;
      if (securityChanged)
        await f.context.adapter.updateMany({
          model: "user",
          where: [],
          update: { twoFactorEnabled: true },
        });
      const step = await f.respond(await f.client.start("slot"));
      if (step.kind !== "browser-required")
        throw new Error("expected browser fallback");
      expect(step.hasSession).toBe(true);
      let opened!: () => void;
      const waiting = new Promise<void>((resolve) => {
        opened = resolve;
      });
      f.ports.browser = {
        open: ({ signal }) =>
          new Promise<string>((_resolve, reject) => {
            signal.addEventListener(
              "abort",
              () => reject(new FirstPartyClientError("cancelled")),
              { once: true },
            );
            opened();
          }),
      };
      const operation = f.client
        .openBrowser("slot", { flowId: step.flowId, stepId: step.step.id })
        .catch((error: unknown) => error);
      await waiting;
      await expect(f.client.cancel("slot")).resolves.toMatchObject({
        kind: "authenticated",
      });
      await expect(operation).resolves.toMatchObject({ code: "cancelled" });
      const access = f.client.fetch("slot", `${f.config.issuer}/sdk-resource`);
      if (securityChanged) {
        await expect(access).rejects.toMatchObject({
          code: "reauthentication_required",
          cleanup: "complete",
        });
        expect(f.storage.record.sessionJSON).toBeNull();
        expect(f.controls.removed).toBe(0);
      } else await expect(access).resolves.toMatchObject({ status: 200 });
    },
  );

  it("logs out the previous family even while a replacement login is pending", async () => {
    const f = await fixture();
    await f.respond(await f.client.start("slot"));
    await f.client.start("slot");
    await expect(f.client.logout("slot")).resolves.toMatchObject({
      kind: "signed-out",
      remote: "confirmed",
    });
    expect(f.storage.record.sessionJSON).toBeNull();
    expect(f.storage.record.recoverySessionJSON).toBeNull();
    await expect(f.client.cancel("slot")).resolves.toMatchObject({
      kind: "signed-out",
    });
  });

  it("cannot overwrite a newer login with a late callback from an older browser", async () => {
    const f = await fixture();
    await f.context.adapter.updateMany({
      model: "user",
      where: [],
      update: { twoFactorEnabled: true },
    });
    const step = await f.respond(await f.client.start("slot"));
    if (step.kind !== "browser-required")
      throw new Error("expected browser fallback");
    let opened!: () => void;
    const waiting = new Promise<void>((resolve) => {
      opened = resolve;
    });
    let finish!: (value: string) => void;
    f.ports.browser = {
      open: () => {
        opened();
        return new Promise((resolve) => {
          finish = resolve;
        });
      },
    };
    const pending = f.client
      .openBrowser("slot", { flowId: step.flowId, stepId: step.step.id })
      .catch((error: unknown) => error);
    await waiting;
    const stored = z
      .object({ browser: z.object({ state: z.string() }) })
      .parse(JSON.parse(f.storage.record.sessionJSON!));
    await f.client.start("slot");
    const newest = f.storage.record.sessionJSON;
    finish(
      `example:/callback?${new URLSearchParams({ code: "late-code", state: stored.browser.state, iss: f.config.issuer })}`,
    );
    await expect(pending).resolves.toMatchObject({ code: "invalid_state" });
    expect(JSON.parse(f.storage.record.sessionJSON!)).toEqual(
      JSON.parse(newest!),
    );
    expect(
      f.requests.filter((request) => request.url.endsWith("/oauth2/token")),
    ).toHaveLength(0);
  });

  it("completes real browser MFA and redeems its code with the original PKCE and exact callback", async () => {
    const f = await fixture();
    await f.context.adapter.updateMany({
      model: "user",
      where: [],
      update: { twoFactorEnabled: true },
    });
    const step = await f.respond(await f.client.start("slot"));
    if (step.kind !== "browser-required")
      throw new Error("expected browser fallback");
    await expect(
      f.client.openBrowser("slot", {
        flowId: step.flowId,
        stepId: step.step.id,
      }),
    ).resolves.toMatchObject({
      kind: "authenticated",
    });
    const exchange = f.requests.find((request) =>
      request.url.endsWith("/oauth2/token"),
    )!;
    expect(new URLSearchParams(exchange.body!).get("redirect_uri")).toBe(
      "example:/callback",
    );
    await expect(
      f.client.fetch("slot", `${f.config.issuer}/sdk-resource`),
    ).resolves.toMatchObject({ status: 200 });
    expect(f.storage.record.sessionJSON).not.toContain("requestUri");
    expect(f.storage.record.sessionJSON).not.toContain("verifier");
  });

  it("rejects a substituted browser callback before code redemption", async () => {
    const f = await fixture();
    await f.context.adapter.updateMany({
      model: "user",
      where: [],
      update: { twoFactorEnabled: true },
    });
    const step = await f.respond(await f.client.start("slot"));
    if (step.kind !== "browser-required")
      throw new Error("expected browser fallback");
    f.ports.browser = {
      open: async ({ url }) => {
        const callback = new URL(await f.completeBrowser(url));
        callback.searchParams.set("state", "substituted");
        return callback.href;
      },
    };
    await expect(
      f.client.openBrowser("slot", {
        flowId: step.flowId,
        stepId: step.step.id,
      }),
    ).rejects.toMatchObject({
      code: "invalid_response",
    });
    expect(
      f.requests.filter((request) => request.url.endsWith("/oauth2/token")),
    ).toHaveLength(0);
  });

  it("never opens an arbitrary request_uri as a URL", async () => {
    const f = await fixture();
    await f.context.adapter.updateMany({
      model: "user",
      where: [],
      update: { twoFactorEnabled: true },
    });
    const step = await f.respond(await f.client.start("slot"));
    if (step.kind !== "browser-required")
      throw new Error("expected browser fallback");
    const send = f.ports.send;
    f.ports.send = async (request) => {
      const response = await send(request);
      const body = JSON.parse(response.body) as Record<string, unknown>;
      return {
        ...response,
        body: JSON.stringify({
          ...body,
          request_uri: "https://attacker.example",
        }),
      };
    };
    const open = vi.fn();
    f.ports.browser = { open };
    await expect(
      f.client.openBrowser("slot", {
        flowId: step.flowId,
        stepId: step.step.id,
      }),
    ).rejects.toMatchObject({
      code: "invalid_response",
    });
    expect(open).not.toHaveBeenCalled();
  });

  it("cancels an open browser without holding a lease and rejects its late callback", async () => {
    const f = await fixture();
    await f.context.adapter.updateMany({
      model: "user",
      where: [],
      update: { twoFactorEnabled: true },
    });
    const step = await f.respond(await f.client.start("slot"));
    if (step.kind !== "browser-required")
      throw new Error("expected browser fallback");
    let started!: () => void;
    const waiting = new Promise<void>((resolve) => {
      started = resolve;
    });
    let finish!: (value: string) => void;
    f.ports.browser = {
      open: () => {
        started();
        return new Promise((resolve) => {
          finish = resolve;
        });
      },
    };
    const result = f.client
      .openBrowser("slot", { flowId: step.flowId, stepId: step.step.id })
      .catch((error: unknown) => error);
    await waiting;
    expect(f.storage.record.lease).toBeNull();
    await expect(
      f.client.openBrowser("slot", {
        flowId: step.flowId,
        stepId: step.step.id,
      }),
    ).rejects.toMatchObject({
      code: "browser_busy",
    });
    await expect(f.client.cancel("slot")).resolves.toMatchObject({
      kind: "signed-out",
    });
    finish("example:/callback?code=late");
    await expect(result).resolves.toMatchObject({ code: "cancelled" });
    expect(
      f.requests.filter((request) => request.url.endsWith("/oauth2/token")),
    ).toHaveLength(0);
    expect(f.storage.record.sessionJSON).toBeNull();
  });

  it("does not reopen a one-use browser handoff after replacing the runtime", async () => {
    const f = await fixture();
    await f.context.adapter.updateMany({
      model: "user",
      where: [],
      update: { twoFactorEnabled: true },
    });
    const step = await f.respond(await f.client.start("slot"));
    if (step.kind !== "browser-required")
      throw new Error("expected browser fallback");
    f.ports.browser = {
      open: () =>
        Promise.reject(new FirstPartyClientError("browser_unavailable")),
    };
    await expect(
      f.client.openBrowser("slot", {
        flowId: step.flowId,
        stepId: step.step.id,
      }),
    ).rejects.toMatchObject({
      code: "browser_unavailable",
    });
    const restarted = createFirstPartyClientCore(f.config, f.ports);
    const restored = await restarted.restore("slot");
    if (restored.kind !== "browser-required")
      throw new Error("expected retained browser state");
    const before = f.storage.record.sessionJSON;
    await expect(
      restarted.openBrowser("slot", {
        flowId: restored.flowId,
        stepId: restored.step.id,
      }),
    ).rejects.toMatchObject({ code: "invalid_state" });
    expect(f.storage.record.sessionJSON).toBe(before);
  });

  it("does not delete keys when confirmed retirement cannot be durably recorded", async () => {
    const f = await fixture();
    await f.respond(await f.client.start("slot"));
    f.ports.vault.saveIdentity = () =>
      Promise.reject(new FirstPartyClientError("vault_storage_failed"));
    await expect(f.client.retire("slot")).rejects.toMatchObject({
      code: "vault_storage_failed",
    });
    expect(f.controls.removed).toBe(0);
    expect(f.storage.record.sessionJSON).toBeNull();
    expect(JSON.parse(f.storage.record.identityJSON!)).not.toHaveProperty(
      "retired",
    );
    const credentials = await f.context.adapter.findMany<{ status: string }>({
      model: "firstPartyCredential",
    });
    expect(credentials[0]?.status).toBe("revoked");
  });

  it("cancels a resource request without discarding the known committed login", async () => {
    const f = await fixture();
    await f.respond(await f.client.start("slot"));
    const session = f.storage.record.sessionJSON;
    const send = f.ports.send;
    const controller = new AbortController();
    f.ports.send = () => {
      controller.abort();
      return new Promise<never>(() => undefined);
    };
    await expect(
      f.client.fetch("slot", `${f.config.issuer}/sdk-resource`, {
        signal: controller.signal,
      }),
    ).rejects.toMatchObject({ code: "cancelled" });
    expect(f.storage.record.sessionJSON).toBe(session);
    expect(f.storage.record.lease).toBeNull();
    f.ports.send = send;
    await expect(
      f.client.fetch("slot", `${f.config.issuer}/sdk-resource`),
    ).resolves.toMatchObject({ status: 200 });
  });

  it("binds resource requests to the access token and reuses its private cache", async () => {
    const f = await fixture();
    await f.respond(await f.client.start("slot"));
    const url = `${f.config.issuer}/sdk-resource`;
    const before = f.requests.filter((request) =>
      request.url.endsWith("/oauth2/token"),
    ).length;
    const response = await f.client.fetch("slot", `${url}?page=1`, {
      method: "POST",
      body: "payload",
      headers: { "X-Request-Id": "business-id" },
    });
    expect(response.status).toBe(200);
    expect(JSON.parse(response.body)).toMatchObject({ effects: 1 });
    await expect(f.client.fetch("slot", url)).resolves.toMatchObject({
      status: 200,
    });
    expect(
      f.requests.filter((request) => request.url.endsWith("/oauth2/token")),
    ).toHaveLength(before);
    const sent = f.requests.find((request) => request.url === `${url}?page=1`)!;
    const token = sent.headers.Authorization!.slice(5);
    expect(
      JSON.parse(
        Buffer.from(sent.headers.DPoP!.split(".")[1]!, "base64url").toString(),
      ),
    ).toMatchObject({
      htm: "POST",
      htu: url,
      ath: hash(token).toString("base64url"),
    });
    expect(sent.headers["x-request-id"]).toBe("business-id");
    expect(f.storage.record.sessionJSON).not.toContain(token);
  });

  it("commits refresh before a resource side effect and detects another runtime's rotation", async () => {
    const f = await fixture();
    await f.respond(await f.client.start("slot"));
    const before = f.storage.record.sessionJSON;
    const send = f.ports.send;
    f.ports.send = async (request) => {
      if (request.url.endsWith("/sdk-resource"))
        expect(f.storage.record.sessionJSON).not.toBe(before);
      return send(request);
    };
    const restarted = createFirstPartyClientCore(f.config, f.ports);
    await expect(
      restarted.fetch("slot", `${f.config.issuer}/sdk-resource`, {
        method: "POST",
      }),
    ).resolves.toMatchObject({ status: 200 });
    expect(f.resource.effects).toBe(1);
    const rotated = f.storage.record.sessionJSON;
    await expect(
      f.client.fetch("slot", `${f.config.issuer}/sdk-resource`),
    ).resolves.toMatchObject({ status: 200 });
    expect(f.storage.record.sessionJSON).not.toBe(rotated);
  });

  it("does not execute an application operation when rotated-token storage fails", async () => {
    const f = await fixture();
    await f.respond(await f.client.start("slot"));
    f.storage.faults.rejectTokenCommit = true;
    const restarted = createFirstPartyClientCore(f.config, f.ports);
    await expect(
      restarted.fetch("slot", `${f.config.issuer}/sdk-resource`, {
        method: "POST",
      }),
    ).rejects.toMatchObject({ code: "vault_storage_failed" });
    expect(f.resource.calls).toBe(0);
    expect(f.storage.record.sessionJSON).toBeNull();
  });

  it("rejects credential exfiltration and request overrides before touching a valid session", async () => {
    const f = await fixture();
    await f.respond(await f.client.start("slot"));
    const before = { ...f.storage.record };
    const count = f.requests.length;
    for (const url of [
      "https://evil.example/resource",
      `${f.config.issuer}/sdk-resource#fragment`,
      "https://user:pass@evil.example/resource",
      "not-url",
    ])
      await expect(f.client.fetch("slot", url)).rejects.toMatchObject({
        code: "invalid_request",
      });
    for (const input of [
      { headers: { aUtHoRiZaTiOn: "secret" } },
      { headers: { DPoP: "forged" } },
      { headers: { Cookie: "cookie" } },
      { headers: { Test: "a\r\nb" } },
      { headers: { Test: "a", test: "b" } },
      { body: "GET-body" },
      { maximumResponseBytes: 0 },
    ])
      await expect(
        f.client.fetch("slot", `${f.config.issuer}/sdk-resource`, input),
      ).rejects.toMatchObject({ code: "invalid_request" });
    expect(f.requests).toHaveLength(count);
    expect(f.storage.record).toEqual(before);
  });

  it("never retries an ambiguous business write and preserves its already committed session", async () => {
    const f = await fixture();
    await f.respond(await f.client.start("slot"));
    const before = f.storage.record.sessionJSON;
    const send = f.ports.send;
    f.ports.send = async (request) => {
      const response = await send(request);
      if (request.url.endsWith("/sdk-resource") && request.method === "POST")
        throw new Error("lost response with secrets");
      return response;
    };
    await expect(
      f.client.fetch("slot", `${f.config.issuer}/sdk-resource`, {
        method: "POST",
      }),
    ).rejects.toMatchObject({ code: "request_failed" });
    expect(f.resource.effects).toBe(1);
    expect(f.storage.record.sessionJSON).toBe(before);
    await expect(
      f.client.fetch("slot", `${f.config.issuer}/sdk-resource`),
    ).resolves.toMatchObject({ status: 200 });
    expect(f.resource.effects).toBe(1);
  });

  it("returns rejected resource access without silently replaying the application operation", async () => {
    const f = await fixture();
    await f.respond(await f.client.start("slot"));
    const send = f.ports.send;
    f.ports.send = (request) =>
      send({
        ...request,
        headers: { ...request.headers, DPoP: "invalid-proof" },
      });
    await expect(
      f.client.fetch("slot", `${f.config.issuer}/sdk-resource`, {
        method: "POST",
      }),
    ).resolves.toMatchObject({ status: 401 });
    expect(f.resource.calls).toBe(1);
    expect(f.resource.effects).toBe(0);
    expect(f.storage.record.sessionJSON).not.toBeNull();
  });

  it("clears local capabilities before confirmed remote logout and retains both keys", async () => {
    const f = await fixture();
    await f.respond(await f.client.start("slot"));
    const send = f.ports.send;
    f.ports.send = (request) => {
      if (request.url.endsWith("/first-party/logout"))
        expect(f.storage.record.sessionJSON).toBeNull();
      return send(request);
    };
    await expect(f.client.logout("slot")).resolves.toEqual({
      kind: "signed-out",
      slotId: "slot",
      remote: "confirmed",
      keys: "retained",
    });
    expect(f.storage.record.sessionJSON).toBeNull();
    expect(f.controls.removed).toBe(0);
    const families = await f.context.adapter.findMany<{ status: string }>({
      model: "firstPartyTokenFamily",
    });
    expect(families.every((family) => family.status === "revoked")).toBe(true);
    await expect(f.client.start("slot")).resolves.toMatchObject({
      kind: "interaction-required",
    });
  });

  it("reports offline logout honestly and never removes keys", async () => {
    const f = await fixture();
    await f.respond(await f.client.start("slot"));
    f.ports.send = () => Promise.reject(new Error("offline"));
    await expect(f.client.logout("slot")).resolves.toMatchObject({
      remote: "unconfirmed",
      keys: "retained",
    });
    expect(f.storage.record.sessionJSON).toBeNull();
    expect(f.controls.removed).toBe(0);
    await expect(
      f.client.fetch("slot", `${f.config.issuer}/sdk-resource`),
    ).rejects.toMatchObject({ code: "reauthentication_required" });
  });

  it("retires the credential before removing keys and permanently fences the old slot", async () => {
    const f = await fixture({ ios: true });
    await f.respond(await f.client.start("slot"));
    await expect(f.client.retire("slot")).resolves.toEqual({
      kind: "signed-out",
      slotId: "slot",
      remote: "confirmed",
      keys: "removed",
    });
    expect(f.controls.removed).toBe(1);
    expect(f.storage.record.sessionJSON).toBeNull();
    expect(JSON.parse(f.storage.record.identityJSON!)).toMatchObject({
      retired: true,
    });
    const credentials = await f.context.adapter.findMany<{ status: string }>({
      model: "firstPartyCredential",
    });
    expect(credentials).toHaveLength(1);
    expect(credentials[0]?.status).toBe("revoked");
    await expect(f.client.start("slot")).rejects.toMatchObject({
      code: "reauthentication_required",
    });
    expect(f.controls.nativeRegistrations).toBe(1);
  });

  it("retains keys after an unconfirmed retirement response", async () => {
    const f = await fixture();
    await f.respond(await f.client.start("slot"));
    const send = f.ports.send;
    f.ports.send = async (request) => {
      const response = await send(request);
      if (request.url.endsWith("/first-party/retire"))
        throw new Error("lost retirement response");
      return response;
    };
    await expect(f.client.retire("slot")).resolves.toMatchObject({
      remote: "unconfirmed",
      keys: "retained",
    });
    expect(f.controls.removed).toBe(0);
    expect(f.storage.record.sessionJSON).toBeNull();
    expect(JSON.parse(f.storage.record.identityJSON!)).not.toHaveProperty(
      "retired",
    );
  });

  it("retries only local key removal after a durably confirmed retirement", async () => {
    const f = await fixture({ ios: true });
    await f.respond(await f.client.start("slot"));
    f.controls.failRemoval = true;
    await expect(f.client.retire("slot")).resolves.toMatchObject({
      remote: "confirmed",
      keys: "removal-pending",
    });
    expect(JSON.parse(f.storage.record.identityJSON!)).toMatchObject({
      retired: true,
    });
    f.controls.failRemoval = false;
    f.ports.send = () =>
      Promise.reject(new Error("must not use old authority"));
    const restarted = createFirstPartyClientCore(f.config, f.ports);
    await expect(restarted.retire("slot")).resolves.toMatchObject({
      remote: "confirmed",
      keys: "removed",
    });
    expect(f.controls.removed).toBe(1);
  });

  it("logout preempts an in-flight request and cannot expose its late response", async () => {
    const f = await fixture();
    await f.respond(await f.client.start("slot"));
    let complete!: (
      response: Awaited<ReturnType<FirstPartyClientPorts["send"]>>,
    ) => void;
    let started!: () => void;
    const waiting = new Promise<void>((resolve) => {
      started = resolve;
    });
    f.ports.send = () => {
      started();
      return new Promise((resolve) => {
        complete = resolve;
      });
    };
    const request = f.client
      .fetch("slot", `${f.config.issuer}/sdk-resource`)
      .catch((error: unknown) => error);
    await waiting;
    await expect(f.client.logout("slot")).resolves.toMatchObject({
      remote: "unconfirmed",
      keys: "retained",
    });
    await expect(request).resolves.toMatchObject({ code: "cancelled" });
    complete({
      url: `${f.config.issuer}/sdk-resource`,
      status: 200,
      body: "{}",
    });
    expect(f.storage.record.sessionJSON).toBeNull();
  });

  it("uses the iOS adapter for registration, admission, login and retained-key refresh", async () => {
    const f = await fixture({ ios: true });
    await expect(
      f.respond(await f.client.start("slot")),
    ).resolves.toMatchObject({ kind: "authenticated" });
    expect(f.controls.nativeRegistrations).toBe(1);
    expect(JSON.parse(f.storage.record.identityJSON!)).toMatchObject({
      providerRegistration: "registered",
    });
    const restarted = createFirstPartyClientCore(f.config, f.ports);
    await expect(restarted.restore("slot")).resolves.toMatchObject({
      kind: "authenticated",
    });
    expect(f.controls.nativeRegistrations).toBe(1);
  });

  it("recovers a lost registration response by assertion after a fresh client start", async () => {
    const f = await fixture({ ios: true });
    f.controls.loseRegistrationResponse = true;
    await expect(f.client.start("slot")).rejects.toMatchObject({
      code: "request_failed",
    });
    expect(JSON.parse(f.storage.record.identityJSON!)).toMatchObject({
      providerRegistration: "attesting",
    });
    expect(f.storage.record.sessionJSON).toBeNull();
    f.controls.loseRegistrationResponse = false;
    const restarted = createFirstPartyClientCore(f.config, f.ports);
    await expect(restarted.start("slot")).resolves.toMatchObject({
      kind: "interaction-required",
    });
    expect(f.controls.nativeRegistrations).toBe(1);
    expect(JSON.parse(f.storage.record.identityJSON!)).toMatchObject({
      providerRegistration: "registered",
    });
  });

  it("requires explicit recovery after uncertain Apple attestation without re-attesting the key", async () => {
    const f = await fixture({ ios: true });
    f.controls.failNativeAttestation = true;
    await expect(f.client.start("slot")).rejects.toMatchObject({
      code: "operation_failed",
    });
    const retained = f.storage.record.identityJSON;
    f.controls.failNativeAttestation = false;
    const restarted = createFirstPartyClientCore(f.config, f.ports);
    await expect(restarted.start("slot")).rejects.toMatchObject({
      code: "registration_recovery_required",
    });
    expect(f.controls.nativeRegistrations).toBe(1);
    expect(f.storage.record.identityJSON).toBe(retained);
    expect(f.storage.record.sessionJSON).toBeNull();
  });

  it("refuses registration journaling that changes the prepared key identity", async () => {
    const f = await fixture();
    f.ports.keys.admission = async (identity, _binding, context) => {
      await context.saveIdentity({
        ...identity,
        dpopAlias: "replacement-key",
        providerRegistration: "registered",
      });
      throw new Error("must not proceed");
    };
    await expect(f.client.start("slot")).rejects.toMatchObject({
      code: "invalid_state",
    });
    expect(JSON.parse(f.storage.record.identityJSON!)).toMatchObject({
      dpopAlias: "stable-slot-key",
    });
  });

  it("returns browser-required when Better Auth requires MFA, without issuing mobile tokens", async () => {
    const f = await fixture();
    await f.context.adapter.updateMany({
      model: "user",
      where: [],
      update: { twoFactorEnabled: true },
    });
    const step = await f.respond(await f.client.start("slot"));
    expect(step).toMatchObject({
      kind: "browser-required",
      step: { kind: "browser-required" },
    });
    expect(
      f.requests.some((request) => request.url.endsWith("/oauth2/token")),
    ).toBe(false);
    expect(JSON.stringify(step)).not.toContain("authSession");
    expect(f.storage.record.sessionJSON).not.toContain("refreshToken");
  });

  it.each([
    ["redirect", "invalid_response"],
    ["origin", "invalid_response"],
    ["oversized", "invalid_response"],
    ["json", "invalid_response"],
    ["unknown-step", "unsupported_step"],
    ["server-error", "request_failed"],
  ] as const)(
    "rejects %s responses without accepting or logging a capability",
    async (mode, code) => {
      const f = await fixture();
      const send = f.ports.send;
      f.ports.send = async (request) => {
        const response = await send(request);
        if (mode === "redirect") return { ...response, status: 302 };
        if (mode === "origin")
          return { ...response, url: "https://unapproved.example/" };
        if (mode === "oversized")
          return { ...response, body: " ".repeat(65537) };
        if (mode === "json") return { ...response, body: "raw-secret-error" };
        if (mode === "server-error")
          return {
            ...response,
            status: 500,
            body: '{"error":"raw-secret-error"}',
          };
        return {
          ...response,
          body: JSON.stringify({
            error: "insufficient_authorization",
            auth_session: "secret-handle",
            step: { kind: "unexpected-factor", id: "step" },
          }),
        };
      };
      const error: unknown = await f.client
        .start("slot")
        .catch((value: unknown) => value);
      expect(error).toMatchObject({ code });
      expect(String(error)).not.toContain("secret");
      expect(f.storage.record.sessionJSON).toBeNull();
      expect(f.storage.record.identityJSON).not.toBeNull();
    },
  );

  it("restores a pending interaction without performing refresh and cancels without removing keys", async () => {
    const f = await fixture();
    const step = await f.client.start("slot");
    const count = f.requests.length;
    const identity = f.storage.record.identityJSON;
    await expect(
      createFirstPartyClientCore(f.config, f.ports).restore("slot"),
    ).resolves.toEqual(step);
    expect(f.requests).toHaveLength(count);
    await expect(f.client.cancel("slot")).resolves.toEqual({
      kind: "signed-out",
      slotId: "slot",
    });
    expect(f.storage.record.sessionJSON).toBeNull();
    expect(f.storage.record.identityJSON).toBe(identity);
    await expect(f.client.restore("slot")).resolves.toEqual({
      kind: "signed-out",
      slotId: "slot",
    });
  });

  it("rejects bearer issuance and corrupt stored sessions", async () => {
    const f = await fixture();
    const step = await f.client.start("slot");
    const send = f.ports.send;
    f.ports.send = async (request) => {
      const response = await send(request);
      if (!request.url.endsWith("/oauth2/token")) return response;
      return {
        ...response,
        body: JSON.stringify({
          ...(JSON.parse(response.body) as object),
          token_type: "Bearer",
        }),
      };
    };
    await expect(f.respond(step)).rejects.toMatchObject({
      code: "invalid_response",
    });
    f.storage.record.sessionJSON = '{"version":100,"phase":"active"}';
    await expect(f.client.restore("slot")).rejects.toMatchObject({
      code: "vault_corrupt",
    });
    expect(f.storage.record.sessionJSON).toBeNull();
  });

  it("rejects a refresh response that reuses the consumed token", async () => {
    const f = await fixture();
    await f.respond(await f.client.start("slot"));
    const old = (
      JSON.parse(f.storage.record.sessionJSON!) as { refreshToken: string }
    ).refreshToken;
    const send = f.ports.send;
    f.ports.send = async (request) => {
      const response = await send(request);
      return {
        ...response,
        body: JSON.stringify({
          ...(JSON.parse(response.body) as object),
          refresh_token: old,
        }),
      };
    };
    await expect(f.client.restore("slot")).rejects.toMatchObject({
      code: "invalid_response",
    });
    expect(f.storage.record.sessionJSON).toBeNull();
  });

  it("rejects insecure issuers and malformed input before mutation", async () => {
    const f = await fixture();
    for (const issuer of [
      "http://remote.example/auth",
      "https://user:password@example.com",
      "https://example.com?query=1",
      "file:///auth",
    ]) {
      expect(() =>
        createFirstPartyClientCore({ ...f.config, issuer }, f.ports),
      ).toThrow();
    }
    await expect(
      f.client.respond("slot", {
        flowId: "bad",
        stepId: "bad",
        response: {
          kind: "password",
          email: "invalid",
          password: "",
        },
      }),
    ).rejects.toMatchObject({ code: "invalid_state" });
    expect(f.storage.record.generation).toBe(0);
  });

  it("performs proof-bound password login, hides capabilities, and refreshes after runtime replacement", async () => {
    const f = await fixture();
    const step = await f.client.start("slot");
    expect(step).toMatchObject({
      kind: "interaction-required",
      step: { kind: "password" },
    });
    const saved = f.storage.record.sessionJSON;
    const rejected = await f.respond(step, "incorrect-password");
    expect(rejected).toMatchObject({
      kind: "interaction-required",
      failure: "invalid_credentials",
    });
    expect(f.storage.record.sessionJSON).not.toBe(saved);
    expect(f.storage.record.sessionJSON).not.toContain("incorrect-password");
    const success = await f.respond(rejected);
    expect(success).toMatchObject({
      kind: "authenticated",
      slotId: "slot",
    });
    const token = f.responses.at(-1)!;
    expect(token.token_type).toBe("DPoP");
    expect(f.storage.record.sessionJSON).toContain(token.refresh_token);
    expect(f.storage.record.sessionJSON).not.toContain(token.access_token);
    expect(JSON.stringify(success)).not.toContain("auth_session");
    const restarted = createFirstPartyClientCore(f.config, f.ports);
    await expect(restarted.restore("slot")).resolves.toEqual(success);
    expect(f.storage.record.sessionJSON).not.toContain(token.refresh_token);
    expect(f.ports.keys.prepare).toHaveBeenCalledTimes(1);
    for (const request of f.requests) {
      expect(request.headers.DPoP).toMatch(/^[\w-]+\.[\w-]+\.[\w-]+$/);
      expect(request.headers["Content-Type"]).toBe(
        "application/x-www-form-urlencoded",
      );
      expect(new URLSearchParams(request.body ?? "").has("redirect_uri")).toBe(
        false,
      );
    }
    expect(
      new Set(f.requests.map((request) => request.headers.DPoP)).size,
    ).toBe(f.requests.length);
  });

  it("rejects stale UI steps without destroying the current continuation", async () => {
    const f = await fixture();
    const step = await f.client.start("slot");
    const saved = f.storage.record.sessionJSON;
    await expect(
      f.client.respond("slot", {
        flowId: random(),
        stepId: "stale",
        response: {
          kind: "password",
          email: "someone@example.com",
          password: "secret",
        },
      }),
    ).rejects.toMatchObject({ code: "invalid_state" });
    expect(JSON.parse(f.storage.record.sessionJSON!) as unknown).toEqual(
      JSON.parse(saved!) as unknown,
    );
    await expect(f.respond(step)).resolves.toMatchObject({
      kind: "authenticated",
    });
  });

  it("renews expired evidence on the same binding after password verification", async () => {
    const f = await fixture();
    const step = await f.client.start("slot");
    await f.context.adapter.updateMany({
      model: "firstPartyAttempt",
      where: [],
      update: { evidenceExpiresAt: new Date(0) },
    });
    const renewal = await f.respond(step);
    expect(renewal).toMatchObject({
      kind: "interaction-required",
      step: { kind: "attestation" },
    });
    if (renewal.kind !== "interaction-required")
      throw new Error("expected renewal");
    const next = await f.client.respond("slot", {
      flowId: renewal.flowId,
      stepId: renewal.step.id,
      response: { kind: "attestation" },
    });
    // Evidence expiring before password submission may require the password again.
    if (next.kind === "interaction-required")
      await expect(f.respond(next)).resolves.toMatchObject({
        kind: "authenticated",
      });
    else expect(next.kind).toBe("authenticated");
  });

  it.each(["write", "response"])(
    "does not expose authentication after uncertain %s completion",
    async (failure) => {
      const f = await fixture();
      const step = await f.client.start("slot");
      const identity = f.storage.record.identityJSON;
      f.storage.faults.rejectTokenCommit = failure === "write";
      f.controls.loseTokenResponse = failure === "response";
      await expect(f.respond(step)).rejects.toBeInstanceOf(Error);
      expect(f.storage.record.sessionJSON).toBeNull();
      expect(f.storage.record.identityJSON).toBe(identity);
      expect(
        f.requests.filter((request) => request.url.endsWith("/oauth2/token")),
      ).toHaveLength(1);
    },
  );

  it("clears session capabilities on missing keys without generating replacements", async () => {
    const f = await fixture();
    await f.respond(await f.client.start("slot"));
    const identity = f.storage.record.identityJSON;
    const count = f.requests.length;
    f.controls.missingKey = true;
    await expect(f.client.restore("slot")).rejects.toBeInstanceOf(Error);
    expect(f.storage.record.identityJSON).toBe(identity);
    expect(f.storage.record.sessionJSON).toBeNull();
    expect(f.requests).toHaveLength(count);
    expect(f.ports.keys.prepare).toHaveBeenCalledTimes(1);
  });
});

describe("local origins at the client boundary", () => {
  it("constructs local clients and applies the same resource policy", async () => {
    const f = await fixture();
    for (const host of [
      "localhost",
      "eventyr.localhost",
      "deep.eventyr.localhost",
      "EVENTYR.LocalHost",
      "localhost.",
      "eventyr.localhost.",
      "a-b.localhost",
      "127.0.0.1",
      "[::1]",
    ]) {
      const issuer = `http://${host}:3000/api/auth`;
      expect(() =>
        createFirstPartyClientCore(
          { ...f.config, issuer, allowInsecureLoopback: false },
          f.ports,
        ),
      ).toThrow(expect.objectContaining({ code: "invalid_configuration" }));
      const client = createFirstPartyClientCore(
        { ...f.config, issuer },
        f.ports,
      );
      // Valid requests reach session lookup, even before an account exists.
      await expect(
        client.fetch("slot", `${issuer}/resource`),
      ).rejects.toMatchObject({ code: "reauthentication_required" });
    }
    for (const host of [
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
    ]) {
      const url = `http://${host}:3000/resource`;
      expect(() =>
        createFirstPartyClientCore({ ...f.config, issuer: url }, f.ports),
      ).toThrow(expect.objectContaining({ code: "invalid_configuration" }));
      const client = createFirstPartyClientCore(
        { ...f.config, resources: [url] },
        f.ports,
      );
      await expect(client.fetch("slot", url)).rejects.toMatchObject({
        code: "invalid_request",
      });
    }
  });
});

describe("development native protocol failure boundaries", () => {
  it("keeps failed password and cancelled OTP attempts signed out", async () => {
    const f = await fixture({ ios: true, development: true, emailOTP: true });
    const wrong = await f.respond(await f.client.start("slot"), "incorrect");
    expect(wrong).toMatchObject({
      kind: "interaction-required",
      failure: "invalid_credentials",
    });
    await f.client.cancel("slot");
    expect(await f.client.restore("slot")).toMatchObject({
      kind: "signed-out",
    });
    const start = await f.client.start("slot");
    if (start.kind !== "interaction-required")
      throw new Error("expected interaction");
    await f.client.respond("slot", {
      flowId: start.flowId,
      stepId: start.step.id,
      response: { kind: "email-otp-request", email: f.testUser.email },
    });
    await f.client.cancel("slot");
    await expect(
      f.client.fetch("slot", `${f.config.issuer}/sdk-resource`),
    ).rejects.toMatchObject({ code: "reauthentication_required" });
    expect(
      await f.context.adapter.count({
        model: "firstPartyTokenFamily",
        where: [{ field: "status", value: "active" }],
      }),
    ).toBe(0);
  });
  it.each([
    "provider",
    "environment",
    "deployment-authorization",
    "production-deployment",
  ])(
    "rejects development token refresh and resource access after %s policy changes",
    async (change) => {
      vi.stubEnv("NODE_ENV", "production");
      const f = await fixture({ ios: true, development: true });
      expect((await f.respond(await f.client.start("slot"))).kind).toBe(
        "authenticated",
      );
      if (change === "provider")
        f.nativeOptions.applications[0]!.provider = {
          ...(f.nativeOptions.applications[0]!
            .provider as DeviceAttestationProvider),
          id: "app-attest",
        };
      if (change === "production-deployment")
        f.deployment.target = "production";
      if (change === "environment")
        f.nativeOptions.applications[0]!.environment = "production";
      if (change === "deployment-authorization")
        f.deployment.allowDevelopmentAuthentication = false;
      try {
        const response = await f.client
          .fetch("slot", `${f.config.issuer}/sdk-resource`)
          .catch((e: unknown) => e);
        expect(response).not.toMatchObject({ status: 200 });
        await expect(f.client.restore("slot")).rejects.toBeInstanceOf(
          FirstPartyClientError,
        );
      } finally {
        vi.unstubAllEnvs();
      }
    },
  );
});

it("production deployment denies initial development token issuance even after successful password verification", async () => {
  vi.stubEnv("NODE_ENV", "production");
  const f = await fixture({ ios: true, development: true });
  const step = await f.client.start("slot");
  const send = f.ports.send;
  f.ports.send = (request) => {
    if (request.url.endsWith("/oauth2/token"))
      f.deployment.target = "production";
    return send(request);
  };
  try {
    await expect(f.respond(step)).rejects.toBeInstanceOf(FirstPartyClientError);
    expect(await f.context.adapter.count({ model: "oauthRefreshToken" })).toBe(
      0,
    );
  } finally {
    vi.unstubAllEnvs();
  }
});
it("a server without the development provider rejects development registration", async () => {
  const f = await fixture({ ios: true });
  await expect(
    f.auth.api.createDeviceAttestationChallenge!({
      body: {
        provider: "development",
        applicationId: f.config.applicationId,
        keyId: randomBytes(32).toString("base64"),
        operation: "register",
        purpose: "credential-registration",
      },
    }),
  ).rejects.toThrow();
});

// Exercise the shipped TypeScript provider and real server verification. Only
// generic device storage/HTTP ports are replaced; evidence and DPoP are real.
it.each(["ios", "android"])(
  "runs authorized local E2E with NODE_ENV=production: password/OTP, restore, fetch, cancellation and logout on %s",
  async (platform) => {
    vi.stubEnv("NODE_ENV", "production");
    const f = await fixture({ ios: true, development: true, emailOTP: true });
    const stored = new Map<string, string>();
    vi.doMock("@react-native-async-storage/async-storage", () => ({
      default: {
        getItem: (key: string) => Promise.resolve(stored.get(key) ?? null),
        setItem: (key: string, value: string) => {
          stored.set(key, value);
          return Promise.resolve();
        },
      },
    }));
    const hardware = vi.fn(() => {
      throw new Error("hardware must not be called");
    });
    const transport = {
      randomToken: () => Promise.resolve(random()),
      transaction: () => f.ports.crypto.transaction(),
      prepareDpop: hardware,
      signDpop: hardware,
      send: async (
        _id: string,
        url: string,
        method: "POST",
        headersJSON: string,
        body: string | null,
        maximumResponseBytes: number,
      ) => {
        const result = await f.ports.send({
          url,
          method,
          headers: JSON.parse(headersJSON) as Record<string, string>,
          body,
          maximumResponseBytes,
          signal: new AbortController().signal,
        });
        return {
          url: result.url,
          status: result.status,
          body: result.body,
          headersJSON: JSON.stringify(result.headers ?? {}),
        };
      },
      cancel: () => Promise.resolve(),
      openBrowser: hardware,
      cancelBrowser: () => Promise.resolve(),
    };
    vi.resetModules();
    vi.doMock("react-native", () => ({
      Platform: { OS: platform },
      TurboModuleRegistry: {
        get: (name: string) =>
          (
            ({
              DeviceAttestationFirstPartyTransport: transport,
            }) as Record<string, unknown>
          )[name] ?? null,
      },
    }));
    try {
      const { createNativeFirstPartyClient } =
        await import("./native-client.ts");
      const compose = () =>
        createNativeFirstPartyClient({
          ...f.config,
          provider: "development",
          environment: "development",
        });
      let sdk = compose();
      const account = await sdk.accounts.create();
      const slot = account.slotId;
      const password = async (value: string) => {
        const start = await sdk.start(slot);
        if (start.kind !== "interaction-required")
          throw new Error("expected password");
        return sdk.respond(slot, {
          flowId: start.flowId,
          stepId: start.step.id,
          response: {
            kind: "password",
            email: f.testUser.email,
            password: value,
          },
        });
      };
      expect(await password("wrong-password")).toMatchObject({
        failure: "invalid_credentials",
      });
      await sdk.cancel(slot);
      expect(await sdk.restore(slot)).toMatchObject({ kind: "signed-out" });
      expect(await password(f.testUser.password)).toMatchObject({
        kind: "authenticated",
      });
      sdk = compose();
      expect(await sdk.accounts.list()).toMatchObject([
        { slotId: slot, hasSession: true },
      ]);
      expect(await sdk.restore(slot)).toMatchObject({ kind: "authenticated" });
      expect(
        await sdk.fetch(slot, `${f.config.issuer}/sdk-resource`),
      ).toMatchObject({ status: 200 });
      expect(await sdk.logout(slot)).toMatchObject({
        remote: "confirmed",
        keys: "retained",
      });
      await expect(
        sdk.fetch(slot, `${f.config.issuer}/sdk-resource`),
      ).rejects.toMatchObject({ code: "reauthentication_required" });
      const start = await sdk.start(slot);
      if (start.kind !== "interaction-required")
        throw new Error("expected selection");
      const sent = await sdk.respond(slot, {
        flowId: start.flowId,
        stepId: start.step.id,
        response: { kind: "email-otp-request", email: f.testUser.email },
      });
      if (sent.kind !== "interaction-required") throw new Error("expected OTP");
      sdk = compose();
      expect(await sdk.restore(slot)).toEqual(sent);
      const wrong = await sdk.respond(slot, {
        flowId: sent.flowId,
        stepId: sent.step.id,
        response: { kind: "email-otp", otp: "invalid-code" },
      });
      if (wrong.kind !== "interaction-required")
        throw new Error("expected retry");
      expect(wrong.failure).toBe("invalid_credentials");
      expect(
        await sdk.respond(slot, {
          flowId: wrong.flowId,
          stepId: wrong.step.id,
          response: { kind: "email-otp", otp: f.sentOTP[0]!.otp },
        }),
      ).toMatchObject({ kind: "authenticated" });
      expect(
        await sdk.fetch(slot, `${f.config.issuer}/sdk-resource`),
      ).toMatchObject({ status: 200 });
      const persisted = JSON.stringify([...stored.values()]);
      for (const sensitive of [
        f.testUser.password,
        f.testUser.email,
        "wrong-password",
        "invalid-code",
        f.sentOTP[0]!.otp,
      ])
        expect(persisted).not.toContain(sensitive);
      expect(hardware).not.toHaveBeenCalled();
      expect(await sdk.retire(slot)).toMatchObject({
        remote: "confirmed",
        keys: "removed",
      });
      await sdk.accounts.forget(slot);
      expect(await sdk.accounts.list()).toEqual([]);
    } finally {
      vi.doUnmock("react-native");
      vi.unstubAllEnvs();
      vi.doUnmock("@react-native-async-storage/async-storage");
      vi.resetModules();
    }
  },
  30_000,
);

it.each(["challenge", "verify"])(
  "rechecks host authorization at admission %s with NODE_ENV=production",
  async (endpoint) => {
    vi.stubEnv("NODE_ENV", "production");
    try {
      const f = await fixture({ ios: true, development: true });
      await f.respond(await f.client.start("slot"));
      await f.client.logout("slot");
      f.controls.beforeSend = (url) => {
        if (url.endsWith(`/first-party/attestation/${endpoint}`))
          f.deployment.target = "production";
      };
      await expect(f.client.start("slot")).rejects.toBeInstanceOf(
        FirstPartyClientError,
      );
      expect(f.deployment.target).toBe("production");
      expect(
        await f.context.adapter.count({
          model: "firstPartyTokenFamily",
          where: [{ field: "status", value: "active" }],
        }),
      ).toBe(0);
    } finally {
      vi.unstubAllEnvs();
    }
  },
);
