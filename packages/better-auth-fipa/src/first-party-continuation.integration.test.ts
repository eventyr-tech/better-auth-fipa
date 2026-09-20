import {
  createHash,
  generateKeyPairSync,
  randomBytes,
  randomUUID,
  sign,
} from "node:crypto";
import type { GenericEndpointContext } from "@better-auth/core";
import { deriveDpopJkt } from "@better-auth/core/oauth2";
import {
  getOAuthProviderApi,
  oauthProvider,
  type OAuthOptions,
  type OAuthTokenResponse,
} from "@better-auth/oauth-provider";
import type { BetterAuthPlugin } from "better-auth";
import {
  APIError,
  createAuthEndpoint,
  createAuthMiddleware,
} from "better-auth/api";
import { emailOTP, twoFactor, jwt as jwtPlugin } from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import { describe, expect, it, vi } from "vitest";
import { z } from "zod";
import { createDeviceAttestation } from "./plugin.js";
import { decodeBase64Strict } from "./encoding/base64.js";
import type { DeviceAttestationProvider } from "./types.js";
import {
  requireNativeAccess,
  requireLegacyAccess,
  type NativeTokenOptions,
} from "./first-party/token-lifecycle.js";
import { createNativeFirstPartyPlugin } from "./first-party/plugin.js";
import type { NativeApplicationPolicy } from "./first-party/admission.js";
import type { NativeAdmissionBinding } from "./first-party/admission-binding.js";
import {
  retireLogicalCredential,
  type LogicalCredential,
} from "./first-party/authorization-store.js";
import type {
  NativeAttempt,
  NativeSession,
} from "./first-party/continuation.js";

const APP = "TEAM.continuation";
const KEY = Buffer.alloc(32, 73).toString("base64");
const VERIFIER = "v".repeat(43);
// Deterministic platform fixture only. DPoP, passwords, hooks, state and token writes are real.
const provider: DeviceAttestationProvider = {
  id: "continuation-test",
  maxEvidenceBytes: 1024,
  decodeKeyId: (value) =>
    decodeBase64Strict(value, { label: "key", exactBytes: 32, maxBytes: 32 }),
  verifyRegistration: () =>
    Promise.resolve({
      applicationId: APP,
      environment: "production",
      publicKey: "fixture-key",
      counter: 0,
      extensionsPresent: false,
    }),
  verifyAssertion: ({ credential, clientDataHash, evidence }) => {
    if (!Buffer.from(evidence).equals(Buffer.from(clientDataHash)))
      return Promise.reject(new Error("bad fixture evidence"));
    return Promise.resolve({
      counter: credential.counter + 1,
      extensionsPresent: false,
    });
  },
};
const BASE_APPLICATION: NativeApplicationPolicy = {
  clientId: "mobile",
  provider,
  applicationId: APP,
  environment: "production",
  scopes: ["offline_access"],
  resources: [],
};
const lifetimes = {
  sessionIdleSeconds: 600,
  sessionAbsoluteSeconds: 3600,
  familyLifetimeSeconds: 3600,
  evidenceMaxAgeSeconds: 300,
};
const BASE_OAUTH_OPTIONS = {
  loginPage: "/login",
  consentPage: "/consent",
  disableJwtPlugin: true,
  scopes: ["offline_access"],
} satisfies OAuthOptions;
interface Wire {
  auth_session: string;
  authorization_code?: string;
  error?: string;
  request_uri?: string;
  expires_in?: number;
  failure?: string;
  cancelled?: boolean;
  step?: { id: string; kind: string };
  binding?: NativeAdmissionBinding;
}

async function fixture(
  testWith: "sqlite" | "postgres",
  jwt = false,
  nativeOTP = false,
  secondarySessions = false,
  databaseVerification = true,
  legacyCompatibility = false,
) {
  const resource = "https://api.example.test/native";
  const application = { ...BASE_APPLICATION, resources: jwt ? [resource] : [] };
  const oauthOptions: OAuthOptions<string[]> = {
    ...BASE_OAUTH_OPTIONS,
    cachedTrustedClients: new Set(["mobile"]),
    disableJwtPlugin: !jwt,
    resources: application.resources,
  };
  const tokenOptions: NativeTokenOptions = {
    ...(legacyCompatibility
      ? {
          legacyCompatibility: {
            clients: [
              {
                clientId: application.clientId,
                provider: provider.id,
                applicationId: APP,
                environment: "production" as const,
                scopes: application.scopes,
                resources: application.resources,
                redirectUris: ["com.example.test:/auth/callback"],
                sessionLifetimeSeconds: 1800,
              },
            ],
          },
        }
      : {}),
    ...(nativeOTP
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
    applications: [application],
    lifetimes,
    accessTokenSeconds: 300,
    maximumAssuranceAgeSeconds: 3600,
  };
  const operations = new Map<
    string,
    (ctx: GenericEndpointContext) => Promise<unknown>
  >();
  const observed = {
    calls: 0,
    emails: [] as { email: string; otp: string }[],
    genericDeliveryCalls: 0,
    otpCalls: 0,
    holdDelivery: undefined as (() => Promise<void>) | undefined,
    otp: "",
    expireEvidence: false,
    limit: false,
    hold: undefined as (() => Promise<void>) | undefined,
  };
  const lowLevel = createDeviceAttestation({
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
  const oauthPlugin: BetterAuthPlugin = {
    ...oauth,
    endpoints: oauth.endpoints as unknown as NonNullable<
      BetterAuthPlugin["endpoints"]
    >,
  };
  const emailAndPassword: { enabled: boolean } = { enabled: true };
  const secondary = new Map<string, { value: string; expiresAt: number }>();
  const { auth, testUser } = await getTestInstance(
    {
      emailAndPassword,
      ...(secondarySessions
        ? {
            session: { storeSessionInDatabase: true },
            verification: { storeInDatabase: databaseVerification },
            secondaryStorage: {
              get: (key: string) => {
                const entry = secondary.get(key);
                return Promise.resolve(
                  entry && entry.expiresAt > Date.now() ? entry.value : null,
                );
              },
              getAndDelete: (key: string) => {
                const entry = secondary.get(key);
                secondary.delete(key);
                return Promise.resolve(
                  entry && entry.expiresAt > Date.now() ? entry.value : null,
                );
              },
              increment: (key: string, ttl: number) => {
                const entry = secondary.get(key);
                const live =
                  entry && entry.expiresAt > Date.now() ? entry : undefined;
                const count = live ? Number(live.value) + 1 : 1;
                secondary.set(key, {
                  value: String(count),
                  expiresAt: live?.expiresAt ?? Date.now() + ttl * 1000,
                });
                return Promise.resolve(count);
              },
              set: (key: string, value: string, ttl?: number) => {
                secondary.set(key, {
                  value,
                  expiresAt:
                    ttl === undefined ? Infinity : Date.now() + ttl * 1000,
                });
                return Promise.resolve();
              },
              delete: (key: string) => {
                secondary.delete(key);
                return Promise.resolve();
              },
            },
          }
        : {}),
      plugins: [
        lowLevel.serverPlugin,
        oauthPlugin,
        ...(nativeOTP
          ? [
              emailOTP({
                storeOTP: "hashed",
                allowedAttempts: 3,
                disableSignUp: true,
                sendVerificationOTP: async (value) => {
                  observed.genericDeliveryCalls++;
                  observed.emails.push(value);
                  await observed.holdDelivery?.();
                },
              }) as BetterAuthPlugin,
            ]
          : []),
        createNativeFirstPartyPlugin(tokenOptions),
        ...(jwt ? [jwtPlugin()] : []),
        twoFactor({
          otpOptions: {
            sendOTP: ({ otp }) => {
              observed.otp = otp;
              return Promise.resolve();
            },
          },
        }),
        {
          id: "continuation-test",
          hooks: {
            before: [
              {
                matcher: (ctx) =>
                  ctx.path === "/sign-in/email" ||
                  ctx.path === "/sign-in/email-otp",
                handler: createAuthMiddleware(async (ctx) => {
                  if (ctx.path === "/sign-in/email-otp") observed.otpCalls++;
                  else observed.calls++;
                  if (observed.limit)
                    throw new APIError(
                      "TOO_MANY_REQUESTS",
                      { message: "limited" },
                      { "retry-after": "15" },
                    );
                  await observed.hold?.();
                }),
              },
            ],
            after: [
              {
                matcher: (ctx) =>
                  ctx.path === "/sign-in/email" ||
                  ctx.path === "/sign-in/email-otp",
                handler: createAuthMiddleware(async (ctx) => {
                  if (observed.expireEvidence)
                    await ctx.context.adapter.updateMany({
                      model: "firstPartyAttempt",
                      where: [{ field: "status", value: "processing" }],
                      update: { evidenceExpiresAt: new Date(0) },
                    });
                }),
              },
            ],
          },
          endpoints: {
            nativeResource: createAuthEndpoint(
              "/test-only/resource",
              { method: "GET", requireHeaders: true },
              (ctx) =>
                requireNativeAccess(ctx, tokenOptions, {
                  headers: ctx.headers,
                  method: "GET",
                  url: `${ctx.context.baseURL}/test-only/resource`,
                  scopes: ["offline_access"],
                  ...(jwt ? { resource } : {}),
                }),
            ),
            continuationProbe: createAuthEndpoint(
              "/test-only/continuation",
              { method: "POST", body: z.object({ id: z.string() }) },
              async (ctx) => {
                const operation = operations.get(ctx.body.id);
                if (!operation) throw new Error("Missing operation");
                return operation(ctx);
              },
            ),
          },
        },
      ],
    },
    { testWith, transaction: true },
  );
  const context = await auth.$context;
  await context.adapter.deleteMany({ model: "session", where: [] });
  const run = async <T>(
    operation: (ctx: GenericEndpointContext) => Promise<T>,
  ): Promise<T> => {
    const id = randomUUID();
    operations.set(id, operation);
    try {
      return (await auth.api.continuationProbe({ body: { id } })) as T;
    } finally {
      operations.delete(id);
    }
  };
  const registered = await auth.api.createDeviceAttestationChallenge({
    body: {
      provider: provider.id,
      applicationId: APP,
      keyId: KEY,
      operation: "register",
      purpose: "credential-registration",
    },
  });
  await auth.api.verifyDeviceAttestation({
    body: {
      challengeToken: registered.challengeToken,
      keyId: KEY,
      evidence: Buffer.from("registration").toString("base64"),
    },
  });
  await context.adapter.create({
    model: "oauthClient",
    data: {
      clientId: "mobile",
      redirectUris: ["com.example.test:/auth/callback"],
      tokenEndpointAuthMethod: "none",
      grantTypes: ["authorization_code", "refresh_token"],
      scopes: ["offline_access"],
      disabled: false,
    },
  });
  // Match Eventyr's trusted-client configuration and warm the ordinary OAuth
  // cache before testing changes to the persisted registration.
  await run(async (ctx) =>
    getOAuthProviderApi(ctx, oauthOptions).getClient("mobile"),
  );
  if (jwt)
    await context.adapter.create({
      model: "oauthClientResource",
      data: { clientId: "mobile", resourceId: resource, createdAt: new Date() },
    });
  const key = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const binding: NativeAdmissionBinding = {
    profile: "device-attestation-fipa-v1",
    mode: "native",
    issuer: context.baseURL,
    clientId: "mobile",
    provider: provider.id,
    applicationId: APP,
    environment: "production",
    attemptId: randomBytes(32).toString("base64url"),
    codeChallenge: createHash("sha256").update(VERIFIER).digest("base64url"),
    codeChallengeMethod: "S256",
    dpopJkt: await deriveDpopJkt(key.publicKey.export({ format: "jwk" })),
    scopes: ["offline_access"],
    resources: application.resources,
  };
  const endpoint = `${context.baseURL}/first-party/authorization-challenge`;
  const proof = (
    url = endpoint,
    signingKey = key,
    accessToken?: string,
    method = accessToken ? "GET" : "POST",
  ) => {
    const encode = (value: unknown) =>
      Buffer.from(JSON.stringify(value)).toString("base64url");
    const unsigned = `${encode({ alg: "ES256", typ: "dpop+jwt", jwk: signingKey.publicKey.export({ format: "jwk" }) })}.${encode({ htm: method, htu: url, iat: Math.floor(Date.now() / 1000), jti: randomUUID(), ...(accessToken ? { ath: createHash("sha256").update(accessToken).digest("base64url") } : {}) })}`;
    return `${unsigned}.${sign("sha256", Buffer.from(unsigned), { key: signingKey.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url")}`;
  };
  const admissionRequest = (
    operation: "challenge" | "verify",
    body: unknown,
    contentType = "application/json",
  ) =>
    auth.handler(
      new Request(`${context.baseURL}/first-party/attestation/${operation}`, {
        method: "POST",
        headers: { "content-type": contentType },
        body: JSON.stringify(body),
      }),
    );
  const grant = async (requested = binding) => {
    const prepared = await admissionRequest("challenge", {
      binding: requested,
      keyId: KEY,
    });
    expect(prepared.status).toBe(200);
    const challenge = (await prepared.json()) as {
      challengeToken: string;
      clientData: string;
    };
    const verified = await admissionRequest("verify", {
      clientId: requested.clientId,
      challengeToken: challenge.challengeToken,
      keyId: KEY,
      evidence: createHash("sha256")
        .update(Buffer.from(challenge.clientData, "base64url"))
        .digest("base64"),
    });
    expect(verified.status).toBe(200);
    return (await verified.json()) as { grantToken: string; expiresAt: string };
  };
  const send = async (
    fields: Record<string, string>,
    dpop: string | null = proof(),
  ) => {
    const headers = new Headers({
      "content-type": "application/x-www-form-urlencoded",
    });
    if (dpop) headers.set("dpop", dpop);
    const response = await auth.handler(
      new Request(endpoint, {
        method: "POST",
        headers,
        body: new URLSearchParams({
          profile: binding.profile,
          client_id: "mobile",
          ...fields,
        }),
      }),
    );
    return { response, body: (await response.json()) as Wire };
  };
  const startFields = async (requested = binding, token?: string) => ({
    response_type: "code",
    ...(requested.resources[0] ? { resource: requested.resources[0] } : {}),
    scope: requested.scopes.join(" "),
    code_challenge: requested.codeChallenge,
    code_challenge_method: "S256",
    authorization_attempt: requested.attemptId,
    device_attestation: token ?? (await grant(requested)).grantToken,
  });
  const start = async (requested = binding) =>
    send(await startFields(requested));
  const step = (
    state: Wire,
    answer: object = {
      kind: "password",
      email: testUser.email,
      password: testUser.password,
    },
    dpop = proof(),
  ) =>
    send(
      {
        auth_session: state.auth_session,
        step_id: state.step!.id,
        response: JSON.stringify(answer),
      },
      dpop,
    );
  const tokenRequest = async (
    fields: Record<string, string>,
    dpop: string | null = proof(`${context.baseURL}/oauth2/token`),
  ) => {
    const headers = new Headers({
      "content-type": "application/x-www-form-urlencoded",
    });
    if (dpop) headers.set("dpop", dpop);
    const response = await auth.handler(
      new Request(`${context.baseURL}/oauth2/token`, {
        method: "POST",
        headers,
        body: new URLSearchParams({ client_id: "mobile", ...fields }),
      }),
    );
    return {
      response,
      body: (await response.json()) as OAuthTokenResponse & {
        error?: string;
        auth_session?: string;
        first_party_account?: { sub: string; credential_id: string };
      },
    };
  };
  const redeem = async (code: string) => {
    const result = await tokenRequest({
      grant_type: "authorization_code",
      code,
      code_verifier: VERIFIER,
    });
    if (result.response.status !== 200)
      throw new Error(`Token exchange failed: ${JSON.stringify(result.body)}`);
    expect(result.response.headers.get("cache-control")).toBe("no-store");
    expect(result.response.headers.get("set-cookie")).toBeNull();
    return result.body;
  };
  const access = async (
    token: string,
    dpop: string | null = proof(
      `${context.baseURL}/test-only/resource`,
      key,
      token,
    ),
    scheme = "DPoP",
  ) => {
    const headers = new Headers({ authorization: `${scheme} ${token}` });
    if (dpop) headers.set("dpop", dpop);
    return auth.handler(
      new Request(`${context.baseURL}/test-only/resource`, { headers }),
    );
  };
  const cookies = new Map<string, string>();
  const browser = async (path: string, body?: object) => {
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
  const browserHandoff = async () => {
    await context.adapter.update({
      model: "user",
      where: [{ field: "email", value: testUser.email }],
      update: { twoFactorEnabled: true },
    });
    const required = await step(
      (
        await start({
          ...binding,
          attemptId: randomBytes(32).toString("base64url"),
        })
      ).body,
    );
    expect(required.body.step?.kind).toBe("browser-required");
    const state = randomBytes(32).toString("base64url");
    const prepared = await step(required.body, {
      kind: "browser",
      redirectUri: "com.example.test:/auth/callback",
      state,
    });
    expect(prepared.body.error).toBe("redirect_to_web");
    const path = `/oauth2/authorize?${new URLSearchParams({ client_id: "mobile", request_uri: prepared.body.request_uri! })}`;
    return { prepared, state, path };
  };
  const browserLogin = async () => {
    const password = await browser("/sign-in/email", {
      email: testUser.email,
      password: testUser.password,
    });
    expect(password.status).toBe(200);
    expect(await password.json()).toMatchObject({ twoFactorRedirect: true });
    expect((await browser("/two-factor/send-otp", {})).status).toBe(200);
    expect(observed.otp).toMatch(/^\d{6}$/);
    expect(
      (await browser("/two-factor/verify-otp", { code: observed.otp })).status,
    ).toBe(200);
  };
  const attempts = () =>
    context.adapter.findMany<NativeAttempt>({ model: "firstPartyAttempt" });
  const sessions = () =>
    context.adapter.findMany<NativeSession>({ model: "firstPartySession" });
  const terminate = (
    action: "logout" | "retire",
    token: string,
    dpop: string | null = proof(
      `${context.baseURL}/first-party/${action}`,
      key,
      token,
      "POST",
    ),
    body: object = {},
  ) =>
    auth.handler(
      new Request(`${context.baseURL}/first-party/${action}`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `DPoP ${token}`,
          ...(dpop ? { dpop } : {}),
        },
        body: JSON.stringify(body),
      }),
    );
  return {
    auth,
    context,
    testUser,
    observed,
    binding,
    endpoint,
    key,
    proof,
    grant,
    admissionRequest,
    send,
    startFields,
    start,
    step,
    redeem,
    tokenRequest,
    tokenOptions,
    access,
    attempts,
    sessions,
    terminate,
    browser,
    cookies,
    browserHandoff,
    browserLogin,
    run,
  };
}

for (const database of ["sqlite", "postgres"] as const)
  describe.runIf(
    database === "sqlite"
      ? Number(process.versions.node.split(".")[0]) >= 22
      : process.env.TEST_POSTGRES === "true",
  )(`Native continuation HTTP (${database})`, () => {
    it("preserves native proof requirements and assurance when legacy compatibility is enabled", async () => {
      const f = await fixture(database, false, false, false, true, true);
      const start = await f.start();
      expect(start.response.status).toBe(403);
      const invalid = await f.step(
        start.body,
        {
          kind: "password",
          email: f.testUser.email,
          password: f.testUser.password,
        },
        "invalid-proof",
      );
      expect(invalid.response.status).toBe(400);
      expect(f.observed.calls).toBe(0);
      const completed = await f.step(start.body);
      expect(completed.response.status).toBe(200);
      const tokens = await f.redeem(completed.body.authorization_code!);
      expect((await f.access(tokens.access_token)).status).toBe(200);
      await expect(
        f.run((ctx) =>
          requireLegacyAccess(ctx, f.tokenOptions, {
            headers: new Headers({
              authorization: `DPoP ${tokens.access_token}`,
              dpop: f.proof(
                `${f.context.baseURL}/test-only/resource`,
                f.key,
                tokens.access_token,
              ),
            }),
            method: "GET",
            url: `${f.context.baseURL}/test-only/resource`,
            scopes: [],
          }),
        ),
      ).rejects.toMatchObject({ statusCode: 401 });
      const refreshed = await f.tokenRequest({
        grant_type: "refresh_token",
        refresh_token: tokens.refresh_token!,
      });
      expect(refreshed.response.status).toBe(200);
      expect(
        await f.context.adapter.count({ model: "firstPartyLegacySession" }),
      ).toBe(0);
    });

    it("offers enabled OTP, verifies the bound email and issues DPoP tokens with OTP assurance", async () => {
      const f = await fixture(database, false, true);
      const start = await f.start();
      expect(start.body.step).toMatchObject({
        kind: "authentication",
        methods: ["password", "email-otp"],
      });
      expect(f.observed.emails).toHaveLength(0);
      const delivered = await f.step(start.body, {
        kind: "email-otp-request",
        email: f.testUser.email,
      });
      expect(delivered.body.step?.kind).toBe("email-otp");
      expect(delivered.body.auth_session).not.toBe(start.body.auth_session);
      expect(f.observed.emails).toHaveLength(1);
      expect(delivered.response.headers.get("set-cookie")).toBeNull();
      const done = await f.step(delivered.body, {
        kind: "email-otp",
        otp: f.observed.emails[0]!.otp,
      });
      expect(done.response.status).toBe(200);
      expect((await f.attempts())[0]?.email).toBeNull();
      const token = await f.redeem(done.body.authorization_code!);
      expect(token.token_type).toBe("DPoP");
      expect((await f.access(token.access_token)).status).toBe(200);
      expect(
        await f.context.adapter.findOne({
          model: "firstPartyTokenFamily",
          where: [],
        }),
      ).toMatchObject({ assurance: { amr: ["otp"] } });
      expect(await f.context.adapter.count({ model: "session" })).toBe(0);
      const refreshed = await f.tokenRequest({
        grant_type: "refresh_token",
        refresh_token: token.refresh_token!,
      });
      expect(refreshed.response.status).toBe(200);
      expect(
        (await f.terminate("logout", refreshed.body.access_token)).status,
      ).toBe(200);
    });

    it("invalidates old password tokens and pending codes after email-ownership promotion while retaining keys", async () => {
      const f = await fixture(database, false, true);
      await f.context.adapter.updateMany({
        model: "user",
        where: [],
        update: { emailVerified: false },
      });
      const first = await f.step((await f.start()).body);
      const old = await f.redeem(first.body.authorization_code!);
      expect((await f.access(old.access_token)).status).toBe(200);
      const pending = await f.step(
        (
          await f.start({
            ...f.binding,
            attemptId: randomBytes(32).toString("base64url"),
          })
        ).body,
      );
      const beforeKeys = await f.context.adapter.findMany<{ id: string }>({
        model: "deviceAttestationCredential",
      });
      const sent = await f.step(
        (
          await f.start({
            ...f.binding,
            attemptId: randomBytes(32).toString("base64url"),
          })
        ).body,
        {
          kind: "email-otp-request",
          email: f.testUser.email,
        },
      );
      const verified = await f.step(sent.body, {
        kind: "email-otp",
        otp: f.observed.emails[0]!.otp,
      });
      expect(verified.response.status).toBe(200);
      expect(await f.context.adapter.count({ model: "account" })).toBe(0);
      expect((await f.access(old.access_token)).status).toBe(401);
      expect(
        (
          await f.tokenRequest({
            grant_type: "refresh_token",
            refresh_token: old.refresh_token!,
          })
        ).body.error,
      ).toBe("invalid_grant");
      expect(
        (
          await f.tokenRequest({
            grant_type: "authorization_code",
            code: pending.body.authorization_code!,
            code_verifier: VERIFIER,
          })
        ).body.error,
      ).toBe("invalid_grant");
      const current = await f.redeem(verified.body.authorization_code!);
      expect((await f.access(current.access_token)).status).toBe(200);
      expect(
        (
          await f.tokenRequest({
            grant_type: "refresh_token",
            refresh_token: current.refresh_token!,
          })
        ).response.status,
      ).toBe(200);
      expect(
        (
          await f.context.adapter.findMany<{ id: string }>({
            model: "deviceAttestationCredential",
          })
        ).map(({ id }) => id),
      ).toEqual(beforeKeys.map(({ id }) => id));
      expect(await f.context.adapter.count({ model: "session" })).toBe(0);
    });

    it("does not resurrect old authority when supported security updates restore the old value", async () => {
      const f = await fixture(database);
      const done = await f.step((await f.start()).body);
      const token = await f.redeem(done.body.authorization_code!);
      const user = await f.context.adapter.findOne<{
        id: string;
        emailVerified: boolean;
        firstPartySecurityEpoch?: string;
      }>({
        model: "user",
        where: [{ field: "email", value: f.testUser.email }],
      });
      await f.context.internalAdapter.updateUser(user!.id, {
        emailVerified: !user!.emailVerified,
      });
      await f.context.internalAdapter.updateUser(user!.id, {
        emailVerified: user!.emailVerified,
      });
      const restored = await f.context.adapter.findOne<{
        firstPartySecurityEpoch?: string;
      }>({ model: "user", where: [{ field: "id", value: user!.id }] });
      expect(restored!.firstPartySecurityEpoch).not.toBe(
        user!.firstPartySecurityEpoch,
      );
      expect((await f.access(token.access_token)).status).toBe(401);
      expect(
        (
          await f.tokenRequest({
            grant_type: "refresh_token",
            refresh_token: token.refresh_token!,
          })
        ).body.error,
      ).toBe("invalid_grant");
      const fresh = await f.redeem(
        (
          await f.step(
            (
              await f.start({
                ...f.binding,
                attemptId: randomBytes(32).toString("base64url"),
              })
            ).body,
          )
        ).body.authorization_code!,
      );
      expect((await f.access(fresh.access_token)).status).toBe(200);
      await f.context.internalAdapter.updateUser(user!.id, {
        name: "Changed display name",
      });
      expect((await f.access(fresh.access_token)).status).toBe(200);
    });

    it("invalidates old tokens on password updates even if the password hash is restored", async () => {
      const f = await fixture(database);
      const token = await f.redeem(
        (await f.step((await f.start()).body)).body.authorization_code!,
      );
      const account = await f.context.adapter.findOne<{
        id: string;
        password: string;
        firstPartySecurityEpoch?: string;
      }>({
        model: "account",
        where: [{ field: "providerId", value: "credential" }],
      });
      await f.context.internalAdapter.updateAccount(account!.id, {
        password: "replacement-hash",
      });
      await f.context.internalAdapter.updateAccount(account!.id, {
        password: account!.password,
      });
      const restored = await f.context.adapter.findOne<{
        firstPartySecurityEpoch?: string;
      }>({ model: "account", where: [{ field: "id", value: account!.id }] });
      expect(restored!.firstPartySecurityEpoch).not.toBe(
        account!.firstPartySecurityEpoch,
      );
      expect((await f.access(token.access_token)).status).toBe(401);
      expect(
        (
          await f.tokenRequest({
            grant_type: "refresh_token",
            refresh_token: token.refresh_token!,
          })
        ).body.error,
      ).toBe("invalid_grant");
      const fresh = await f.redeem(
        (
          await f.step(
            (
              await f.start({
                ...f.binding,
                attemptId: randomBytes(32).toString("base64url"),
              })
            ).body,
          )
        ).body.authorization_code!,
      );
      expect((await f.access(fresh.access_token)).status).toBe(200);
    });

    it("rejects access and refresh after deletion of the authenticated user", async () => {
      const f = await fixture(database);
      const token = await f.redeem(
        (await f.step((await f.start()).body)).body.authorization_code!,
      );
      await f.context.adapter.deleteMany({ model: "user", where: [] });
      expect((await f.access(token.access_token)).status).toBe(401);
      expect(
        (
          await f.tokenRequest({
            grant_type: "refresh_token",
            refresh_token: token.refresh_token!,
          })
        ).response.status,
      ).toBe(400);
    });

    it("rejects a password factor whose account security changes while its auth hook is running", async () => {
      const f = await fixture(database);
      const start = await f.start();
      let release!: () => void;
      let entered!: () => void;
      const arrived = new Promise<void>((resolve) => {
        entered = resolve;
      });
      const held = new Promise<void>((resolve) => {
        release = resolve;
      });
      f.observed.hold = () => {
        entered();
        return held;
      };
      const pending = f.step(start.body);
      await arrived;
      try {
        const user = await f.context.adapter.findOne<{
          id: string;
          emailVerified: boolean;
        }>({
          model: "user",
          where: [{ field: "email", value: f.testUser.email }],
        });
        await f.context.internalAdapter.updateUser(user!.id, {
          emailVerified: !user!.emailVerified,
        });
      } finally {
        release();
      }
      const result = await pending;
      expect(result.body.authorization_code).toBeUndefined();
      expect(result.body.step?.kind).toBe("browser-required");
      expect(
        await f.context.adapter.count({ model: "firstPartyAuthorization" }),
      ).toBe(0);
      expect(await f.context.adapter.count({ model: "session" })).toBe(0);
    });

    it("rejects a retained factor after security changes during evidence renewal", async () => {
      const f = await fixture(database);
      f.observed.expireEvidence = true;
      const stale = await f.step((await f.start()).body);
      expect(stale.body.step?.kind).toBe("attestation");
      const user = await f.context.adapter.findOne<{
        id: string;
        emailVerified: boolean;
      }>({
        model: "user",
        where: [{ field: "email", value: f.testUser.email }],
      });
      await f.context.internalAdapter.updateUser(user!.id, {
        emailVerified: !user!.emailVerified,
      });
      const renewed = await f.step(stale.body, {
        kind: "attestation",
        grantToken: (await f.grant()).grantToken,
      });
      expect(renewed.response.status).toBe(400);
      expect(renewed.body.authorization_code).toBeUndefined();
      expect(
        await f.context.adapter.count({ model: "firstPartyAuthorization" }),
      ).toBe(0);
    });

    it("uses explicitly routed OTP delivery through the public native challenge flow", async () => {
      const f = await fixture(database, false, true);
      f.tokenOptions.emailOTP!.delivery = (value) => {
        f.observed.emails.push(value);
        return Promise.resolve();
      };
      const start = await f.start();
      const sent = await f.step(start.body, {
        kind: "email-otp-request",
        email: f.testUser.email,
      });
      expect(sent.body.step?.kind).toBe("email-otp");
      expect(f.observed.genericDeliveryCalls).toBe(0);
      expect(f.observed.emails).toHaveLength(1);
      const completed = await f.step(sent.body, {
        kind: "email-otp",
        otp: f.observed.emails[0]!.otp,
      });
      expect(completed.response.status).toBe(200);
      const tokens = await f.redeem(completed.body.authorization_code!);
      expect((await f.access(tokens.access_token)).status).toBe(200);
      expect(await f.context.adapter.count({ model: "session" })).toBe(0);
    });

    it("rejects OTP when disabled and rejects missing proof or substituted steps before delivery", async () => {
      const disabled = await fixture(database);
      expect(
        (
          await disabled.step((await disabled.start()).body, {
            kind: "email-otp-request",
            email: disabled.testUser.email,
          })
        ).response.status,
      ).toBe(400);
      const f = await fixture(database, false, true);
      const start = await f.start();
      const answer = { kind: "email-otp-request", email: f.testUser.email };
      expect(
        (
          await f.send(
            {
              auth_session: start.body.auth_session,
              step_id: start.body.step!.id,
              response: JSON.stringify(answer),
            },
            null,
          )
        ).response.status,
      ).toBe(400);
      expect(
        (
          await f.step(
            {
              ...start.body,
              step: { kind: "authentication", id: "wrong-step" },
            },
            answer,
          )
        ).response.status,
      ).toBe(400);
      expect(f.observed.emails).toHaveLength(0);
      expect(
        await f.context.adapter.count({ model: "firstPartyEmailDelivery" }),
      ).toBe(0);
    });

    it("pins the recipient and requires explicit budgeted resend with replacement handles", async () => {
      const f = await fixture(database, false, true);
      const initial = (await f.start()).body;
      const delivered = (
        await f.step(initial, {
          kind: "email-otp-request",
          email: f.testUser.email,
        })
      ).body;
      expect(
        (
          await f.step(delivered, {
            kind: "email-otp",
            email: "different@example.test",
            otp: f.observed.emails[0]!.otp,
          })
        ).response.status,
      ).toBe(400);
      expect(
        (
          await f.step(delivered, {
            kind: "email-otp-request",
            email: "different@example.test",
          })
        ).response.status,
      ).toBe(400);
      const limited = await f.step(delivered, { kind: "email-otp-resend" });
      expect(limited.body).toMatchObject({
        step: { kind: "email-otp" },
        failure: "temporarily_unavailable",
      });
      expect(
        Number(limited.response.headers.get("retry-after")),
      ).toBeGreaterThan(0);
      expect(limited.body.auth_session).not.toBe(delivered.auth_session);
      expect(f.observed.emails).toHaveLength(1);
      await f.context.adapter.updateMany({
        model: "firstPartyEmailBudget",
        where: [],
        update: { nextRequestAt: new Date(0) },
      });
      const resent = await f.step(limited.body, { kind: "email-otp-resend" });
      expect(resent.body.step?.kind).toBe("email-otp");
      expect(f.observed.emails).toHaveLength(2);
      expect(
        (
          await f.step(resent.body, {
            kind: "email-otp",
            otp: f.observed.emails[1]!.otp,
          })
        ).response.status,
      ).toBe(200);
    });

    it("retains the OTP step after wrong codes and routes existing MFA to browser", async () => {
      const f = await fixture(database, false, true);
      const initial = (await f.start()).body;
      const sent = await f.step(initial, {
        kind: "email-otp-request",
        email: f.testUser.email,
      });
      const wrong = await f.step(sent.body, {
        kind: "email-otp",
        otp: "wrong-code",
      });
      expect(wrong.body).toMatchObject({
        step: { kind: "email-otp" },
        failure: "invalid_credentials",
      });
      await f.context.adapter.updateMany({
        model: "user",
        where: [],
        update: { twoFactorEnabled: true },
      });
      const mfa = await f.step(wrong.body, {
        kind: "email-otp",
        otp: f.observed.emails[0]!.otp,
      });
      expect(mfa.body.step?.kind).toBe("browser-required");
      expect(mfa.body.authorization_code).toBeUndefined();
      expect(await f.context.adapter.count({ model: "session" })).toBe(0);
    });

    it("renews expired evidence before OTP delivery and before consuming a code", async () => {
      const f = await fixture(database, false, true);
      const start = (await f.start()).body;
      await f.context.adapter.updateMany({
        model: "firstPartyAttempt",
        where: [],
        update: { evidenceExpiresAt: new Date(0) },
      });
      const stale = await f.step(start, {
        kind: "email-otp-request",
        email: f.testUser.email,
      });
      expect(stale.body.step?.kind).toBe("attestation");
      expect(f.observed.emails).toHaveLength(0);
      const renewed = await f.step(stale.body, {
        kind: "attestation",
        grantToken: (await f.grant(f.binding)).grantToken,
      });
      expect(renewed.body.step?.kind).toBe("authentication");
      const sent = await f.step(renewed.body, {
        kind: "email-otp-request",
        email: f.testUser.email,
      });
      await f.context.adapter.updateMany({
        model: "firstPartyAttempt",
        where: [],
        update: { evidenceExpiresAt: new Date(0) },
      });
      const staleOTP = await f.step(sent.body, {
        kind: "email-otp",
        otp: f.observed.emails[0]!.otp,
      });
      expect(staleOTP.body.step?.kind).toBe("attestation");
      expect(f.observed.otpCalls).toBe(0);
      const again = await f.step(staleOTP.body, {
        kind: "attestation",
        grantToken: (await f.grant(f.binding)).grantToken,
      });
      expect(again.body.step?.kind).toBe("email-otp");
      expect(
        (
          await f.step(again.body, {
            kind: "email-otp",
            otp: f.observed.emails[0]!.otp,
          })
        ).response.status,
      ).toBe(200);
    });

    it("retains a verified OTP factor while renewing evidence that expires during authentication", async () => {
      const f = await fixture(database, false, true);
      const sent = await f.step((await f.start()).body, {
        kind: "email-otp-request",
        email: f.testUser.email,
      });
      f.observed.expireEvidence = true;
      const verified = await f.step(sent.body, {
        kind: "email-otp",
        otp: f.observed.emails[0]!.otp,
      });
      expect(verified.body.step?.kind).toBe("attestation");
      const done = await f.step(verified.body, {
        kind: "attestation",
        grantToken: (await f.grant(f.binding)).grantToken,
      });
      expect(done.response.status).toBe(200);
      expect(f.observed.otpCalls).toBe(1);
      expect((await f.redeem(done.body.authorization_code!)).token_type).toBe(
        "DPoP",
      );
    });

    it.each(["cancel", "disable-client", "retire"] as const)(
      "checks disabled clients before sending and discards late delivery after %s",
      async (action) => {
        const f = await fixture(database, false, true);
        const start = (await f.start()).body;
        await f.context.adapter.updateMany({
          model: "oauthClient",
          where: [],
          update: { disabled: true },
        });
        expect(
          (
            await f.step(start, {
              kind: "email-otp-request",
              email: f.testUser.email,
            })
          ).response.status,
        ).toBe(400);
        expect(f.observed.emails).toHaveLength(0);
        await f.context.adapter.updateMany({
          model: "oauthClient",
          where: [],
          update: { disabled: false },
        });
        let release!: () => void;
        let started!: () => void;
        const waiting = new Promise<void>((resolve) => {
          started = resolve;
        });
        const held = new Promise<void>((resolve) => {
          release = resolve;
        });
        f.observed.holdDelivery = () => {
          started();
          return held;
        };
        const delivery = f.step(start, {
          kind: "email-otp-request",
          email: f.testUser.email,
        });
        try {
          await waiting;
          if (action === "cancel")
            expect(
              (await f.step(start, { kind: "cancel" })).body.cancelled,
            ).toBe(true);
          else if (action === "disable-client")
            await f.context.adapter.updateMany({
              model: "oauthClient",
              where: [],
              update: { disabled: true },
            });
          else {
            const credential =
              await f.context.adapter.findOne<LogicalCredential>({
                model: "firstPartyCredential",
                where: [],
              });
            await f.run((ctx) => retireLogicalCredential(ctx, credential!.id));
          }
        } finally {
          release();
        }
        expect((await delivery).response.status).toBe(400);
        expect(
          await f.context.adapter.count({ model: "firstPartyAuthorization" }),
        ).toBe(0);
      },
    );

    it("offers only OTP when password authentication is disabled", async () => {
      const f = await fixture(database, false, true);
      f.context.options.emailAndPassword.enabled = false;
      const start = await f.start();
      expect(start.body.step).toMatchObject({
        kind: "authentication",
        methods: ["email-otp"],
      });
      expect((await f.step(start.body)).response.status).toBe(409);
      expect(f.observed.calls).toBe(0);
      const sent = await f.step(start.body, {
        kind: "email-otp-request",
        email: f.testUser.email,
      });
      expect(
        (
          await f.step(sent.body, {
            kind: "email-otp",
            otp: f.observed.emails[0]!.otp,
          })
        ).response.status,
      ).toBe(200);
    });

    it("does not reveal a missing account or create it when signup is disabled", async () => {
      const f = await fixture(database, false, true);
      const sent = await f.step((await f.start()).body, {
        kind: "email-otp-request",
        email: "missing@example.test",
      });
      expect(sent.response.status).toBe(403);
      expect(sent.body.step?.kind).toBe("email-otp");
      expect(sent.body.failure).toBeUndefined();
      expect(f.observed.emails).toHaveLength(0);
      expect(
        await f.context.adapter.count({
          model: "user",
          where: [{ field: "email", value: "missing@example.test" }],
        }),
      ).toBe(0);
    });

    it("reuses a reserved delivery operation after a duplicate request without sending twice", async () => {
      const f = await fixture(database, false, true);
      const start = (await f.start()).body;
      let release!: () => void;
      let started!: () => void;
      const waiting = new Promise<void>((resolve) => {
        started = resolve;
      });
      const held = new Promise<void>((resolve) => {
        release = resolve;
      });
      f.observed.holdDelivery = () => {
        started();
        return held;
      };
      const answer = { kind: "email-otp-request", email: f.testUser.email };
      const original = f.step(start, answer);
      let duplicate: Awaited<ReturnType<typeof f.step>>;
      try {
        await waiting;
        duplicate = await f.step(start, answer);
        expect(duplicate.body).toMatchObject({
          step: { kind: "email-otp" },
          failure: "temporarily_unavailable",
        });
        expect(f.observed.emails).toHaveLength(1);
      } finally {
        release();
      }
      expect((await original).response.status).toBe(400);
      expect(
        (
          await f.step(duplicate.body, {
            kind: "email-otp",
            otp: f.observed.emails[0]!.otp,
          })
        ).response.status,
      ).toBe(200);
      expect(
        await f.context.adapter.count({ model: "firstPartyEmailDelivery" }),
      ).toBe(1);
    });

    it("preserves password sign-in when OTP is also offered", async () => {
      const f = await fixture(database, false, true);
      const result = await f.step((await f.start()).body);
      expect(result.response.status).toBe(200);
      expect(f.observed.emails).toHaveLength(0);
      expect((await f.redeem(result.body.authorization_code!)).token_type).toBe(
        "DPoP",
      );
    });

    it("authenticates a real password, issues a bound code and actual tokens, and retains the auth session", async () => {
      const f = await fixture(database);
      const first = await f.start();
      expect(first.response.status).toBe(403);
      expect(first.body).toMatchObject({
        error: "insufficient_authorization",
        step: { kind: "password" },
      });
      expect(f.observed.calls).toBe(0);
      const done = await f.step(first.body);
      expect(done.response.status).toBe(200);
      expect(done.body.authorization_code).toMatch(/^fp1_/);
      expect(done.body.auth_session).not.toBe(first.body.auth_session);
      for (const response of [first.response, done.response]) {
        expect(response.headers.get("cache-control")).toBe("no-store");
        expect(response.headers.get("set-cookie")).toBeNull();
      }
      expect(await f.context.adapter.count({ model: "session" })).toBe(0);
      const stored = JSON.stringify([
        ...(await f.sessions()),
        ...(await f.attempts()),
      ]);
      for (const secret of [
        first.body.auth_session,
        done.body.auth_session,
        f.testUser.password,
        done.body.authorization_code!,
      ])
        expect(stored).not.toContain(secret);
      const tokens = await f.redeem(done.body.authorization_code!);
      expect(tokens.token_type).toBe("DPoP");
      expect(
        await f.context.adapter.count({ model: "firstPartyTokenFamily" }),
      ).toBe(1);
      const renewed = {
        ...f.binding,
        attemptId: randomBytes(32).toString("base64url"),
        codeChallenge: "z".repeat(43),
      };
      const next = await f.send({
        ...(await f.startFields(renewed)),
        auth_session: tokens.auth_session!,
      });
      expect(next.response.status).toBe(403);
      expect(next.body.step?.kind).toBe("password");
      expect(await f.sessions()).toHaveLength(1);
      expect(await f.attempts()).toHaveLength(2);
    });

    it("rejects bad/missing proofs and substituted steps before password work", async () => {
      const f = await fixture(database);
      const fields = await f.startFields();
      expect(
        (await f.send(fields, null)).response.status,
      ).toBeGreaterThanOrEqual(400);
      expect(await f.sessions()).toEqual([]);
      const usedProof = f.proof();
      const start = await f.send(fields, usedProof);
      expect((await f.step(start.body, undefined, usedProof)).body.error).toBe(
        "invalid_dpop_proof",
      );
      const wrongKey = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
      for (const dpop of [
        f.proof(`${f.endpoint}/wrong`),
        f.proof(f.endpoint, wrongKey),
      ])
        expect(
          (await f.step(start.body, undefined, dpop)).response.status,
        ).toBeGreaterThanOrEqual(400);
      expect(
        (
          await f.step({
            ...start.body,
            step: { id: "wrong", kind: "password" },
          })
        ).body.error,
      ).toBe("invalid_request");
      expect(
        (
          await f.step(
            { ...start.body, step: { id: "wrong", kind: "password" } },
            { kind: "cancel" },
          )
        ).body.error,
      ).toBe("invalid_request");
      expect(f.observed.calls).toBe(0);
      expect((await f.step(start.body)).body.authorization_code).toBeDefined();
    });

    it("rotates handles and steps after a bad password and rejects old handles", async () => {
      const f = await fixture(database);
      const start = await f.start();
      const bad = await f.step(start.body, {
        kind: "password",
        email: f.testUser.email,
        password: "wrong",
      });
      expect(bad.body.failure).toBe("invalid_credentials");
      expect(bad.body.auth_session).not.toBe(start.body.auth_session);
      expect(bad.body.step!.id).not.toBe(start.body.step!.id);
      expect((await f.step(start.body)).body.error).toBe("invalid_session");
      expect((await f.step(bad.body)).body.authorization_code).toBeDefined();
    });

    it("requires new evidence before account work when admission freshness expires", async () => {
      const f = await fixture(database);
      const start = await f.start();
      await f.context.adapter.updateMany({
        model: "firstPartyAttempt",
        where: [],
        update: { evidenceExpiresAt: new Date(0) },
      });
      const stale = await f.step(start.body);
      expect(stale.body.step?.kind).toBe("attestation");
      expect(f.observed.calls).toBe(0);
      expect(stale.body.binding?.attemptId).toBe(f.binding.attemptId);
      const renewed = await f.step(stale.body, {
        kind: "attestation",
        grantToken: (await f.grant()).grantToken,
      });
      expect(renewed.body.step?.kind).toBe("password");
      expect(
        (await f.step(renewed.body)).body.authorization_code,
      ).toBeDefined();
    });

    it("preserves a verified password when evidence expires during authentication", async () => {
      const f = await fixture(database);
      const start = await f.start();
      f.observed.expireEvidence = true;
      const stale = await f.step(start.body);
      expect(stale.body.step?.kind).toBe("attestation");
      expect((await f.attempts())[0]!.userId).toBeTruthy();
      const renewed = await f.step(stale.body, {
        kind: "attestation",
        grantToken: (await f.grant()).grantToken,
      });
      expect(renewed.body.authorization_code).toBeDefined();
      expect(f.observed.calls).toBe(1);
    });

    it("serializes duplicate step submissions before running a password hook", async () => {
      const f = await fixture(database);
      const start = await f.start();
      let release!: () => void;
      let entered!: () => void;
      const arrived = new Promise<void>((resolve) => {
        entered = resolve;
      });
      const held = new Promise<void>((resolve) => {
        release = resolve;
      });
      f.observed.hold = () => {
        entered();
        return held;
      };
      const first = f.step(start.body);
      await arrived;
      const second = await f.step(start.body);
      expect(second.response.status).toBe(409);
      release();
      expect((await first).body.authorization_code).toBeDefined();
      expect(f.observed.calls).toBe(1);
    });

    it("cancels an in-flight password step and prevents its late result issuing a code", async () => {
      const f = await fixture(database);
      const start = await f.start();
      let release!: () => void;
      let entered!: () => void;
      const arrived = new Promise<void>((resolve) => {
        entered = resolve;
      });
      const held = new Promise<void>((resolve) => {
        release = resolve;
      });
      f.observed.hold = () => {
        entered();
        return held;
      };
      const pending = f.step(start.body);
      await arrived;
      const cancelled = await f.step(start.body, { kind: "cancel" });
      expect(cancelled.body.cancelled).toBe(true);
      release();
      expect((await pending).body.error).toBe("invalid_session");
      expect((await f.attempts())[0]!.status).toBe("cancelled");
      expect(
        await f.context.adapter.count({ model: "firstPartyAuthorization" }),
      ).toBe(0);
      expect(await f.context.adapter.count({ model: "session" })).toBe(0);
    });

    it("keeps a second start out of an active session and leaves its grant usable after cancellation", async () => {
      const f = await fixture(database);
      const start = await f.start();
      const fields = await f.startFields({
        ...f.binding,
        attemptId: randomBytes(32).toString("base64url"),
      });
      expect(
        (await f.send({ ...fields, auth_session: start.body.auth_session }))
          .response.status,
      ).toBe(409);
      const cancelled = await f.step(start.body, { kind: "cancel" });
      const next = await f.send({
        ...fields,
        auth_session: cancelled.body.auth_session,
      });
      expect(next.body.step?.kind).toBe("password");
      expect(await f.sessions()).toHaveLength(1);
    });

    it("retirement cancels a running factor and revokes its durable continuation", async () => {
      const f = await fixture(database);
      const start = await f.start();
      let release!: () => void;
      let entered!: () => void;
      const arrived = new Promise<void>((resolve) => {
        entered = resolve;
      });
      const held = new Promise<void>((resolve) => {
        release = resolve;
      });
      f.observed.hold = () => {
        entered();
        return held;
      };
      const pending = f.step(start.body);
      await arrived;
      const [credential] = await f.context.adapter.findMany<LogicalCredential>({
        model: "firstPartyCredential",
      });
      await f.run((ctx) => retireLogicalCredential(ctx, credential!.id));
      release();
      expect((await pending).body.error).toBe("invalid_session");
      expect((await f.attempts())[0]!.status).toBe("cancelled");
      expect((await f.sessions())[0]!.status).toBe("revoked");
      expect(
        await f.context.adapter.count({ model: "firstPartyAuthorization" }),
      ).toBe(0);
      expect(await f.context.adapter.count({ model: "session" })).toBe(0);
    });

    it("requires browser continuation for MFA without completing authorization", async () => {
      const f = await fixture(database);
      await f.context.adapter.update({
        model: "user",
        where: [{ field: "email", value: f.testUser.email }],
        update: { twoFactorEnabled: true },
      });
      const start = await f.start();
      const result = await f.step(start.body);
      expect(result.body.error).toBe("insufficient_authorization");
      expect(result.body.step?.kind).toBe("browser-required");
      expect((await f.attempts())[0]!.status).toBe("browser");
      expect(
        await f.context.adapter.count({ model: "firstPartyAuthorization" }),
      ).toBe(0);
    });

    it("propagates rate limiting with a replacement handle and no account session", async () => {
      const f = await fixture(database);
      const start = await f.start();
      f.observed.limit = true;
      const result = await f.step(start.body);
      expect(result.body.failure).toBe("temporarily_unavailable");
      expect(result.response.headers.get("retry-after")).toBe("15");
      expect(result.body.auth_session).not.toBe(start.body.auth_session);
      expect(await f.context.adapter.count({ model: "session" })).toBe(0);
    });

    it("rejects expired sessions, expired attempts and retired credentials before password work", async () => {
      for (const target of ["session", "attempt", "credential"]) {
        const f = await fixture(database);
        const start = await f.start();
        if (target === "credential") {
          const [credential] =
            await f.context.adapter.findMany<LogicalCredential>({
              model: "firstPartyCredential",
            });
          await f.run((ctx) => retireLogicalCredential(ctx, credential!.id));
        } else
          await f.context.adapter.updateMany({
            model:
              target === "session" ? "firstPartySession" : "firstPartyAttempt",
            where: [],
            update: { expiresAt: new Date(0) },
          });
        expect((await f.step(start.body)).body.error).toBe("invalid_session");
        expect(f.observed.calls).toBe(0);
      }
    });

    it("rejects JSON and conflicting or malformed new-protocol fields", async () => {
      const f = await fixture(database);
      const json = await f.auth.handler(
        new Request(f.endpoint, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: "{}",
        }),
      );
      expect(json.status).toBe(415);
      const fields = await f.startFields();
      for (const extra of [
        { dpop_jkt: "wrong" },
        { acr_values: "unimplemented" },
        { step_id: "ambiguous" },
      ])
        expect((await f.send({ ...fields, ...extra })).response.status).toBe(
          400,
        );
      expect(await f.sessions()).toEqual([]);
      const start = await f.send(fields);
      expect(
        (
          await f.send({
            auth_session: start.body.auth_session,
            step_id: start.body.step!.id,
            response: "not-json",
          })
        ).body.error,
      ).toBe("invalid_request");
      expect(f.observed.calls).toBe(0);
    });
    it.each([false, true])(
      "enforces access proofs and rotates refresh tokens for JWT=%s",
      async (jwt) => {
        const f = await fixture(database, jwt);
        const start = await f.start();
        const authorized = await f.step(start.body);
        const tokens = await f.redeem(authorized.body.authorization_code!);
        expect(tokens.auth_session).toBeTruthy();
        expect(tokens.auth_session).not.toBe(authorized.body.auth_session);
        const bound = await f.context.adapter.findOne<{
          id: string;
          userId: string;
        }>({
          model: "firstPartyCredential",
          where: [],
        });
        expect(tokens.first_party_account).toEqual({
          sub: bound!.userId,
          credential_id: bound!.id,
        });
        if (jwt) expect(tokens.access_token.split(".")).toHaveLength(3);
        expect((await f.access(tokens.access_token)).status).toBe(200);
        expect((await f.access(tokens.access_token, null)).status).toBe(401);
        const missingAth = f.proof(
          `${f.context.baseURL}/test-only/resource`,
          f.key,
          undefined,
          "GET",
        );
        expect((await f.access(tokens.access_token, missingAth)).status).toBe(
          401,
        );
        expect(
          (await f.access(tokens.access_token, undefined, "Bearer")).status,
        ).toBe(401);
        const wrongAth = f.proof(
          `${f.context.baseURL}/test-only/resource`,
          f.key,
          "different-token",
        );
        expect((await f.access(tokens.access_token, wrongAth)).status).toBe(
          401,
        );
        const proof = f.proof(
          `${f.context.baseURL}/test-only/resource`,
          f.key,
          tokens.access_token,
        );
        expect((await f.access(tokens.access_token, proof)).status).toBe(200);
        expect((await f.access(tokens.access_token, proof)).status).toBe(401);
        const refreshed = await f.tokenRequest({
          grant_type: "refresh_token",
          refresh_token: tokens.refresh_token!,
        });
        expect(refreshed.response.status).toBe(200);
        expect(refreshed.body.refresh_token).not.toBe(tokens.refresh_token);
        expect(refreshed.body.auth_session).not.toBe(tokens.auth_session);
        expect(refreshed.body.first_party_account).toEqual(
          tokens.first_party_account,
        );
        expect((await f.access(refreshed.body.access_token)).status).toBe(200);
        const stored = JSON.stringify(
          await f.context.adapter.findMany({ model: "firstPartyRefresh" }),
        );
        expect(stored).not.toContain(tokens.refresh_token!);
        expect(stored).not.toContain(refreshed.body.refresh_token!);
      },
    );

    it("blocks ordinary authorization and unsupported grants for the configured mobile client", async () => {
      const f = await fixture(database);
      expect(
        (
          await f.browser("/sign-in/email", {
            email: f.testUser.email,
            password: f.testUser.password,
          })
        ).status,
      ).toBe(200);
      const response = await f.browser(
        `/oauth2/authorize?${new URLSearchParams({
          client_id: "mobile",
          response_type: "code",
          redirect_uri: "com.example.test:/auth/callback",
          scope: "offline_access",
          state: randomUUID(),
          code_challenge: f.binding.codeChallenge,
          code_challenge_method: "S256",
        })}`,
      );
      expect(response.status).toBe(400);
      expect(await response.json()).toMatchObject({ error: "invalid_request" });
      expect(response.headers.get("location")).toBeNull();
      const unsupported = await f.tokenRequest({
        grant_type: "client_credentials",
      });
      expect(unsupported.response.status).toBe(400);
      expect(unsupported.body.access_token).toBeUndefined();
      expect(
        await f.context.adapter.count({ model: "firstPartyTokenFamily" }),
      ).toBe(0);
      expect(await f.context.adapter.count({ model: "oauthAccessToken" })).toBe(
        0,
      );
    });

    it("rejects native code client substitution without consuming the valid code", async () => {
      const f = await fixture(database);
      const code = (await f.step((await f.start()).body)).body
        .authorization_code!;
      const substituted = await f.tokenRequest({
        grant_type: "authorization_code",
        code,
        code_verifier: VERIFIER,
        client_id: "other-client",
      });
      expect(substituted.response.status).toBe(400);
      expect(substituted.body).toMatchObject({ error: "invalid_grant" });
      expect(substituted.body.access_token).toBeUndefined();
      const tokens = await f.redeem(code);
      expect((await f.access(tokens.access_token)).status).toBe(200);
    });

    it("rejects a valid ordinary bearer token at the native resource without a family", async () => {
      const f = await fixture(database);
      // Mint through the public provider API without library admission, then
      // verify it is active before exercising the real HTTP resource guard.
      const tokens = await f.run(async (ctx) => {
        const issuer = getOAuthProviderApi(
          ctx,
          f.tokenOptions.oauth,
          "authorization_code",
        );
        const client = await issuer.getClient("mobile");
        const user = await ctx.context.adapter.findOne<{ id: string }>({
          model: "user",
          where: [{ field: "email", value: f.testUser.email }],
        });
        const subject = await ctx.context.internalAdapter.findUserById(
          user!.id,
        );
        return issuer.issueTokens({
          client: client!,
          user: subject!,
          scopes: ["offline_access"],
        });
      });
      await expect(
        f.run(async (ctx) =>
          getOAuthProviderApi(
            ctx,
            f.tokenOptions.oauth,
          ).requireActiveAccessToken(tokens.access_token, "mobile"),
        ),
      ).resolves.toMatchObject({ active: true });
      expect(await f.context.adapter.count({ model: "firstPartyAccess" })).toBe(
        0,
      );
      expect((await f.access(tokens.access_token, null, "Bearer")).status).toBe(
        401,
      );
      expect((await f.access(tokens.access_token)).status).toBe(401);
    });

    it("rejects invalid refresh proofs without consuming or revoking the family", async () => {
      const f = await fixture(database);
      const tokens = await f.redeem(
        (await f.step((await f.start()).body)).body.authorization_code!,
      );
      const request = {
        grant_type: "refresh_token",
        refresh_token: tokens.refresh_token!,
      };
      const wrongKey = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
      for (const proof of [
        null,
        f.proof(`${f.context.baseURL}/oauth2/token`, wrongKey),
      ]) {
        expect((await f.tokenRequest(request, proof)).body.error).toBe(
          "invalid_dpop_proof",
        );
      }
      expect((await f.access(tokens.access_token)).status).toBe(200);
      expect((await f.tokenRequest(request)).response.status).toBe(200);
    });

    it("does not dispatch indexed native refresh tokens through alternative client authentication", async () => {
      const f = await fixture(database);
      const tokens = await f.redeem(
        (await f.step((await f.start()).body)).body.authorization_code!,
      );
      for (const variant of [
        { fields: {}, basic: false },
        { fields: { client_id: "other-client" }, basic: false },
        { fields: {}, basic: true },
        { fields: { client_id: "other-client" }, basic: true },
        { fields: { client_id: "mobile" }, basic: true },
      ]) {
        const response = await f.auth.handler(
          new Request(`${f.context.baseURL}/oauth2/token`, {
            method: "POST",
            headers: {
              "content-type": "application/x-www-form-urlencoded",
              ...(variant.basic
                ? {
                    authorization: `Basic ${Buffer.from("mobile:").toString("base64")}`,
                  }
                : {}),
              dpop: f.proof(`${f.context.baseURL}/oauth2/token`),
            },
            body: new URLSearchParams({
              grant_type: "refresh_token",
              refresh_token: tokens.refresh_token!,
              ...variant.fields,
            }),
          }),
        );
        const rejection = (await response.json()) as {
          error: string;
          access_token?: string;
        };
        expect([400, 401]).toContain(response.status);
        expect(["invalid_grant", "invalid_client"]).toContain(rejection.error);
        expect(rejection.access_token).toBeUndefined();
      }
      expect(
        (
          await f.tokenRequest({
            grant_type: "refresh_token",
            refresh_token: tokens.refresh_token!,
          })
        ).response.status,
      ).toBe(200);
    });

    it("allows issuance crossing a clock second while enforcing disabled server grants", async () => {
      const f = await fixture(database);
      const authorized = await f.step((await f.start()).body);
      const request = {
        grant_type: "authorization_code",
        code: authorized.body.authorization_code!,
        code_verifier: VERIFIER,
      };
      f.tokenOptions.oauth.grantTypes = [];
      expect((await f.tokenRequest(request)).body.error).toBe("invalid_grant");
      f.tokenOptions.oauth.grantTypes = ["authorization_code", "refresh_token"];
      const before = Date.now();
      const clock = vi.spyOn(Date, "now").mockReturnValue(before);
      const transaction = f.context.adapter.transaction;
      f.context.adapter.transaction = (operation) =>
        transaction(async (adapter) => {
          const find = adapter.findOne;
          adapter.findOne = async <T>(
            input: Parameters<typeof find>[0],
          ): Promise<T | null> => {
            const row = await find<T>(input);
            if (input.model === "oauthClient")
              clock.mockReturnValue(before + 2000);
            return row;
          };
          return operation(adapter);
        });
      let issued: Awaited<ReturnType<typeof f.tokenRequest>>;
      try {
        issued = await f.tokenRequest(request);
        expect(issued.response.status).toBe(200);
        expect(issued.body.expires_at * 1000).toBeLessThanOrEqual(
          before + 302_000,
        );
        expect(issued.body.expires_at * 1000).toBeGreaterThan(before + 300_000);
      } finally {
        clock.mockRestore();
        f.context.adapter.transaction = transaction;
      }
      f.tokenOptions.oauth.grantTypes = ["authorization_code"];
      expect(
        (
          await f.tokenRequest({
            grant_type: "refresh_token",
            refresh_token: issued!.body.refresh_token!,
          })
        ).body.error,
      ).toBe("invalid_grant");
    });

    it("revokes only the replayed family and rejects its access and refresh tokens", async () => {
      const f = await fixture(database);
      const first = await f.redeem(
        (await f.step((await f.start()).body)).body.authorization_code!,
      );
      const rotated = (
        await f.tokenRequest({
          grant_type: "refresh_token",
          refresh_token: first.refresh_token!,
        })
      ).body;
      const secondStart = await f.start({
        ...f.binding,
        attemptId: randomBytes(32).toString("base64url"),
      });
      const second = await f.redeem(
        (await f.step(secondStart.body)).body.authorization_code!,
      );
      expect(
        (
          await f.tokenRequest({
            grant_type: "refresh_token",
            refresh_token: first.refresh_token!,
          })
        ).body.error,
      ).toBe("invalid_grant");
      expect((await f.access(rotated.access_token)).status).toBe(401);
      expect(
        (
          await f.tokenRequest({
            grant_type: "refresh_token",
            refresh_token: rotated.refresh_token!,
          })
        ).body.error,
      ).toBe("invalid_grant");
      expect((await f.access(second.access_token)).status).toBe(200);
      expect(
        await f.context.adapter.count({
          model: "firstPartyTokenFamily",
          where: [{ field: "status", value: "active" }],
        }),
      ).toBe(1);
    });

    it("serializes concurrent refresh and commits reuse revocation", async () => {
      const f = await fixture(database);
      const tokens = await f.redeem(
        (await f.step((await f.start()).body)).body.authorization_code!,
      );
      const request = {
        grant_type: "refresh_token",
        refresh_token: tokens.refresh_token!,
      };
      const results = await Promise.all([
        f.tokenRequest(request),
        f.tokenRequest(request),
      ]);
      expect(
        results.filter((result) => result.response.status === 200),
      ).toHaveLength(1);
      expect(
        results.filter((result) => result.response.status === 400),
      ).toHaveLength(1);
      expect(
        await f.context.adapter.count({
          model: "firstPartyTokenFamily",
          where: [{ field: "status", value: "active" }],
        }),
      ).toBe(0);
      expect(
        await f.context.adapter.count({ model: "oauthRefreshToken" }),
      ).toBe(0);
      expect(
        (
          await f.access(
            results.find((result) => result.response.status === 200)!.body
              .access_token,
          )
        ).status,
      ).toBe(401);
    });

    it("retirement racing refresh leaves no usable token, including JWTs", async () => {
      const f = await fixture(database, true);
      const tokens = await f.redeem(
        (await f.step((await f.start()).body)).body.authorization_code!,
      );
      const [credential] = await f.context.adapter.findMany<LogicalCredential>({
        model: "firstPartyCredential",
      });
      await Promise.all([
        f.tokenRequest({
          grant_type: "refresh_token",
          refresh_token: tokens.refresh_token!,
        }),
        f.run((ctx) => retireLogicalCredential(ctx, credential!.id)),
      ]);
      expect((await f.access(tokens.access_token)).status).toBe(401);
      expect(
        await f.context.adapter.count({ model: "oauthRefreshToken" }),
      ).toBe(0);
      expect(
        await f.context.adapter.count({
          model: "firstPartyTokenFamily",
          where: [{ field: "status", value: "active" }],
        }),
      ).toBe(0);
    });

    it("rolls back minted tokens, ownership and handle rotation if token indexing fails", async () => {
      const f = await fixture(database);
      const authorized = await f.step((await f.start()).body);
      const before = await f.sessions();
      const transaction = f.context.adapter.transaction;
      f.context.adapter.transaction = (operation) =>
        transaction(async (adapter) => {
          const create = adapter.create;
          adapter.create = async (input) => {
            if (input.model === "firstPartyAccess")
              throw new Error("injected-token-index-failure");
            return create(input);
          };
          return operation(adapter);
        });
      const request = {
        grant_type: "authorization_code",
        code: authorized.body.authorization_code!,
        code_verifier: VERIFIER,
      };
      expect((await f.tokenRequest(request)).response.status).toBe(500);
      expect(await f.sessions()).toEqual(before);
      for (const model of [
        "firstPartyTokenFamily",
        "firstPartyAccess",
        "firstPartyRefresh",
        "oauthAccessToken",
        "oauthRefreshToken",
      ])
        expect(await f.context.adapter.count({ model })).toBe(0);
      expect(
        await f.context.adapter.findMany({ model: "firstPartyCredential" }),
      ).toMatchObject([{ userId: null }]);
      f.context.adapter.transaction = transaction;
      expect((await f.tokenRequest(request)).response.status).toBe(200);
    });

    it("enforces current client policy and rejects expansion of scopes and resources", async () => {
      const f = await fixture(database);
      const authorized = await f.step((await f.start()).body);
      await f.context.adapter.update({
        model: "oauthClient",
        where: [{ field: "clientId", value: "mobile" }],
        update: { disabled: true },
      });
      const request = {
        grant_type: "authorization_code",
        code: authorized.body.authorization_code!,
        code_verifier: VERIFIER,
      };
      expect((await f.tokenRequest(request)).response.status).toBe(400);
      await f.context.adapter.update({
        model: "oauthClient",
        where: [{ field: "clientId", value: "mobile" }],
        update: { disabled: false },
      });
      const tokens = (await f.tokenRequest(request)).body;
      for (const extra of [
        { scope: "offline_access admin" },
        { resource: "https://other.example" },
      ])
        expect(
          (
            await f.tokenRequest({
              grant_type: "refresh_token",
              refresh_token: tokens.refresh_token!,
              ...extra,
            })
          ).body.error,
        ).toBe("invalid_grant");
      expect((await f.access(tokens.access_token)).status).toBe(200);
    });

    it.each([false, true])(
      "rejects access and refresh after disabling a cached client (JWT=%s)",
      async (jwt) => {
        const f = await fixture(database, jwt);
        const tokens = await f.redeem(
          (await f.step((await f.start()).body)).body.authorization_code!,
        );
        expect((await f.access(tokens.access_token)).status).toBe(200);
        const refresh = {
          grant_type: "refresh_token",
          refresh_token: tokens.refresh_token!,
        };
        await f.context.adapter.update({
          model: "oauthClient",
          where: [{ field: "clientId", value: "mobile" }],
          update: { disabled: true },
        });
        expect((await f.access(tokens.access_token)).status).toBe(401);
        expect((await f.tokenRequest(refresh)).response.status).toBe(400);
        await f.context.adapter.update({
          model: "oauthClient",
          where: [{ field: "clientId", value: "mobile" }],
          update: { disabled: false },
        });
        // Policy rejection rolls back refresh consumption and handle rotation.
        expect((await f.tokenRequest(refresh)).response.status).toBe(200);
      },
    );

    it("rejects expired family and assurance even while the provider token remains valid", async () => {
      for (const expired of ["family", "assurance"]) {
        const f = await fixture(database);
        const tokens = await f.redeem(
          (await f.step((await f.start()).body)).body.authorization_code!,
        );
        const [family] = await f.context.adapter.findMany<{
          id: string;
          assurance: Record<string, unknown>;
        }>({ model: "firstPartyTokenFamily" });
        await f.context.adapter.update({
          model: "firstPartyTokenFamily",
          where: [{ field: "id", value: family!.id }],
          update:
            expired === "family"
              ? { expiresAt: new Date(0) }
              : {
                  assurance: {
                    ...family!.assurance,
                    evidenceVerifiedAt: new Date(0).toISOString(),
                  },
                },
        });
        expect((await f.access(tokens.access_token)).status).toBe(401);
        expect(
          (
            await f.tokenRequest({
              grant_type: "refresh_token",
              refresh_token: tokens.refresh_token!,
            })
          ).body.error,
        ).toBe("invalid_grant");
      }
    });

    it("rejects a provider retirement or reassigned application policy on existing tokens", async () => {
      for (const change of ["provider", "policy"]) {
        const f = await fixture(database);
        const tokens = await f.redeem(
          (await f.step((await f.start()).body)).body.authorization_code!,
        );
        if (change === "provider")
          await f.context.adapter.updateMany({
            model: "deviceAttestationCredential",
            where: [],
            update: { status: "revoked" },
          });
        else
          f.tokenOptions.applications = [
            { ...f.tokenOptions.applications[0]!, applicationId: "TEAM.other" },
          ];
        expect((await f.access(tokens.access_token)).status).toBe(401);
        expect(
          (
            await f.tokenRequest({
              grant_type: "refresh_token",
              refresh_token: tokens.refresh_token!,
            })
          ).body.error,
        ).toBe("invalid_grant");
      }
    });

    it("preserves ISO-looking binding strings through storage and evidence renewal", async () => {
      const f = await fixture(database);
      const binding = { ...f.binding, nonce: "2026-01-01T00:00:00Z" };
      const fields = {
        ...(await f.startFields(binding)),
        nonce: binding.nonce,
      };
      const first = await f.send(fields);
      expect((await f.attempts())[0]!.binding.nonce).toBe(binding.nonce);
      await f.context.adapter.updateMany({
        model: "firstPartyAttempt",
        where: [],
        update: { evidenceExpiresAt: new Date(0) },
      });
      const stale = await f.step(first.body);
      const renewed = await f.step(stale.body, {
        kind: "attestation",
        grantToken: (await f.grant(binding)).grantToken,
      });
      expect(
        (await f.step(renewed.body)).body.authorization_code,
      ).toBeDefined();
    });

    it("completes browser MFA through a one-use handoff with exact callback, PKCE and DPoP binding", async () => {
      const f = await fixture(database);
      const { prepared, state, path } = await f.browserHandoff();
      const opened = await f.browser(path);
      expect(opened.status).toBe(302);
      const login = new URL(opened.headers.get("location")!);
      expect(login.pathname).toBe("/login");
      expect(login.searchParams.get("callbackURL")).toBe(
        `${f.context.baseURL}/first-party/browser/complete`,
      );
      expect(opened.headers.get("referrer-policy")).toBe("no-referrer");
      expect((await f.browser(path)).status).toBe(400);
      expect((await f.browser("/first-party/browser/complete")).status).toBe(
        401,
      );
      await f.browserLogin();
      const completed = await f.browser("/first-party/browser/complete");
      expect(completed.status).toBe(302);
      const callback = new URL(completed.headers.get("location")!);
      expect(`${callback.protocol}${callback.pathname}`).toBe(
        "com.example.test:/auth/callback",
      );
      expect(callback.searchParams.get("state")).toBe(state);
      expect(callback.searchParams.get("iss")).toBe(f.context.baseURL);
      expect((await f.browser("/first-party/browser/complete")).status).toBe(
        400,
      );
      const code = callback.searchParams.get("code")!;
      const exchange = {
        grant_type: "authorization_code",
        code,
        code_verifier: VERIFIER,
      };
      expect((await f.tokenRequest(exchange)).body.error).toBe("invalid_grant");
      expect(
        (
          await f.tokenRequest({
            ...exchange,
            redirect_uri: "com.example.test:/other",
          })
        ).body.error,
      ).toBe("invalid_grant");
      expect(
        (
          await f.tokenRequest(
            { ...exchange, redirect_uri: "com.example.test:/auth/callback" },
            null,
          )
        ).response.status,
      ).toBe(400);
      const tokens = await f.tokenRequest({
        ...exchange,
        redirect_uri: "com.example.test:/auth/callback",
      });
      expect(tokens.response.status).toBe(200);
      expect(tokens.body.token_type).toBe("DPoP");
      expect(tokens.body.auth_session).not.toBe(prepared.body.auth_session);
      expect((await f.access(tokens.body.access_token)).status).toBe(200);
      const [family] = await f.context.adapter.findMany<{
        assurance: { amr: string[] };
      }>({ model: "firstPartyTokenFamily" });
      expect(family!.assurance.amr).toEqual([
        "urn:better-auth:browser-session",
      ]);
    });

    it.each([false, true])(
      "rejects browser completion after account security changes following authentication, secondary sessions: %s",
      async (secondarySessions) => {
        const f = await fixture(database, false, false, secondarySessions);
        const { path } = await f.browserHandoff();
        expect((await f.browser(path)).status).toBe(302);
        await f.browserLogin();
        const view = (await (await f.browser("/get-session")).json()) as {
          session: {
            token: string;
            firstPartyBrowserHandoffId?: string;
            firstPartyBrowserSecurityHash?: string;
          };
        };
        expect(view.session.firstPartyBrowserHandoffId).toBeUndefined();
        expect(view.session.firstPartyBrowserSecurityHash).toBeUndefined();
        const persisted = await f.context.adapter.findOne<{
          firstPartyBrowserSecurityHash: string;
        }>({
          model: "session",
          where: [{ field: "token", value: view.session.token }],
        });
        expect(persisted!.firstPartyBrowserSecurityHash).toMatch(
          /^[a-f0-9]{64}$/,
        );

        const user = await f.context.adapter.findOne<{
          id: string;
          emailVerified: boolean;
        }>({
          model: "user",
          where: [{ field: "email", value: f.testUser.email }],
        });
        await f.context.internalAdapter.updateUser(user!.id, {
          emailVerified: !user!.emailVerified,
        });
        await f.context.internalAdapter.updateSession(view.session.token, {
          expiresAt: new Date(Date.now() + 300_000),
        });
        const refreshed = await f.context.adapter.findOne<{
          firstPartyBrowserSecurityHash: string;
        }>({
          model: "session",
          where: [{ field: "token", value: view.session.token }],
        });
        expect(refreshed!.firstPartyBrowserSecurityHash).toBe(
          persisted!.firstPartyBrowserSecurityHash,
        );
        const completed = await f.browser("/first-party/browser/complete");
        expect(completed.status).toBe(401);
        expect(completed.headers.get("location")).toBeNull();
        expect(
          await f.context.adapter.count({ model: "firstPartyAuthorization" }),
        ).toBe(0);
        await f.browserLogin();
        expect((await f.browser("/first-party/browser/complete")).status).toBe(
          302,
        );
      },
    );

    it("requires SQL-backed verification when secondary storage is configured", async () => {
      await expect(
        fixture(database, false, false, true, false),
      ).rejects.toThrow("verification.storeInDatabase: true");
    });

    it("rejects browser completion when SQL session revocation has not reached the secondary cache", async () => {
      const f = await fixture(database, false, false, true);
      const { path } = await f.browserHandoff();
      expect((await f.browser(path)).status).toBe(302);
      await f.browserLogin();
      const view = (await (await f.browser("/get-session")).json()) as {
        session: { token: string };
      };
      await f.context.adapter.delete({
        model: "session",
        where: [{ field: "token", value: view.session.token }],
      });
      const cached = (await (await f.browser("/get-session")).json()) as {
        session: { token: string };
      };
      expect(cached.session.token).toBe(view.session.token);
      expect((await f.browser("/first-party/browser/complete")).status).toBe(
        401,
      );
      expect(
        await f.context.adapter.count({ model: "firstPartyAuthorization" }),
      ).toBe(0);
    });

    it.each(["missing", "handoff", "snapshot"] as const)(
      "rejects browser session proof with %s provenance",
      async (change) => {
        const f = await fixture(database);
        const { path } = await f.browserHandoff();
        expect((await f.browser(path)).status).toBe(302);
        await f.browserLogin();
        await f.context.adapter.updateMany({
          model: "session",
          where: [],
          update:
            change === "handoff"
              ? { firstPartyBrowserHandoffId: "another-handoff" }
              : {
                  firstPartyBrowserSecurityHash:
                    change === "missing" ? null : "invalid",
                },
        });
        expect((await f.browser("/first-party/browser/complete")).status).toBe(
          401,
        );
        expect(
          await f.context.adapter.count({ model: "firstPartyAuthorization" }),
        ).toBe(0);
      },
    );

    it("does not resurrect browser authentication after a security setting is restored", async () => {
      const f = await fixture(database);
      const { path } = await f.browserHandoff();
      expect((await f.browser(path)).status).toBe(302);
      await f.browserLogin();
      const user = await f.context.adapter.findOne<{
        id: string;
        emailVerified: boolean;
      }>({
        model: "user",
        where: [{ field: "email", value: f.testUser.email }],
      });
      await f.context.internalAdapter.updateUser(user!.id, {
        emailVerified: !user!.emailVerified,
      });
      await f.context.internalAdapter.updateUser(user!.id, {
        emailVerified: user!.emailVerified,
      });
      expect((await f.browser("/first-party/browser/complete")).status).toBe(
        401,
      );
      expect(
        await f.context.adapter.count({ model: "firstPartyAuthorization" }),
      ).toBe(0);
    });

    it("rejects browser account changes for an already-bound native key and rechecks client registration", async () => {
      const f = await fixture(database);
      await f.redeem(
        (await f.step((await f.start()).body)).body.authorization_code!,
      );
      const { path } = await f.browserHandoff();
      expect((await f.browser(path)).status).toBe(302);
      expect(
        (
          await f.browser("/sign-up/email", {
            email: "other-browser@example.test",
            password: "other-password-123",
            name: "Other",
          })
        ).status,
      ).toBe(200);
      expect((await f.browser("/first-party/browser/complete")).status).toBe(
        401,
      );
      await f.browserLogin();
      await f.context.adapter.update({
        model: "oauthClient",
        where: [{ field: "clientId", value: "mobile" }],
        update: { disabled: true },
      });
      expect((await f.browser("/first-party/browser/complete")).status).toBe(
        400,
      );
      await f.context.adapter.update({
        model: "oauthClient",
        where: [{ field: "clientId", value: "mobile" }],
        update: { disabled: false },
      });
      expect((await f.browser("/first-party/browser/complete")).status).toBe(
        302,
      );
    });

    it("rejects stale browser sessions and requires the handoff cookie as well as completed MFA", async () => {
      const f = await fixture(database);
      const { path } = await f.browserHandoff();
      await f.browserLogin();
      await f.context.adapter.updateMany({
        model: "session",
        where: [],
        update: { createdAt: new Date(0) },
      });
      expect((await f.browser(path)).status).toBe(302);
      const [opened] = await f.context.adapter.findMany<{ openedAt: Date }>({
        model: "firstPartyBrowser",
      });
      // Even equality at the database clock precision cannot prove a fresh login.
      await f.context.adapter.updateMany({
        model: "session",
        where: [],
        update: { createdAt: opened!.openedAt },
      });
      expect((await f.browser("/first-party/browser/complete")).status).toBe(
        401,
      );
      await f.browserLogin();
      const handoff = [...f.cookies].find(([name]) =>
        name.includes("first_party_browser"),
      )!;
      f.cookies.delete(handoff[0]);
      expect((await f.browser("/first-party/browser/complete")).status).toBe(
        400,
      );
      f.cookies.set(handoff[0], "tampered");
      expect((await f.browser("/first-party/browser/complete")).status).toBe(
        400,
      );
      f.cookies.set(...handoff);
      expect(
        (
          await f.browser(
            "/first-party/browser/complete?redirect_uri=https://attacker.example",
          )
        ).status,
      ).toBe(400);
      expect(
        await f.context.adapter.count({ model: "firstPartyAuthorization" }),
      ).toBe(0);
      expect((await f.browser("/first-party/browser/complete")).status).toBe(
        302,
      );
    });

    it("rejects substituted browser clients and callback parameters without consuming the valid handoff", async () => {
      const f = await fixture(database);
      const { prepared, path } = await f.browserHandoff();
      for (const answer of [
        {
          kind: "browser",
          redirectUri: "https://attacker.example/callback",
          state: randomBytes(32).toString("base64url"),
        },
        {
          kind: "browser",
          redirectUri: "com.example.test:/auth/callback",
          state: "short",
        },
      ])
        expect((await f.step(prepared.body, answer)).response.status).toBe(400);
      expect(
        (await f.browser(path.replace("client_id=mobile", "client_id=other")))
          .status,
      ).toBe(400);
      expect(
        (await f.browser(`${path}&redirect_uri=https://attacker.example`))
          .status,
      ).toBe(400);
      expect((await f.browser(`${path}&client_id=mobile`)).status).toBe(400);
      expect(
        (
          await f.browser(
            "/oauth2/authorize?client_id=mobile&response_type=code&redirect_uri=com.example.test:/auth/callback",
          )
        ).status,
      ).toBe(400);
      expect((await f.browser(path)).status).toBe(302);
      expect(
        await f.context.adapter.count({ model: "firstPartyAuthorization" }),
      ).toBe(0);
    });

    it("invalidates browser completion after cancellation, retirement or evidence expiry", async () => {
      for (const action of ["cancel", "retire", "expire"] as const) {
        const f = await fixture(database);
        const { prepared, path } = await f.browserHandoff();
        expect((await f.browser(path)).status).toBe(302);
        await f.browserLogin();
        if (action === "cancel")
          expect(
            (await f.step(prepared.body, { kind: "cancel" })).body.cancelled,
          ).toBe(true);
        else if (action === "expire")
          await f.context.adapter.updateMany({
            model: "firstPartyAttempt",
            where: [],
            update: { evidenceExpiresAt: new Date(0) },
          });
        else {
          const [credential] =
            await f.context.adapter.findMany<LogicalCredential>({
              model: "firstPartyCredential",
            });
          await f.run((ctx) => retireLogicalCredential(ctx, credential!.id));
        }
        expect((await f.browser("/first-party/browser/complete")).status).toBe(
          400,
        );
        expect(
          await f.context.adapter.count({ model: "firstPartyAuthorization" }),
        ).toBe(0);
      }
    });

    it("allows exactly one browser completion under concurrent callback requests", async () => {
      const f = await fixture(database);
      const { path } = await f.browserHandoff();
      expect((await f.browser(path)).status).toBe(302);
      await f.browserLogin();
      const results = await Promise.all([
        f.browser("/first-party/browser/complete"),
        f.browser("/first-party/browser/complete"),
      ]);
      expect(results.map((result) => result.status).sort()).toEqual([302, 400]);
      expect(
        await f.context.adapter.count({ model: "firstPartyAuthorization" }),
      ).toBe(1);
    });

    it("rolls back browser completion and retains a retryable handoff if authorization storage fails", async () => {
      const f = await fixture(database);
      const { path } = await f.browserHandoff();
      expect((await f.browser(path)).status).toBe(302);
      await f.browserLogin();
      const before = await f.sessions();
      const transaction = f.context.adapter.transaction;
      f.context.adapter.transaction = (operation) =>
        transaction(async (adapter) => {
          const create = adapter.create;
          adapter.create = async (input) => {
            if (input.model === "firstPartyAuthorization")
              throw new Error("injected-browser-authorization-failure");
            return create(input);
          };
          return operation(adapter);
        });
      try {
        expect((await f.browser("/first-party/browser/complete")).status).toBe(
          500,
        );
      } finally {
        f.context.adapter.transaction = transaction;
      }
      expect(await f.sessions()).toEqual(before);
      expect(
        await f.context.adapter.count({
          model: "firstPartyBrowser",
          where: [{ field: "status", value: "opened" }],
        }),
      ).toBe(1);
      expect(
        await f.context.adapter.count({ model: "firstPartyAuthorization" }),
      ).toBe(0);
      expect((await f.browser("/first-party/browser/complete")).status).toBe(
        302,
      );
    });

    it("bounds admission requests and rejects unknown clients, malformed evidence and cross-purpose fields before account work", async () => {
      const f = await fixture(database);
      const valid = { binding: f.binding, keyId: KEY };
      for (const body of [
        { ...valid, binding: { ...f.binding, clientId: "not-registered" } },
        { ...valid, binding: { ...f.binding, applicationId: "TEAM.other" } },
        {
          ...valid,
          binding: { ...f.binding, issuer: "https://other.example.test" },
        },
        { ...valid, purpose: "oauth-authorization" },
      ])
        expect((await f.admissionRequest("challenge", body)).status).toBe(400);
      expect(
        (await f.admissionRequest("challenge", valid, "text/plain")).status,
      ).toBe(415);
      expect(
        (
          await f.admissionRequest("challenge", {
            ...valid,
            padding: "x".repeat(32768),
          })
        ).status,
      ).toBe(413);
      const response = await f.admissionRequest("challenge", valid);
      expect(response.headers.get("cache-control")).toBe("no-store");
      expect(response.headers.get("set-cookie")).toBeNull();
      const challenge = (await response.json()) as { challengeToken: string };
      const rejected = await f.admissionRequest("verify", {
        clientId: "mobile",
        challengeToken: challenge.challengeToken,
        keyId: KEY,
        evidence: Buffer.from("invalid-provider-evidence").toString("base64"),
      });
      expect(rejected.status).toBe(400);
      expect(await rejected.json()).toEqual({ error: "invalid_request" });
      expect(
        (
          await f.admissionRequest("verify", {
            clientId: "mobile",
            challengeToken: challenge.challengeToken,
            keyId: KEY,
            evidence: "x".repeat(6000),
          })
        ).status,
      ).toBe(413);
      expect(f.observed.calls).toBe(0);
      expect(await f.sessions()).toHaveLength(0);
      expect(
        await f.context.adapter.count({ model: "firstPartyTokenFamily" }),
      ).toBe(0);
      // Rejection does not make this key unusable or consume another challenge.
      expect((await f.start()).body.step?.kind).toBe("password");
    });

    it("limits failed-storage cleanup to the proven family without cancelling its replacement or continuation", async () => {
      const f = await fixture(database, true);
      const first = await f.redeem(
        (await f.step((await f.start()).body)).body.authorization_code!,
      );
      const continuation = async (handle: string) =>
        f.step(
          (
            await f.send({
              ...(await f.startFields({
                ...f.binding,
                attemptId: randomBytes(32).toString("base64url"),
              })),
              auth_session: handle,
            })
          ).body,
        );
      const second = await f.redeem(
        (await continuation(first.auth_session!)).body.authorization_code!,
      );
      const pending = (await continuation(second.auth_session!)).body
        .authorization_code!;
      expect(
        (
          await f.terminate("logout", second.access_token, null, {
            scope: "family",
          })
        ).status,
      ).toBe(401);
      expect(
        (
          await f.terminate("retire", second.access_token, undefined, {
            scope: "family",
          })
        ).status,
      ).toBe(400);
      expect(
        (
          await f.terminate("logout", second.access_token, undefined, {
            scope: "family",
          })
        ).status,
      ).toBe(200);
      expect((await f.access(second.access_token)).status).toBe(401);
      expect(
        (
          await f.tokenRequest({
            grant_type: "refresh_token",
            refresh_token: second.refresh_token!,
          })
        ).response.status,
      ).toBe(400);
      expect((await f.access(first.access_token)).status).toBe(200);
      expect(
        (await f.access((await f.redeem(pending)).access_token)).status,
      ).toBe(200);
    });

    it("logs out every family in the retained session and cancels unredeemed codes while retaining other sessions and keys", async () => {
      const f = await fixture(database, true);
      const first = await f.redeem(
        (await f.step((await f.start()).body)).body.authorization_code!,
      );
      const continueSession = async (handle: string) => {
        const start = await f.send({
          ...(await f.startFields({
            ...f.binding,
            attemptId: randomBytes(32).toString("base64url"),
          })),
          auth_session: handle,
        });
        return f.step(start.body);
      };
      const second = await f.redeem(
        (await continueSession(first.auth_session!)).body.authorization_code!,
      );
      const pendingCode = (await continueSession(second.auth_session!)).body;
      const other = await f.redeem(
        (
          await f.step(
            (
              await f.start({
                ...f.binding,
                attemptId: randomBytes(32).toString("base64url"),
              })
            ).body,
          )
        ).body.authorization_code!,
      );
      const response = await f.terminate("logout", first.access_token);
      expect(response.status).toBe(200);
      expect(await response.json()).toEqual({ success: true });
      expect(response.headers.get("cache-control")).toBe("no-store");
      expect(response.headers.get("set-cookie")).toBeNull();
      expect((await f.access(first.access_token)).status).toBe(401);
      expect((await f.access(second.access_token)).status).toBe(401);
      expect((await f.access(other.access_token)).status).toBe(200);
      expect(
        (
          await f.tokenRequest({
            grant_type: "refresh_token",
            refresh_token: second.refresh_token!,
          })
        ).body.error,
      ).toBe("invalid_grant");
      expect(
        (
          await f.tokenRequest({
            grant_type: "authorization_code",
            code: pendingCode.authorization_code!,
            code_verifier: VERIFIER,
          })
        ).body.error,
      ).toBe("invalid_grant");
      expect(
        (
          await f.send({
            ...(await f.startFields({
              ...f.binding,
              attemptId: randomBytes(32).toString("base64url"),
            })),
            auth_session: pendingCode.auth_session,
          })
        ).response.status,
      ).toBe(400);
      expect(
        await f.context.adapter.count({
          model: "firstPartyCredential",
          where: [{ field: "status", value: "active" }],
        }),
      ).toBe(1);
      expect(
        await f.context.adapter.count({
          model: "deviceAttestationCredential",
          where: [{ field: "status", value: "active" }],
        }),
      ).toBe(1);
      // A new session with fresh evidence can reuse the preserved account keys.
      expect(
        (
          await f.start({
            ...f.binding,
            attemptId: randomBytes(32).toString("base64url"),
          })
        ).body.step?.kind,
      ).toBe("password");
    });

    it("requires token-bound DPoP for removal and scopes retirement to the proven credential", async () => {
      const f = await fixture(database);
      const tokens = await f.redeem(
        (await f.step((await f.start()).body)).body.authorization_code!,
      );
      const url = `${f.context.baseURL}/first-party/retire`;
      const wrongKey = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
      for (const proof of [
        null,
        f.proof(url),
        f.proof(url, wrongKey, tokens.access_token, "POST"),
        f.proof(url, f.key, "substituted", "POST"),
      ])
        expect(
          (await f.terminate("retire", tokens.access_token, proof)).status,
        ).toBe(401);
      expect(
        (
          await f.terminate("retire", tokens.access_token, undefined, {
            credentialId: "another-credential",
          })
        ).status,
      ).toBe(400);
      expect((await f.access(tokens.access_token)).status).toBe(200);
      expect(
        (
          await f.terminate("retire", tokens.access_token, undefined, {
            padding: "x".repeat(257),
          })
        ).status,
      ).toBe(413);
      const next = await f.start({
        ...f.binding,
        attemptId: randomBytes(32).toString("base64url"),
      });
      expect((await f.terminate("retire", tokens.access_token)).status).toBe(
        200,
      );
      expect((await f.step(next.body)).response.status).toBe(400);
      expect((await f.access(tokens.access_token)).status).toBe(401);
      expect(
        await f.context.adapter.count({ model: "oauthRefreshToken" }),
      ).toBe(0);
      expect(
        await f.context.adapter.count({
          model: "firstPartyCredential",
          where: [{ field: "status", value: "revoked" }],
        }),
      ).toBe(1);
      expect(
        await f.context.adapter.count({
          model: "deviceAttestationCredential",
          where: [{ field: "status", value: "revoked" }],
        }),
      ).toBe(1);
    });

    it("rolls back logout and retirement completely if provider token deletion fails", async () => {
      for (const action of ["logout", "retire"] as const) {
        const f = await fixture(database);
        const tokens = await f.redeem(
          (await f.step((await f.start()).body)).body.authorization_code!,
        );
        const before = await f.sessions();
        const transaction = f.context.adapter.transaction;
        f.context.adapter.transaction = (operation) =>
          transaction(async (adapter) => {
            const remove = adapter.deleteMany;
            adapter.deleteMany = async (input) => {
              if (input.model === "oauthRefreshToken")
                throw new Error("injected-removal-failure");
              return remove(input);
            };
            return operation(adapter);
          });
        const proof = f.proof(
          `${f.context.baseURL}/first-party/${action}`,
          f.key,
          tokens.access_token,
          "POST",
        );
        try {
          const response = await f.terminate(
            action,
            tokens.access_token,
            proof,
          );
          expect(response.status).toBe(500);
          expect(await response.json()).toEqual({ error: "server_error" });
        } finally {
          f.context.adapter.transaction = transaction;
        }
        expect(await f.sessions()).toEqual(before);
        expect((await f.access(tokens.access_token)).status).toBe(200);
        expect(
          await f.context.adapter.count({ model: "oauthRefreshToken" }),
        ).toBe(1);
        expect(
          await f.context.adapter.count({
            model: "firstPartyCredential",
            where: [{ field: "status", value: "active" }],
          }),
        ).toBe(1);
        expect(
          await f.context.adapter.count({
            model: "deviceAttestationCredential",
            where: [{ field: "status", value: "active" }],
          }),
        ).toBe(1);
        expect(
          (await f.terminate(action, tokens.access_token, proof)).status,
        ).toBe(401);
        expect((await f.terminate(action, tokens.access_token)).status).toBe(
          200,
        );
        expect((await f.access(tokens.access_token)).status).toBe(401);
      }
    });

    it("serializes logout against refresh so no refreshed family survives sign-out", async () => {
      const f = await fixture(database, true);
      const tokens = await f.redeem(
        (await f.step((await f.start()).body)).body.authorization_code!,
      );
      const [logout, refreshed] = await Promise.all([
        f.terminate("logout", tokens.access_token),
        f.tokenRequest({
          grant_type: "refresh_token",
          refresh_token: tokens.refresh_token!,
        }),
      ]);
      expect(logout.status).toBe(200);
      expect([200, 400]).toContain(refreshed.response.status);
      if (refreshed.response.status === 200)
        expect((await f.access(refreshed.body.access_token)).status).toBe(401);
      expect(await f.context.adapter.count({ model: "oauthAccessToken" })).toBe(
        0,
      );
      expect(
        await f.context.adapter.count({ model: "oauthRefreshToken" }),
      ).toBe(0);
      expect(
        await f.context.adapter.count({
          model: "firstPartyTokenFamily",
          where: [{ field: "status", value: "active" }],
        }),
      ).toBe(0);
    });

    it("prevents password work already in flight from reviving a signed-out session", async () => {
      const f = await fixture(database);
      const tokens = await f.redeem(
        (await f.step((await f.start()).body)).body.authorization_code!,
      );
      const next = await f.send({
        ...(await f.startFields({
          ...f.binding,
          attemptId: randomBytes(32).toString("base64url"),
        })),
        auth_session: tokens.auth_session!,
      });
      let entered!: () => void;
      let release!: () => void;
      const waiting = new Promise<void>((resolve) => {
        entered = resolve;
      });
      const held = new Promise<void>((resolve) => {
        release = resolve;
      });
      f.observed.hold = async () => {
        entered();
        await held;
      };
      const completing = f.step(next.body);
      await waiting;
      try {
        expect((await f.terminate("logout", tokens.access_token)).status).toBe(
          200,
        );
      } finally {
        release();
      }
      expect((await completing).response.status).toBe(400);
      expect(await f.context.adapter.count({ model: "session" })).toBe(0);
      expect(
        (await f.attempts()).some((attempt) => attempt.status === "processing"),
      ).toBe(false);
      expect((await f.sessions())[0]!.status).toBe("revoked");
    });

    it("does not rotate away an auth session being used by another authorization attempt", async () => {
      const f = await fixture(database);
      const tokens = await f.redeem(
        (await f.step((await f.start()).body)).body.authorization_code!,
      );
      const fields = await f.startFields({
        ...f.binding,
        attemptId: randomBytes(32).toString("base64url"),
      });
      const second = await f.send({
        ...fields,
        auth_session: tokens.auth_session!,
      });
      const refreshed = await f.tokenRequest({
        grant_type: "refresh_token",
        refresh_token: tokens.refresh_token!,
      });
      expect(refreshed.response.status).toBe(200);
      expect(refreshed.body.auth_session).toBeUndefined();
      expect((await f.step(second.body)).body.authorization_code).toBeDefined();
    });
  });
