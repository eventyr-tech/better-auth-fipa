import { createHash, generateKeyPairSync, randomUUID, sign } from "node:crypto";
import { deriveDpopJkt } from "@better-auth/core/oauth2";
import type { GenericEndpointContext } from "@better-auth/core";
import {
  getOAuthProviderApi,
  oauthProvider,
  type OAuthOptions,
} from "@better-auth/oauth-provider";
import type { BetterAuthPlugin } from "better-auth";
import {
  APIError,
  createAuthEndpoint,
  createAuthMiddleware,
  dispatchAuthEndpoint,
} from "better-auth/api";
import { emailOTP, twoFactor, jwt } from "better-auth/plugins";
import {
  requestLegacyEmailOTP,
  submitLegacyEmailOTP,
} from "./first-party/legacy-v1/email-otp.js";
import {
  authorizeLegacySession,
  submitLegacyPassword,
  submitLegacyProfile,
} from "./first-party/legacy-v1/authorization.js";
import { authenticateWithPassword } from "./first-party/password-method.js";
import { reauthenticateLegacyPassword } from "./first-party/legacy-v1/reauthentication.js";
import {
  createNativeTokenHook,
  requireNativeAccess,
  revokeNativeFamily,
  type NativeTokenOptions,
} from "./first-party/token-lifecycle.js";
import { getTestInstance } from "./fixtures/auth-instance.js";
import { describe, expect, it, vi } from "vitest";
import { withFirstPartyTransaction } from "./first-party/transaction.js";
import { z } from "zod";
import { createDeviceAttestation } from "./plugin.js";
import {
  createNativeFirstPartyPlugin,
  requireLegacyAccess,
  resolveFirstPartyTokenContext,
  type FirstPartyTokenContext,
} from "./first-party.js";
import { FIRST_PARTY_PROFILE } from "./first-party/wire.js";
import type { DeviceAttestationProvider } from "./types.js";
import { createNativeChallengeEndpoint } from "./first-party/challenge-endpoint.js";
import { firstPartyStateSchema } from "./first-party/state-schema.js";
import {
  parseLegacyChallenge,
  type LegacyClientPolicy,
} from "./first-party/legacy-v1/contract.js";
import {
  createLegacySession,
  finishLegacyStep,
  legacySessionSchema,
  reserveLegacyStep,
  type LegacySession,
} from "./first-party/legacy-v1/session.js";

const APP = "TEAM.legacy";
const KEY = Buffer.alloc(32, 44).toString("base64");
const oauth: OAuthOptions<string[]> = {
  loginPage: "/login",
  consentPage: "/consent",
  disableJwtPlugin: true,
  scopes: ["offline_access", "api:read"],
  resources: ["https://api.example.test"],
};
const defaultPolicy: LegacyClientPolicy = {
  clientId: "mobile",
  provider: "legacy-test",
  applicationId: APP,
  environment: "production",
  redirectUris: ["example:/callback"],
  scopes: ["offline_access", "api:read"],
  resources: ["https://api.example.test"],
  sessionLifetimeSeconds: 1800,
};
const signingKey = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const VERIFIER = "v".repeat(43);
const fields = {
  client_id: "mobile",
  response_type: "code",
  scope: "api:read offline_access",
  code_challenge: createHash("sha256").update(VERIFIER).digest("base64url"),
  code_challenge_method: "S256",
  dpop_jkt: await deriveDpopJkt(signingKey.publicKey.export({ format: "jwk" })),
  redirect_uri: "example:/callback",
  resource: "https://api.example.test",
  platform: "ios",
  intent: "authenticate",
  email: "tester@example.test",
};
const provider: DeviceAttestationProvider = {
  id: defaultPolicy.provider,
  maxEvidenceBytes: 1024,
  decodeKeyId: (key) => Buffer.from(key, "base64"),
  verifyRegistration: () =>
    Promise.resolve({
      applicationId: APP,
      environment: "production",
      publicKey: "fixture",
      counter: 0,
      extensionsPresent: false,
    }),
  verifyAssertion: ({ credential }) =>
    Promise.resolve({
      counter: credential.counter + 1,
      extensionsPresent: false,
    }),
};
async function fixture(
  database: "sqlite" | "postgres",
  enabled = true,
  tokens = false,
  otp = false,
  useSecondary = false,
  publicComposition = false,
  policy: LegacyClientPolicy = { ...defaultPolicy },
  claimsMode?: "opaque" | "jwt",
) {
  const claims = {
    contexts: [] as FirstPartyTokenContext[],
    fallbacks: 0,
    fail: false,
  };
  const secondary = new Map<string, { value: string; expiresAt: number }>();
  const low = createDeviceAttestation({
    providers: [provider],
    purposes: {
      credentialRegistration: {},
      oauthAuthorization: {
        protectedClientIds: ["mobile"],
        requireDpopJkt: true,
      },
    },
  });
  const configuredOAuth: OAuthOptions<string[]> = {
    ...oauth,
    disableJwtPlugin: claimsMode !== "jwt",
    cachedTrustedClients: new Set(["mobile"]),
    ...(claimsMode
      ? {
          customAccessTokenClaims: async (
            info: Parameters<
              NonNullable<OAuthOptions<string[]>["customAccessTokenClaims"]>
            >[0],
          ) => {
            const context = await resolveFirstPartyTokenContext(
              tokenOptions,
              info,
            );
            if (!context) {
              claims.fallbacks++;
              return { "urn:example:ordinary": true };
            }
            claims.contexts.push(context);
            if (claims.fail) throw new Error("private host claims failure");
            return {
              "urn:example:family": context.familyId,
              "urn:example:profile": context.profile,
              "urn:example:auth_time": context.authTime,
              // Host policy: a freshly completed password factor qualifies.
              // This label does not imply MFA or change protocol provenance.
              ...(Array.isArray(context.assurance.amr) &&
              context.assurance.amr.includes("pwd")
                ? { "urn:example:acr": "eventyr:password" }
                : {}),
            };
          },
        }
      : {}),
  };
  const providerPlugin = oauthProvider(configuredOAuth);
  const oauthPlugin: BetterAuthPlugin = {
    ...providerPlugin,
    endpoints: providerPlugin.endpoints as unknown as NonNullable<
      BetterAuthPlugin["endpoints"]
    >,
  };
  const ops = new Map<
    string,
    (ctx: GenericEndpointContext) => Promise<unknown>
  >();
  const observed = {
    vetoDelete: false,
    legacyCalls: 0,
    limitEvidence: false,
    passwordLimit: false,
    passwordCalls: 0,
    profileCalls: 0,
    setupCalls: 0,
    denySetup: false,
    fakeSetup: false,
    fakeProfile: false,
    failPasswordSessionCache: false,
    onProfile: undefined as
      ((ctx: GenericEndpointContext) => Promise<void>) | undefined,
    onPassword: undefined as
      ((ctx: GenericEndpointContext) => Promise<void>) | undefined,
    routed: [] as { email: string; otp: string }[],
    genericDeliveryCalls: 0,
    failDelivery: false,
    denyCreateOTP: false,
    createOTPCalls: 0,
    onDelivery: undefined as (() => Promise<void>) | undefined,
  };
  const options = {
    policy,
    oauth: configuredOAuth,
    familyLifetimeSeconds: 3600,
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
      delivery: async (input: { email: string; otp: string }) => {
        observed.routed.push(input);
        await observed.onDelivery?.();
        if (observed.failDelivery)
          throw new Error("private template delivery failure");
      },
    },
  };
  const tokenOptions: NativeTokenOptions = {
    ...(publicComposition && otp ? { emailOTP: options.emailOTP } : {}),
    ...(publicComposition && enabled
      ? { legacyCompatibility: { clients: [policy] } }
      : {}),
    oauth: configuredOAuth,
    applications: [
      {
        clientId: "mobile",
        provider,
        applicationId: APP,
        environment: "production",
        scopes: [...policy.scopes],
        resources: [...policy.resources],
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
  const passwordAnswer = async (
    ctx: GenericEndpointContext,
    request: Record<string, unknown>,
  ) => {
    const result = await submitLegacyPassword(ctx, options, request);
    return result.kind === "authorized"
      ? Response.json({
          authorization_code: result.authorizationCode,
          auth_session: request.auth_session,
        })
      : Response.json(
          {
            error:
              result.kind === "rejected"
                ? "invalid_grant"
                : "interaction_required",
          },
          { status: result.kind === "rejected" ? 401 : 403 },
        );
  };
  const challenge = createNativeChallengeEndpoint(
    tokenOptions,
    enabled
      ? {
          policies: [policy],
          handle: async (ctx, request) => {
            observed.legacyCalls++;
            let authSession = request.auth_session;
            let session: LegacySession;
            if (authSession) {
              if (tokens && request.password)
                return passwordAnswer(ctx, request);
              const reserved = await reserveLegacyStep(ctx, options, request);
              session = await finishLegacyStep(ctx, options, reserved, {
                step: "email_password",
              });
            } else {
              const evidence = request.device_attestation;
              if (!evidence) throw new Error("Missing fixture evidence");
              const result = await dispatchAuthEndpoint(
                low.serverPlugin.endpoints.verifyDeviceAttestation,
                {
                  context: ctx.context,
                  method: "POST",
                  body: {
                    challengeToken: evidence.challenge_token,
                    keyId: evidence.key_id,
                    evidence: evidence.evidence,
                  },
                  asResponse: true,
                },
              );
              if (!(result instanceof Response) || !result.ok)
                throw new Error("Fixture verification failed");
              const grant = z
                .object({
                  credentialState: z.literal("asserted"),
                  grantToken: z.string(),
                })
                .parse(await result.json());
              const created = await createLegacySession(
                ctx,
                options,
                request,
                grant.grantToken,
              );
              authSession = created.authSession;
              session = created.session;
              if (tokens && request.password)
                return passwordAnswer(ctx, {
                  ...request,
                  auth_session: authSession,
                });
            }
            return Response.json({
              error: "insufficient_authorization",
              auth_session: authSession,
              next_step: session.step,
              email: session.email,
            });
          },
        }
      : undefined,
  );
  const { auth, testUser } = await getTestInstance(
    {
      user: {
        deleteUser: {
          enabled: true,
          beforeDelete: () => {
            if (observed.vetoDelete) throw new APIError("FORBIDDEN");
            return Promise.resolve();
          },
        },
      },
      ...(useSecondary
        ? {
            session: { storeSessionInDatabase: true },
            verification: { storeInDatabase: true },
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
                const value = Number(live?.value ?? "0") + 1;
                secondary.set(key, {
                  value: String(value),
                  expiresAt: live?.expiresAt ?? Date.now() + ttl * 1000,
                });
                return Promise.resolve(value);
              },
              set: (key: string, value: string, ttl?: number) => {
                secondary.set(key, {
                  value,
                  expiresAt: Date.now() + (ttl ?? 3600) * 1000,
                });
                if (
                  observed.failPasswordSessionCache &&
                  observed.setupCalls > 0 &&
                  value.includes('"session":')
                ) {
                  observed.failPasswordSessionCache = false;
                  return Promise.reject(
                    new Error("cache acknowledged after write with an error"),
                  );
                }
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
        ...(claimsMode === "jwt" ? [jwt()] : []),
        low.serverPlugin,
        oauthPlugin,
        twoFactor(),
        ...(publicComposition
          ? [createNativeFirstPartyPlugin(tokenOptions)]
          : []),
        ...(otp
          ? [
              emailOTP({
                storeOTP: "hashed",
                generateOTP: () => "003147",
                allowedAttempts: 3,
                disableSignUp: false,
                sendVerificationOTP: () => {
                  observed.genericDeliveryCalls++;
                  throw new Error("delivery must use the routed sender");
                },
              }) as BetterAuthPlugin,
            ]
          : []),
        {
          id: "legacy-fixture",
          ...(tokens
            ? {
                hooks: {
                  before: [
                    {
                      matcher: (ctx) =>
                        ctx.path === "/device-attestation/verify",
                      handler: createAuthMiddleware(() => {
                        if (observed.limitEvidence)
                          throw new APIError(
                            "TOO_MANY_REQUESTS",
                            { message: "private evidence limiter" },
                            {
                              "retry-after": "7",
                              "set-cookie": "private=do-not-return",
                            },
                          );
                        return Promise.resolve();
                      }),
                    },
                    {
                      matcher: (ctx) => ctx.path === "/update-user",
                      handler: createAuthMiddleware(async (ctx) => {
                        if (observed.fakeProfile)
                          return ctx.json({ status: true });
                      }),
                    },
                    {
                      matcher: (ctx) =>
                        ctx.path === undefined &&
                        typeof (
                          ctx.body as { newPassword?: unknown } | undefined
                        )?.newPassword === "string",
                      handler: createAuthMiddleware(async (ctx) => {
                        observed.setupCalls++;
                        if (observed.denySetup)
                          throw new APIError("FORBIDDEN", {
                            message: "private setup policy",
                          });
                        if (observed.fakeSetup)
                          return ctx.json({ status: true });
                      }),
                    },
                    {
                      matcher: (ctx) =>
                        ctx.path === undefined &&
                        (ctx.body as { type?: string } | undefined)?.type ===
                          "sign-in",
                      handler: createAuthMiddleware(() => {
                        observed.createOTPCalls++;
                        if (observed.denyCreateOTP)
                          throw new APIError("FORBIDDEN", {
                            message: "private delivery policy",
                          });
                        return Promise.resolve();
                      }),
                    },
                    ...(publicComposition
                      ? []
                      : [
                          createNativeTokenHook(
                            tokenOptions,
                            enabled ? [policy] : [],
                          ),
                        ]),
                    {
                      matcher: (ctx) => ctx.path === "/sign-in/email",
                      handler: createAuthMiddleware(async (ctx) => {
                        observed.passwordCalls++;
                        if (observed.passwordLimit)
                          throw new APIError(
                            "TOO_MANY_REQUESTS",
                            { error: "temporarily_unavailable" },
                            { "retry-after": "15" },
                          );
                        await observed.onPassword?.(ctx);
                      }),
                    },
                  ],
                  after: [
                    {
                      matcher: (ctx) => ctx.path === "/update-user",
                      handler: createAuthMiddleware(async (ctx) => {
                        observed.profileCalls++;
                        await observed.onProfile?.(ctx);
                      }),
                    },
                  ],
                },
              }
            : {}),
          ...(publicComposition
            ? {}
            : { schema: { ...firstPartyStateSchema, ...legacySessionSchema } }),
          endpoints: {
            ...(publicComposition ? {} : { legacyChallenge: challenge }),
            legacyProbe: createAuthEndpoint(
              "/test-only/legacy",
              { method: "POST", body: z.object({ id: z.string() }) },
              (ctx) => {
                const op = ops.get(ctx.body.id);
                if (!op) throw new Error("Missing fixture operation");
                return op(ctx);
              },
            ),
          },
        },
      ],
    },
    { testWith: database, transaction: true },
  );
  const context = await auth.$context;
  const user = await context.adapter.findOne<{ id: string }>({
    model: "user",
    where: [{ field: "email", value: testUser.email }],
  });
  if (!user) throw new Error("Missing fixture user");
  for (const session of await context.adapter.findMany<{ token: string }>({
    model: "session",
  }))
    await context.internalAdapter.deleteSession(session.token);
  await context.adapter.create({
    model: "oauthClient",
    data: {
      clientId: "mobile",
      redirectUris: ["example:/callback"],
      scopes: [...policy.scopes],
      grantTypes: ["authorization_code", "refresh_token"],
      tokenEndpointAuthMethod: "none",
      disabled: false,
    },
  });
  await context.adapter.create({
    model: "oauthClientResource",
    data: {
      clientId: "mobile",
      resourceId: policy.resources[0],
      createdAt: new Date(),
    },
  });
  const registration = await auth.api.createDeviceAttestationChallenge({
    body: {
      provider: provider.id,
      applicationId: APP,
      keyId: KEY,
      operation: "register",
      purpose: "credential-registration",
    },
  });
  const registered = await auth.api.verifyDeviceAttestation({
    body: {
      challengeToken: registration.challengeToken,
      keyId: KEY,
      evidence: "YQ==",
    },
  });
  if (registered.credentialState !== "registered-unbound")
    throw new Error("Bad fixture registration");
  const credentialId = registered.credentialId;
  const run = async <T>(
    op: (ctx: GenericEndpointContext) => Promise<T>,
  ): Promise<T> => {
    const id = randomUUID();
    ops.set(id, op);
    try {
      return (await auth.api.legacyProbe({ body: { id } })) as T;
    } finally {
      ops.delete(id);
    }
  };
  const runHTTP = async (
    op: (ctx: GenericEndpointContext) => Promise<unknown>,
    headers: Headers,
  ) => {
    const id = randomUUID();
    ops.set(id, op);
    try {
      return await auth.api.legacyProbe({
        body: { id },
        headers,
        asResponse: true,
      });
    } finally {
      ops.delete(id);
    }
  };
  const evidence = async () => {
    const binding = parseLegacyChallenge(fields, policy).binding;
    const challenge = await auth.api.createDeviceAttestationChallenge({
      body: {
        provider: provider.id,
        applicationId: APP,
        keyId: KEY,
        operation: "assert",
        purpose: "oauth-authorization",
        binding,
      },
    });
    return {
      challenge_token: challenge.challengeToken,
      key_id: KEY,
      evidence: "YQ==",
    };
  };
  const grant = async () => {
    const proof = await evidence();
    const result = await auth.api.verifyDeviceAttestation({
      body: {
        challengeToken: proof.challenge_token,
        keyId: proof.key_id,
        evidence: proof.evidence,
      },
    });
    if (result.credentialState !== "asserted")
      throw new Error("Bad fixture grant");
    return result.grantToken;
  };
  const create = async (overrides: Record<string, unknown> = {}) => {
    const token = await grant();
    return run((ctx) =>
      createLegacySession(ctx, options, { ...fields, ...overrides }, token),
    );
  };
  const reserve = (handle: string, overrides: Record<string, unknown> = {}) =>
    run((ctx) =>
      reserveLegacyStep(ctx, options, {
        ...fields,
        auth_session: handle,
        ...overrides,
      }),
    );
  const send = (
    body: Record<string, unknown>,
    contentType = "application/json",
    proof?: string,
  ) =>
    auth.handler(
      new Request(`${context.baseURL}/first-party/authorization-challenge`, {
        method: "POST",
        headers: {
          "content-type": contentType,
          ...(proof ? { DPoP: proof } : {}),
        },
        body:
          contentType === "application/json"
            ? JSON.stringify(body)
            : new URLSearchParams(body as Record<string, string>),
      }),
    );
  const proof = (
    key = signingKey,
    accessToken?: string,
    path = accessToken ? "/resource" : "/oauth2/token",
  ) => {
    const encode = (value: unknown) =>
      Buffer.from(JSON.stringify(value)).toString("base64url");
    const unsigned = `${encode({ alg: "ES256", typ: "dpop+jwt", jwk: key.publicKey.export({ format: "jwk" }) })}.${encode({ htm: accessToken ? "GET" : "POST", htu: `${context.baseURL}${path}`, iat: Math.floor(Date.now() / 1000), jti: randomUUID(), ...(accessToken ? { ath: createHash("sha256").update(accessToken).digest("base64url") } : {}) })}`;
    return `${unsigned}.${sign("sha256", Buffer.from(unsigned), { key: key.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url")}`;
  };
  const nativeLogin = async () => {
    const binding = {
      profile: FIRST_PARTY_PROFILE,
      mode: "native",
      issuer: context.baseURL,
      clientId: "mobile",
      provider: provider.id,
      applicationId: APP,
      environment: "production",
      attemptId: randomUUID(),
      codeChallenge: fields.code_challenge,
      codeChallengeMethod: "S256",
      dpopJkt: fields.dpop_jkt,
      scopes: [...policy.scopes],
      resources: [...policy.resources],
    };
    const admission = async (operation: string, body: object) => {
      const response = await auth.handler(
        new Request(`${context.baseURL}/first-party/attestation/${operation}`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(body),
        }),
      );
      expect(response.status).toBe(200);
      return (await response.json()) as Record<string, string>;
    };
    const challenge = await admission("challenge", { binding, keyId: KEY });
    const grant = await admission("verify", {
      clientId: "mobile",
      challengeToken: challenge.challengeToken,
      keyId: KEY,
      evidence: "YQ==",
    });
    const request = (body: object) =>
      send(
        { profile: FIRST_PARTY_PROFILE, client_id: "mobile", ...body },
        "application/x-www-form-urlencoded",
        proof(signingKey, undefined, "/first-party/authorization-challenge"),
      );
    const start = await request({
      response_type: "code",
      scope: fields.scope,
      resource: fields.resource,
      code_challenge: fields.code_challenge,
      code_challenge_method: "S256",
      authorization_attempt: binding.attemptId,
      device_attestation: grant.grantToken,
    });
    expect(start.status).toBe(403);
    const pending = (await start.json()) as {
      auth_session: string;
      step: { id: string };
    };
    const result = await request({
      auth_session: pending.auth_session,
      step_id: pending.step.id,
      response: JSON.stringify({
        kind: "password",
        email: testUser.email,
        password: testUser.password,
      }),
    });
    expect(result.status).toBe(200);
    return (await result.json()) as {
      authorization_code: string;
      auth_session: string;
    };
  };
  const exchange = async (
    body: Record<string, string>,
    dpop: string | null = proof(),
  ) =>
    auth.handler(
      new Request(`${context.baseURL}/oauth2/token`, {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          ...(dpop ? { dpop } : {}),
        },
        body: new URLSearchParams({ client_id: "mobile", ...body }),
      }),
    );
  const login = async () => {
    const response = await send({
      ...fields,
      email: testUser.email,
      password: testUser.password,
      device_attestation: await evidence(),
    });
    expect(response.status).toBe(200);
    return (await response.json()) as {
      authorization_code: string;
      auth_session: string;
    };
  };
  const requestOTP = (
    handle: string,
    overrides: Record<string, unknown> = {},
  ) =>
    run((ctx) =>
      requestLegacyEmailOTP(ctx, options, {
        ...fields,
        intent: "create_account",
        auth_session: handle,
        ...overrides,
      }),
    );
  const verifyOTP = (handle: string, overrides: Record<string, unknown> = {}) =>
    run((ctx) =>
      submitLegacyEmailOTP(ctx, options, {
        ...fields,
        intent: "create_account",
        auth_session: handle,
        verification_code: observed.routed.at(-1)?.otp,
        ...overrides,
      }),
    );
  const setupProfile = (
    handle: string,
    overrides: Record<string, unknown> = {},
  ) =>
    run((ctx) =>
      submitLegacyProfile(ctx, options, {
        ...fields,
        intent: "create_account",
        auth_session: handle,
        email: undefined,
        display_name: "New User",
        new_password: "new-verified-password",
        ...overrides,
      }),
    );
  return {
    nativeLogin,
    claims,
    setupProfile,
    secondary,
    requestOTP,
    verifyOTP,
    auth,
    testUser: { ...testUser, id: user.id },
    login,
    proof,
    exchange,
    tokenOptions,
    context,
    credentialId,
    options,
    observed,
    run,
    runHTTP,
    grant,
    evidence,
    create,
    reserve,
    send,
  };
}
for (const database of ["sqlite", "postgres"] as const)
  describe.runIf(
    database === "sqlite"
      ? process.env.TEST_POSTGRES !== "true" &&
          Number(process.versions.node.split(".")[0]) >= 22
      : process.env.TEST_POSTGRES === "true",
  )(`legacy continuation boundary (${database})`, () => {
    const codeFields = (code: string) => ({
      grant_type: "authorization_code",
      code,
      code_verifier: VERIFIER,
      redirect_uri: fields.redirect_uri,
      resource: fields.resource,
    });
    const passwordAcr = "urn:example:password";
    const claimsFixture = (mode: "opaque" | "jwt") =>
      fixture(
        database,
        true,
        true,
        false,
        false,
        true,
        { ...defaultPolicy },
        mode,
      );

    it.each(["opaque", "jwt"] as const)(
      "resolves authoritative host claims for %s issuance/introspection and refresh",
      async (mode) => {
        const f = await claimsFixture(mode);
        const login = await f.login();
        const response = await f.exchange(codeFields(login.authorization_code));
        expect(response.status).toBe(200);
        const tokens = (await response.json()) as {
          access_token: string;
          refresh_token: string;
        };
        const payload = await f.run(
          async (ctx) =>
            await getOAuthProviderApi(
              ctx,
              f.options.oauth,
            ).requireActiveAccessToken(tokens.access_token, "mobile"),
        );
        expect(payload).toMatchObject({
          active: true,
          sub: f.testUser.id,
          "urn:example:profile": "legacy-v1",
        });
        expect(f.claims.fallbacks).toBe(0);
        const context = f.claims.contexts[0]!;
        expect(context).toMatchObject({
          userId: f.testUser.id,
          clientId: "mobile",
          profile: "legacy-v1",
          assurance: { challengeProof: false, amr: ["pwd"] },
        });
        expect(payload["urn:example:family"]).toBe(context.familyId);
        const renewed = await f.exchange({
          grant_type: "refresh_token",
          refresh_token: tokens.refresh_token,
          scope: "api:read",
          resource: fields.resource,
        });
        expect(renewed.status).toBe(200);
        const next = (await renewed.json()) as { access_token: string };
        const refreshed = await f.run(
          async (ctx) =>
            await getOAuthProviderApi(
              ctx,
              f.options.oauth,
            ).requireActiveAccessToken(next.access_token, "mobile"),
        );
        expect(refreshed).toMatchObject({
          "urn:example:family": context.familyId,
          "urn:example:auth_time": context.authTime,
        });
        expect(f.claims.contexts.at(-1)?.scopes).toEqual(["api:read"]);
        expect(f.claims.fallbacks).toBe(0);
      },
    );

    it.each([
      ["legacy", "opaque"],
      ["legacy", "jwt"],
      ["native", "opaque"],
      ["native", "jwt"],
    ] as const)(
      "maps fresh password step-up claims for %s/%s and rejects revoked resource access",
      async (protocol, mode) => {
        const f = await fixture(
          database,
          true,
          true,
          false,
          false,
          true,
          {
            ...defaultPolicy,
            passwordAcrValues: ["eventyr:password"],
            allowPasswordReauthentication: true,
          },
          mode,
        );
        const exchangeCode = async (code: string, verifier = VERIFIER) => {
          const response = await f.exchange({
            grant_type: "authorization_code",
            code,
            code_verifier: verifier,
            ...(protocol === "legacy"
              ? { redirect_uri: fields.redirect_uri, resource: fields.resource }
              : {}),
          });
          expect(response.status).toBe(200);
          return (await response.json()) as {
            access_token: string;
            refresh_token: string;
          };
        };
        const claimsFor = (token: string) =>
          f.run(
            async (ctx) =>
              await getOAuthProviderApi(
                ctx,
                f.options.oauth,
              ).requireActiveAccessToken(token, "mobile"),
          );
        const initial = await (protocol === "legacy"
          ? f.login()
          : f.nativeLogin());
        const firstTokens = await exchangeCode(initial.authorization_code);
        const firstClaims = await claimsFor(firstTokens.access_token);
        vi.useFakeTimers({ toFake: ["Date"] });
        try {
          vi.setSystemTime(Date.now() + 2000);
          let authorization: { authorization_code: string };
          const nextVerifier =
            protocol === "legacy" ? "w".repeat(43) : VERIFIER;
          if (protocol === "legacy") {
            const response = await f.send({
              ...fields,
              auth_session: initial.auth_session,
              intent: "step_up",
              acr_values: "eventyr:password",
              email: f.testUser.email,
              password: f.testUser.password,
              code_challenge: createHash("sha256")
                .update(nextVerifier)
                .digest("base64url"),
            });
            expect(response.status).toBe(200);
            authorization = (await response.json()) as {
              authorization_code: string;
            };
          } else {
            // Native step-up here is a new password authentication, not a
            // client-asserted ACR or reuse of an earlier authentication time.
            authorization = await f.nativeLogin();
          }
          const tokens = await exchangeCode(
            authorization.authorization_code,
            nextVerifier,
          );
          const payload = await claimsFor(tokens.access_token);
          const context = f.claims.contexts.at(-1)!;
          const expected = {
            active: true,
            sub: f.testUser.id,
            "urn:example:acr": "eventyr:password",
            "urn:example:profile":
              protocol === "legacy" ? "legacy-v1" : FIRST_PARTY_PROFILE,
            "urn:example:family": context.familyId,
            "urn:example:auth_time": context.authTime,
          };
          expect(payload).toMatchObject(expected);
          expect(context.authTime).toBeGreaterThan(
            firstClaims["urn:example:auth_time"] as number,
          );
          expect(context.assurance.amr).toContain("pwd");
          const family = await f.context.adapter.findOne<{
            authenticatedAt: Date;
          }>({
            model: "firstPartyTokenFamily",
            where: [{ field: "id", value: context.familyId }],
          });
          expect(context.authTime).toBe(
            Math.floor(family!.authenticatedAt.getTime() / 1000),
          );
          vi.setSystemTime(Date.now() + 2000);
          const refresh = await f.exchange({
            grant_type: "refresh_token",
            refresh_token: tokens.refresh_token,
            resource: fields.resource,
          });
          expect(refresh.status).toBe(200);
          const renewed = (await refresh.json()) as { access_token: string };
          expect(await claimsFor(renewed.access_token)).toMatchObject(expected);
          const access = () =>
            f.run((ctx) =>
              (protocol === "legacy"
                ? requireLegacyAccess
                : requireNativeAccess)(ctx, f.tokenOptions, {
                headers: new Headers({
                  authorization: `DPoP ${renewed.access_token}`,
                  dpop: f.proof(signingKey, renewed.access_token),
                }),
                method: "GET",
                url: `${f.context.baseURL}/resource`,
                resource: fields.resource,
                scopes: ["api:read"],
              }),
            );
          await expect(access()).resolves.toMatchObject({
            userId: f.testUser.id,
          });
          await f.run((ctx) =>
            withFirstPartyTransaction(ctx, (tx) =>
              revokeNativeFamily(tx, context.familyId),
            ),
          );
          await expect(access()).rejects.toMatchObject({ statusCode: 401 });
          expect(f.claims.fallbacks).toBe(0);
        } finally {
          vi.useRealTimers();
        }
      },
    );

    const lifecycleFixture = async (protocol: "native" | "legacy") => {
      const f = await claimsFixture("jwt");
      const login = () => (protocol === "native" ? f.nativeLogin() : f.login());
      const redeem = (code: string) =>
        f.exchange({
          grant_type: "authorization_code",
          code,
          code_verifier: VERIFIER,
          ...(protocol === "legacy"
            ? { redirect_uri: fields.redirect_uri, resource: fields.resource }
            : {}),
        });
      const exchanged = await redeem((await login()).authorization_code);
      expect(exchanged.status).toBe(200);
      const tokens = (await exchanged.json()) as {
        access_token: string;
        refresh_token: string;
      };
      const browser = await f.auth.api.signInEmail({
        body: { email: f.testUser.email, password: f.testUser.password },
        asResponse: true,
      });
      expect(browser.status).toBe(200);
      const cookie = browser.headers
        .getSetCookie()
        .map((value) => value.split(";")[0])
        .join("; ");
      const remove = (operation: "user" | "provider") =>
        f.auth.handler(
          new Request(
            `${f.context.baseURL}${operation === "user" ? "/delete-user" : "/device-attestation/credentials/retire"}`,
            {
              method: "POST",
              headers: {
                cookie,
                origin: new URL(f.context.baseURL).origin,
                "content-type": "application/json",
              },
              body: JSON.stringify(
                operation === "user"
                  ? { password: f.testUser.password }
                  : { credentialId: f.credentialId },
              ),
            },
          ),
        );
      const access = (token = tokens.access_token) =>
        f.run((ctx) =>
          (protocol === "native" ? requireNativeAccess : requireLegacyAccess)(
            ctx,
            f.tokenOptions,
            {
              headers: new Headers({
                authorization: `DPoP ${token}`,
                dpop: f.proof(signingKey, token),
              }),
              method: "GET",
              url: `${f.context.baseURL}/resource`,
              scopes: ["api:read"],
              resource: fields.resource,
            },
          ),
        );
      const refresh = () =>
        f.exchange({
          grant_type: "refresh_token",
          refresh_token: tokens.refresh_token,
          resource: fields.resource,
        });
      return { ...f, login, redeem, tokens, remove, access, refresh };
    };
    const lifecycleCases = [
      ["native", "user"],
      ["native", "provider"],
      ["legacy", "user"],
      ["legacy", "provider"],
    ] as const;

    it.each(lifecycleCases)(
      "public %s/%s retirement cancels pending codes and revokes token families",
      async (protocol, operation) => {
        const f = await lifecycleFixture(protocol);
        const pending = await f.login();
        await expect(f.access()).resolves.toMatchObject({
          userId: f.testUser.id,
        });
        expect((await f.remove(operation)).status).toBe(200);
        expect(
          await f.context.adapter.findOne({
            model: "deviceAttestationCredential",
            where: [{ field: "id", value: f.credentialId }],
          }),
        ).toMatchObject({ status: "revoked", publicKey: null });
        await expect(f.access()).rejects.toMatchObject({ statusCode: 401 });
        expect((await f.refresh()).status).toBe(400);
        expect((await f.redeem(pending.authorization_code)).status).toBe(400);
        expect(
          await f.context.adapter.count({
            model: "firstPartyTokenFamily",
            where: [{ field: "status", value: "active" }],
          }),
        ).toBe(0);
        expect(
          await f.context.adapter.count({
            model: "firstPartyAuthorization",
            where: [{ field: "status", value: "code-issued" }],
          }),
        ).toBe(0);
        expect(
          await f.context.adapter.count({ model: "oauthRefreshToken" }),
        ).toBe(0);
      },
    );

    it.each(lifecycleCases)(
      "public %s/%s retirement fences a password operation already in flight",
      async (protocol, operation) => {
        const f = await lifecycleFixture(protocol);
        let entered!: () => void;
        let release!: () => void;
        const started = new Promise<void>((resolve) => {
          entered = resolve;
        });
        const blocked = new Promise<void>((resolve) => {
          release = resolve;
        });
        f.observed.onPassword = async () => {
          entered();
          await blocked;
        };
        const pending = f.login().then(
          () => false,
          () => true,
        );
        await started;
        try {
          expect((await f.remove(operation)).status).toBe(200);
        } finally {
          release();
        }
        expect(await pending).toBe(true);
        expect(
          await f.context.adapter.count({
            model: "firstPartyTokenFamily",
            where: [{ field: "status", value: "active" }],
          }),
        ).toBe(0);
        expect(
          await f.context.adapter.count({
            model: "firstPartyAuthorization",
            where: [{ field: "status", value: "code-issued" }],
          }),
        ).toBe(0);
        await expect(f.access()).rejects.toMatchObject({ statusCode: 401 });
      },
    );

    it.each(lifecycleCases)(
      "public %s/%s retirement racing refresh leaves no usable authority",
      async (protocol, operation) => {
        const f = await lifecycleFixture(protocol);
        const [refresh, removal] = await Promise.all([
          f.refresh(),
          f.remove(operation),
        ]);
        expect(removal.status).toBe(200);
        expect([200, 400]).toContain(refresh.status);
        if (refresh.status === 200) {
          const renewed = (await refresh.json()) as { access_token: string };
          await expect(f.access(renewed.access_token)).rejects.toMatchObject({
            statusCode: 401,
          });
        }
        await expect(f.access()).rejects.toMatchObject({ statusCode: 401 });
        expect(
          await f.context.adapter.count({
            model: "firstPartyTokenFamily",
            where: [{ field: "status", value: "active" }],
          }),
        ).toBe(0);
        expect(
          await f.context.adapter.count({ model: "oauthRefreshToken" }),
        ).toBe(0);
      },
    );

    it.each(["native", "legacy"] as const)(
      "honors the host deletion veto before retiring %s authority",
      async (protocol) => {
        const f = await lifecycleFixture(protocol);
        f.observed.vetoDelete = true;
        expect((await f.remove("user")).status).toBe(403);
        expect(
          await f.context.adapter.count({
            model: "user",
            where: [{ field: "id", value: f.testUser.id }],
          }),
        ).toBe(1);
        await expect(f.access()).resolves.toMatchObject({
          userId: f.testUser.id,
        });
        expect((await f.refresh()).status).toBe(200);
      },
    );

    it("returns no context only for absent host references and rejects known-family identity/scope/resource substitutions", async () => {
      const f = await claimsFixture("opaque");
      const login = await f.login();
      expect(
        (await f.exchange(codeFields(login.authorization_code))).status,
      ).toBe(200);
      const family = (
        await f.context.adapter.findMany<{ id: string }>({
          model: "firstPartyTokenFamily",
        })
      )[0]!;
      const user = await f.context.internalAdapter.findUserById(f.testUser.id);
      if (!user) throw new Error("Missing user");
      const info = {
        referenceId: family.id,
        user,
        scopes: ["api:read"],
        resources: [fields.resource],
      };
      expect(
        await f.run(() =>
          resolveFirstPartyTokenContext(f.tokenOptions, {
            ...info,
            referenceId: "old-host-snapshot",
          }),
        ),
      ).toBeNull();
      expect(
        await f.run(() =>
          resolveFirstPartyTokenContext(f.tokenOptions, { user, scopes: [] }),
        ),
      ).toBeNull();
      for (const input of [
        { ...info, user: { ...user, id: "other-user" } },
        { ...info, user: null },
        { ...info, scopes: ["admin"] },
        { ...info, resources: ["https://other.example"] },
      ])
        await expect(
          f.run(() => resolveFirstPartyTokenContext(f.tokenOptions, input)),
        ).rejects.toThrow();
      await expect(
        f.run(() =>
          resolveFirstPartyTokenContext(
            { ...f.tokenOptions, legacyCompatibility: { clients: [] } },
            info,
          ),
        ),
      ).rejects.toThrow();
      expect(
        await f.run(
          async () =>
            await f.options.oauth.customAccessTokenClaims!({
              ...info,
              referenceId: "old-host-snapshot",
            }),
        ),
      ).toEqual({ "urn:example:ordinary": true });
      expect(f.claims.fallbacks).toBe(1);
      // Returned metadata is detached from persistent authority.
      const resolved = await f.run(() =>
        resolveFirstPartyTokenContext(f.tokenOptions, info),
      );
      expect(resolved).not.toBeNull();
      (resolved!.assurance.amr as string[]).push("unproven");
      expect(
        (await f.run(() => resolveFirstPartyTokenContext(f.tokenOptions, info)))
          ?.assurance.amr,
      ).toEqual(["pwd"]);
    });

    it.each(["revoked", "expired", "provider", "user-security"] as const)(
      "does not fall back to host snapshot semantics for a known invalid family: %s",
      async (reason) => {
        const f = await claimsFixture("opaque");
        const login = await f.login();
        expect(
          (await f.exchange(codeFields(login.authorization_code))).status,
        ).toBe(200);
        const family = (
          await f.context.adapter.findMany<{ id: string }>({
            model: "firstPartyTokenFamily",
          })
        )[0]!;
        const user = await f.context.internalAdapter.findUserById(
          f.testUser.id,
        );
        if (!user) throw new Error("Missing user");
        if (reason === "provider")
          await f.context.adapter.update({
            model: "deviceAttestationCredential",
            where: [{ field: "id", value: f.credentialId }],
            update: { status: "revoked" },
          });
        else if (reason === "user-security")
          await f.context.internalAdapter.updateUser(f.testUser.id, {
            emailVerified: !user.emailVerified,
          });
        else
          await f.context.adapter.update({
            model: "firstPartyTokenFamily",
            where: [{ field: "id", value: family.id }],
            update:
              reason === "revoked"
                ? { status: "revoked" }
                : { expiresAt: new Date(0) },
          });
        await expect(
          f.run(
            async () =>
              await f.options.oauth.customAccessTokenClaims!({
                referenceId: family.id,
                user,
                scopes: ["api:read"],
                resources: [fields.resource],
              }),
          ),
        ).rejects.toThrow();
        expect(f.claims.fallbacks).toBe(0);
      },
    );

    it("resolves the uncommitted JWT family and rolls token ownership back if the host claims callback fails", async () => {
      const f = await claimsFixture("jwt");
      const login = await f.login();
      f.claims.fail = true;
      expect(
        (await f.exchange(codeFields(login.authorization_code))).status,
      ).toBe(500);
      expect(f.claims.contexts).toHaveLength(1);
      expect(f.claims.fallbacks).toBe(0);
      expect(
        await f.context.adapter.count({ model: "firstPartyTokenFamily" }),
      ).toBe(0);
      expect(await f.context.adapter.count({ model: "firstPartyAccess" })).toBe(
        0,
      );
      expect(
        await f.context.adapter.count({ model: "oauthRefreshToken" }),
      ).toBe(0);
      expect(
        await f.context.adapter.findMany({
          model: "deviceAttestationCredential",
        }),
      ).toMatchObject([{ userId: null }]);
      f.claims.fail = false;
      expect(
        (await f.exchange(codeFields(login.authorization_code))).status,
      ).toBe(200);
    });

    const acrFixture = () =>
      fixture(database, true, true, true, false, true, {
        ...defaultPolicy,
        passwordAcrValues: [passwordAcr, "urn:example:password-alias"],
      });

    it("binds an explicitly configured password ACR to fresh legacy step-up authentication and its token family", async () => {
      const f = await acrFixture();
      const response = await f.send({
        ...fields,
        intent: "step_up",
        acr_values: `urn:example:unknown ${passwordAcr}`,
        email: f.testUser.email,
        password: f.testUser.password,
        device_attestation: await f.evidence(),
      });
      expect(response.status).toBe(200);
      const code = (await response.json()) as { authorization_code: string };
      expect(code.authorization_code).toMatch(/^fpl1_/);
      const exchange = await f.exchange(codeFields(code.authorization_code));
      expect(exchange.status).toBe(200);
      const tokens = (await exchange.json()) as {
        refresh_token: string;
        access_token: string;
      };
      expect(
        await f.context.adapter.findMany({ model: "firstPartyTokenFamily" }),
      ).toMatchObject([
        {
          assurance: {
            acr: passwordAcr,
            amr: ["pwd"],
            profile: "legacy-v1",
            challengeProof: false,
          },
        },
      ]);
      const input = () => ({
        headers: new Headers({
          authorization: `DPoP ${tokens.access_token}`,
          dpop: f.proof(signingKey, tokens.access_token),
        }),
        method: "GET",
        url: `${f.context.baseURL}/resource`,
        scopes: ["api:read"],
        resource: fields.resource,
      });
      await expect(
        f.run((ctx) => requireLegacyAccess(ctx, f.tokenOptions, input())),
      ).resolves.toBeDefined();
      f.options.policy.passwordAcrValues = [];
      await expect(
        f.run((ctx) => requireLegacyAccess(ctx, f.tokenOptions, input())),
      ).rejects.toThrow();
      expect(
        (
          await f.exchange({
            grant_type: "refresh_token",
            refresh_token: tokens.refresh_token,
            resource: fields.resource,
          })
        ).status,
      ).toBe(400);
    });

    it("retains the initial password ACR when a continuation omits it and rejects changes without consuming the handle", async () => {
      const f = await acrFixture();
      const initial = await f.send({
        ...fields,
        acr_values: passwordAcr,
        device_attestation: await f.evidence(),
      });
      const pending = (await initial.json()) as { auth_session: string };
      for (const override of [
        { acr_values: "urn:example:password-alias" },
        { acr_values: "urn:example:require-mfa" },
        { intent: "create_account" },
      ]) {
        const response = await f.send({
          ...fields,
          auth_session: pending.auth_session,
          email: f.testUser.email,
          password: f.testUser.password,
          ...override,
        });
        expect(response.status).toBe(400);
      }
      expect(f.observed.passwordCalls).toBe(0);
      expect(f.observed.createOTPCalls).toBe(0);
      const response = await f.send({
        ...fields,
        auth_session: pending.auth_session,
        email: f.testUser.email,
        password: f.testUser.password,
      });
      expect(response.status).toBe(200);
      const code = (await response.json()) as { authorization_code: string };
      expect(
        (await f.exchange(codeFields(code.authorization_code))).status,
      ).toBe(200);
      expect(
        await f.context.adapter.findMany({ model: "firstPartyTokenFamily" }),
      ).toMatchObject([{ assurance: { acr: passwordAcr, amr: ["pwd"] } }]);
    });

    it("does not add an ACR to an existing unqualified continuation or an OTP setup flow", async () => {
      const f = await acrFixture();
      const initial = await f.send({
        ...fields,
        device_attestation: await f.evidence(),
      });
      const pending = (await initial.json()) as { auth_session: string };
      expect(
        (
          await f.send({
            ...fields,
            auth_session: pending.auth_session,
            acr_values: passwordAcr,
            password: f.testUser.password,
          })
        ).status,
      ).toBe(400);
      expect(
        (
          await f.send({
            ...fields,
            intent: "create_account",
            acr_values: passwordAcr,
            device_attestation: await f.evidence(),
          })
        ).status,
      ).toBe(400);
      expect(f.observed.passwordCalls).toBe(0);
      expect(f.observed.createOTPCalls).toBe(0);
      const response = await f.send({
        ...fields,
        auth_session: pending.auth_session,
        email: f.testUser.email,
        password: f.testUser.password,
      });
      expect(response.status).toBe(200);
      const authorizations = await f.context.adapter.findMany<{
        assurance: Record<string, unknown>;
      }>({ model: "firstPartyAuthorization" });
      expect(authorizations).toHaveLength(1);
      expect(authorizations[0]!.assurance).not.toHaveProperty("acr");
    });

    it("rechecks the configured ACR after password hooks before authorizing", async () => {
      const f = await acrFixture();
      f.observed.onPassword = () => {
        f.options.policy.passwordAcrValues = [];
        return Promise.resolve();
      };
      const response = await f.send({
        ...fields,
        acr_values: passwordAcr,
        email: f.testUser.email,
        password: f.testUser.password,
        device_attestation: await f.evidence(),
      });
      expect(response.status).toBe(400);
      expect(
        await f.context.adapter.count({ model: "firstPartyAuthorization" }),
      ).toBe(0);
      expect(
        await f.context.adapter.count({ model: "firstPartyTokenFamily" }),
      ).toBe(0);
    });

    it("rolls back redemption when the password ACR is removed after code issuance", async () => {
      const f = await acrFixture();
      const response = await f.send({
        ...fields,
        acr_values: passwordAcr,
        email: f.testUser.email,
        password: f.testUser.password,
        device_attestation: await f.evidence(),
      });
      expect(response.status).toBe(200);
      const code = (await response.json()) as { authorization_code: string };
      f.options.policy.passwordAcrValues = [];
      expect(
        (await f.exchange(codeFields(code.authorization_code))).status,
      ).toBe(400);
      expect(
        await f.context.adapter.count({ model: "firstPartyTokenFamily" }),
      ).toBe(0);
      expect(
        await f.context.adapter.count({ model: "oauthRefreshToken" }),
      ).toBe(0);
      expect(
        await f.context.adapter.findMany({
          model: "deviceAttestationCredential",
        }),
      ).toMatchObject([{ userId: null }]);
    });

    it("rejects malformed password ACR policy at public composition", async () => {
      const f = await acrFixture();
      for (const passwordAcrValues of [
        [""],
        ["two labels"],
        ["same", "same"],
        ["x".repeat(257)],
        Array.from({ length: 17 }, (_, i) => `acr:${i}`),
      ])
        expect(() =>
          createNativeFirstPartyPlugin({
            ...f.tokenOptions,
            legacyCompatibility: {
              clients: [{ ...defaultPolicy, passwordAcrValues }],
            },
          }),
        ).toThrow();
    });

    const prepareProfile = async (secondary = false) => {
      const f = await fixture(database, true, true, true, secondary);
      const email = "legacy-setup@example.test";
      const created = await f.create({ intent: "create_account", email });
      await f.requestOTP(created.authSession, { email });
      const verified = await f.verifyOTP(created.authSession, { email });
      if (
        verified.kind !== "verified" ||
        verified.session.step !== "profile_password"
      )
        throw new Error("Missing verified profile step");
      return { ...f, created, verified: verified.session, email };
    };

    const prepareStepUp = async (enabled = true, exchanged = true) => {
      const f = await fixture(database, true, true, false, false, true, {
        ...defaultPolicy,
        passwordAcrValues: [passwordAcr],
        allowPasswordReauthentication: enabled,
      });
      const login = await f.login();
      if (exchanged)
        expect(
          (await f.exchange(codeFields(login.authorization_code))).status,
        ).toBe(200);
      const original = (
        await f.context.adapter.findMany<LegacySession>({
          model: "firstPartyLegacySession",
        })
      )[0]!;
      const nextVerifier = "w".repeat(43);
      const request = {
        ...fields,
        auth_session: login.auth_session,
        intent: "step_up",
        acr_values: passwordAcr,
        email: f.testUser.email,
        password: f.testUser.password,
        code_challenge: createHash("sha256")
          .update(nextVerifier)
          .digest("base64url"),
      };
      return {
        ...f,
        original,
        request,
        nextVerifier,
        initialCode: login.authorization_code,
      };
    };

    it("reauthenticates a completed legacy handle with new PKCE, the same subject and unchanged expiry", async () => {
      const f = await prepareStepUp();
      const response = await f.send(f.request);
      expect(response.status).toBe(200);
      const result = (await response.json()) as {
        authorization_code: string;
        auth_session: string;
      };
      expect(result.auth_session).toBe(f.request.auth_session);
      expect(result.authorization_code).not.toBe(f.initialCode);
      // A fresh authorization does not rewrite the consumed code or its family.
      const authorizations = await f.context.adapter.findMany<{
        status: string;
        codeChallenge: string;
        userId: string;
      }>({ model: "firstPartyAuthorization" });
      expect(authorizations).toHaveLength(2);
      expect(authorizations).toContainEqual(
        expect.objectContaining({
          status: "consumed",
          codeChallenge: fields.code_challenge,
        }),
      );
      expect(authorizations).toContainEqual(
        expect.objectContaining({
          status: "code-issued",
          codeChallenge: f.request.code_challenge,
          userId: f.testUser.id,
        }),
      );
      expect(
        (await f.exchange(codeFields(result.authorization_code))).status,
      ).toBe(400);
      expect(
        (
          await f.exchange({
            ...codeFields(result.authorization_code),
            code_verifier: f.nextVerifier,
          })
        ).status,
      ).toBe(200);
      const stored = (
        await f.context.adapter.findMany<LegacySession>({
          model: "firstPartyLegacySession",
        })
      )[0]!;
      expect(stored.expiresAt).toEqual(f.original.expiresAt);
      expect(stored.evidenceVerifiedAt).toEqual(f.original.evidenceVerifiedAt);
      expect(stored.authorizationId).not.toBe(f.original.authorizationId);
      expect(
        await f.context.adapter.findMany({ model: "firstPartyTokenFamily" }),
      ).toMatchObject([
        { userId: f.testUser.id, assurance: { profile: "legacy-v1" } },
        {
          userId: f.testUser.id,
          assurance: {
            profile: "legacy-v1",
            acr: passwordAcr,
            amr: ["pwd"],
            challengeProof: false,
          },
        },
      ]);
      expect(await f.context.adapter.count({ model: "session" })).toBe(0);
    });

    it.each(["password", "rate-limit"])(
      "keeps the completed handle retryable after a definite reauthentication rejection: %s",
      async (reason) => {
        const f = await prepareStepUp();
        f.observed.passwordLimit = reason === "rate-limit";
        const rejected = await f.send({
          ...f.request,
          password:
            reason === "password" ? "wrong-password" : f.testUser.password,
        });
        expect(rejected.status).toBe(reason === "password" ? 200 : 429);
        if (reason === "password")
          expect(await rejected.json()).toMatchObject({
            next_step: "email_password",
            auth_session: f.request.auth_session,
          });
        expect(
          await f.context.adapter.findMany({
            model: "firstPartyLegacySession",
          }),
        ).toMatchObject([
          {
            status: "code-issued",
            bindingHash: f.original.bindingHash,
            authorizationId: f.original.authorizationId,
            operationId: null,
          },
        ]);
        expect(
          await f.context.adapter.count({ model: "firstPartyAuthorization" }),
        ).toBe(1);
        f.observed.passwordLimit = false;
        const response = await f.send(f.request);
        expect(response.status).toBe(200);
        expect(await response.json()).toHaveProperty("authorization_code");
      },
    );

    it("rejects retained-handle step-up unless explicitly enabled and already redeemed", async () => {
      for (const [enabled, exchanged] of [
        [false, true],
        [true, false],
      ] as const) {
        const f = await prepareStepUp(enabled, exchanged);
        const calls = f.observed.passwordCalls;
        expect((await f.send(f.request)).status).toBe(400);
        expect(f.observed.passwordCalls).toBe(calls);
      }
    });

    it("rejects reauthentication that changes the subject, device or immutable OAuth binding", async () => {
      const f = await prepareStepUp();
      const calls = f.observed.passwordCalls;
      for (const mutation of [
        { email: "other@example.test" },
        { dpop_jkt: "k".repeat(43) },
        { scope: "api:read" },
        { resource: undefined },
        { redirect_uri: "example:/other" },
        { intent: "authenticate" },
        { new_password: "irrelevant" },
        { verification_code: "123456" },
      ])
        expect((await f.send({ ...f.request, ...mutation })).status).toBe(400);
      expect(f.observed.passwordCalls).toBe(calls);
      expect(
        await f.context.adapter.count({ model: "firstPartyAuthorization" }),
      ).toBe(1);
    });

    it.each(["family", "provider", "expiry", "policy"] as const)(
      "rejects successful reauthentication if its authority changes during password work: %s",
      async (reason) => {
        const f = await prepareStepUp();
        f.observed.onPassword = async () => {
          if (reason === "policy")
            f.options.policy.allowPasswordReauthentication = false;
          else if (reason === "family")
            await f.context.adapter.updateMany({
              model: "firstPartyTokenFamily",
              where: [{ field: "clientId", value: "mobile" }],
              update: { status: "revoked" },
            });
          else if (reason === "provider")
            await f.context.adapter.update({
              model: "deviceAttestationCredential",
              where: [{ field: "id", value: f.credentialId }],
              update: { status: "revoked" },
            });
          else
            await f.context.adapter.update({
              model: "firstPartyLegacySession",
              where: [{ field: "id", value: f.original.id }],
              update: { expiresAt: new Date(0) },
            });
        };
        expect((await f.send(f.request)).status).toBe(400);
        expect(
          await f.context.adapter.count({ model: "firstPartyAuthorization" }),
        ).toBe(1);
        expect(
          await f.context.adapter.count({ model: "firstPartyTokenFamily" }),
        ).toBe(1);
      },
    );

    it("reserves retained-handle reauthentication before password work so concurrent requests cannot duplicate it", async () => {
      const f = await prepareStepUp();
      let entered!: () => void;
      let release!: () => void;
      const ready = new Promise<void>((resolve) => {
        entered = resolve;
      });
      const pending = new Promise<void>((resolve) => {
        release = resolve;
      });
      f.observed.onPassword = async () => {
        entered();
        await pending;
      };
      const first = f.send(f.request);
      try {
        await ready;
        expect((await f.send(f.request)).status).toBe(400);
      } finally {
        release();
      }
      expect((await first).status).toBe(200);
      expect(
        await f.context.adapter.count({ model: "firstPartyAuthorization" }),
      ).toBe(2);
    });

    it("rolls reauthentication authorization storage back without altering the prior code or family", async () => {
      const f = await prepareStepUp();
      const previous = await f.context.adapter.findMany({
        model: "firstPartyAuthorization",
      });
      const transaction = f.context.adapter.transaction;
      f.context.adapter.transaction = async (operation) =>
        transaction((adapter) =>
          operation({
            ...adapter,
            create: async (input) => {
              if (input.model === "firstPartyAuthorization")
                throw new Error("injected reauthentication storage failure");
              return adapter.create(input);
            },
          }),
        );
      await expect(
        f.run((ctx) =>
          reauthenticateLegacyPassword(
            ctx,
            f.tokenOptions,
            f.options.policy,
            parseLegacyChallenge(f.request, f.options.policy).request,
          ),
        ),
      ).rejects.toThrow("injected reauthentication storage failure");
      expect(
        await f.context.adapter.findMany({ model: "firstPartyAuthorization" }),
      ).toEqual(previous);
      expect(
        await f.context.adapter.count({ model: "firstPartyTokenFamily" }),
      ).toBe(1);
      expect(
        await f.context.adapter.findMany({ model: "firstPartyLegacySession" }),
      ).toMatchObject([
        { status: "processing", authorizationId: f.original.authorizationId },
      ]);
      expect(await f.context.adapter.count({ model: "session" })).toBe(0);
    });

    it("uses the public opt-in adapter for legacy password login, refresh and explicitly legacy access", async () => {
      const f = await fixture(database, true, true, false, false, true);
      const rejected = await f.send({
        ...fields,
        email: f.testUser.email,
        password: "incorrect-password",
        device_attestation: await f.evidence(),
      });
      expect(rejected.status).toBe(200);
      expect(rejected.headers.get("cache-control")).toBe("no-store");
      expect(rejected.headers.has("set-cookie")).toBe(false);
      const pending = (await rejected.json()) as { auth_session: string };
      expect(pending).toMatchObject({
        error: "insufficient_authorization",
        next_step: "email_password",
        email: f.testUser.email,
      });
      const response = await f.send({
        ...fields,
        email: undefined,
        login_hint: f.testUser.email,
        password: f.testUser.password,
        auth_session: pending.auth_session,
      });
      expect(response.status).toBe(200);
      const code = (await response.json()) as {
        authorization_code: string;
        auth_session: string;
      };
      expect(code.auth_session).toBe(pending.auth_session);
      const exchange = await f.exchange(codeFields(code.authorization_code));
      expect(exchange.status).toBe(200);
      const tokens = (await exchange.json()) as {
        access_token: string;
        refresh_token: string;
      };
      const accessInput = () => ({
        headers: new Headers({
          authorization: `DPoP ${tokens.access_token}`,
          dpop: f.proof(signingKey, tokens.access_token),
        }),
        method: "GET",
        url: `${f.context.baseURL}/resource`,
        resource: fields.resource,
        scopes: ["api:read"],
      });
      await expect(
        f.run((ctx) => requireNativeAccess(ctx, f.tokenOptions, accessInput())),
      ).rejects.toMatchObject({ statusCode: 401 });
      expect(
        await f.run((ctx) =>
          requireLegacyAccess(ctx, f.tokenOptions, accessInput()),
        ),
      ).toMatchObject({
        userId: f.testUser.id,
        assurance: { profile: "legacy-v1", challengeProof: false },
      });
      await expect(
        f.run((ctx) =>
          requireLegacyAccess(ctx, f.tokenOptions, {
            ...accessInput(),
            headers: new Headers({
              authorization: `DPoP ${tokens.access_token}`,
            }),
          }),
        ),
      ).rejects.toMatchObject({ statusCode: 401 });
      const disabled = { ...f.tokenOptions };
      delete disabled.legacyCompatibility;
      await expect(
        f.run((ctx) => requireLegacyAccess(ctx, disabled, accessInput())),
      ).rejects.toMatchObject({ statusCode: 401 });
      expect(
        (
          await f.exchange({
            grant_type: "refresh_token",
            refresh_token: tokens.refresh_token,
            resource: fields.resource,
          })
        ).status,
      ).toBe(200);
      expect(await f.context.adapter.count({ model: "session" })).toBe(0);
    });

    it("preserves the submitted account-creation envelopes through OTP, profile setup and code exchange", async () => {
      const f = await fixture(database, true, true, true, false, true);
      const email = "wire-signup@example.test";
      const initial = await f.send({
        ...fields,
        intent: "create_account",
        email,
        device_attestation: await f.evidence(),
      });
      expect(initial.status).toBe(200);
      const state = (await initial.json()) as { auth_session: string };
      expect(state).toMatchObject({
        next_step: "email_verification",
        email,
        error: "insufficient_authorization",
      });
      const continuation = {
        ...fields,
        intent: "create_account",
        email: undefined,
        auth_session: state.auth_session,
      };
      for (let index = 0; index < 2; index++)
        expect(await (await f.send(continuation)).json()).toMatchObject({
          auth_session: state.auth_session,
          next_step: "email_verification",
        });
      expect(f.observed.routed).toHaveLength(1);
      expect(
        await (
          await f.send({ ...continuation, verification_code: "incorrect" })
        ).json(),
      ).toMatchObject({ next_step: "email_verification" });
      const verified = await f.send({
        ...continuation,
        verification_code: f.observed.routed[0]!.otp,
      });
      expect(verified.status).toBe(200);
      expect(await verified.json()).toMatchObject({
        auth_session: state.auth_session,
        next_step: "profile_password",
        email,
      });
      expect(
        await (
          await f.send({ ...continuation, display_name: "Wire User" })
        ).json(),
      ).toMatchObject({ next_step: "profile_password" });
      const setup = await f.send({
        ...continuation,
        display_name: "Wire User",
        new_password: "verified-wire-password",
      });
      expect(setup.status).toBe(200);
      expect(setup.headers.has("set-cookie")).toBe(false);
      const code = (await setup.json()) as {
        authorization_code: string;
        auth_session: string;
      };
      expect(code.auth_session).toBe(state.auth_session);
      expect(
        (await f.exchange(codeFields(code.authorization_code))).status,
      ).toBe(200);
      expect(
        await f.context.adapter.findMany({
          model: "user",
          where: [{ field: "email", value: email }],
        }),
      ).toMatchObject([{ name: "Wire User", emailVerified: true }]);
      expect(await f.context.adapter.count({ model: "session" })).toBe(0);
    });

    it("waits for an email before legacy OTP delivery and never resends on a poll", async () => {
      const f = await fixture(database, true, true, true, false, true);
      const initial = await f.send({
        ...fields,
        email: undefined,
        intent: "create_account",
        device_attestation: await f.evidence(),
      });
      const state = (await initial.json()) as { auth_session: string };
      expect(initial.status).toBe(200);
      expect(f.observed.routed).toHaveLength(0);
      const request = {
        ...fields,
        intent: "create_account",
        auth_session: state.auth_session,
        email: f.testUser.email,
      };
      expect((await f.send(request)).status).toBe(200);
      expect((await f.send(request)).status).toBe(200);
      expect(f.observed.routed).toHaveLength(1);
      expect(
        (await f.send({ ...request, email: "different@example.test" })).status,
      ).toBe(400);
    });

    it("keeps legacy traffic disabled unless explicitly configured and never downgrades mixed/native requests", async () => {
      const disabled = await fixture(database, false, true, true, false, true);
      expect(
        (
          await disabled.send({
            ...fields,
            password: disabled.testUser.password,
            device_attestation: await disabled.evidence(),
          })
        ).status,
      ).toBe(415);
      expect(disabled.observed.passwordCalls).toBe(0);
      expect(disabled.observed.routed).toHaveLength(0);
      const f = await fixture(database, true, true, true, false, true);
      const request = {
        ...fields,
        email: f.testUser.email,
        password: f.testUser.password,
        device_attestation: await f.evidence(),
      };
      expect(
        (await f.send(request, "application/json", "bad-proof")).status,
      ).toBe(400);
      expect(
        (await f.send({ ...request, profile: FIRST_PARTY_PROFILE })).status,
      ).toBe(400);
      for (const proof of [undefined, "bad-proof"])
        expect(
          (
            await f.send(
              {
                profile: FIRST_PARTY_PROFILE,
                client_id: "mobile",
                auth_session: "fpls1_" + "x".repeat(43),
                step_id: "wrong",
                response: JSON.stringify({
                  kind: "password",
                  email: f.testUser.email,
                  password: f.testUser.password,
                }),
              },
              "application/x-www-form-urlencoded",
              proof,
            )
          ).status,
        ).toBe(400);
      expect(f.observed.passwordCalls).toBe(0);
      expect(f.observed.routed).toHaveLength(0);
      expect(
        await f.context.adapter.count({ model: "firstPartyLegacySession" }),
      ).toBe(0);
      expect((await f.send(request)).status).toBe(200);
    });

    it("validates legacy continuation bindings and provider state before method work", async () => {
      const f = await fixture(database, true, true, true, false, true);
      const initial = await f.send({
        ...fields,
        email: f.testUser.email,
        device_attestation: await f.evidence(),
      });
      const state = (await initial.json()) as { auth_session: string };
      const request = {
        ...fields,
        auth_session: state.auth_session,
        email: f.testUser.email,
        password: f.testUser.password,
      };
      expect(
        (await f.send({ ...request, dpop_jkt: "z".repeat(43) })).status,
      ).toBe(400);
      expect(
        (await f.send({ ...request, device_attestation: await f.evidence() }))
          .status,
      ).toBe(400);
      expect(
        (await f.send({ ...request, auth_session: "x".repeat(43) })).status,
      ).toBe(400);
      await f.context.adapter.update({
        model: "deviceAttestationCredential",
        where: [{ field: "id", value: f.credentialId }],
        update: { status: "revoked" },
      });
      expect((await f.send(request)).status).toBe(400);
      expect(f.observed.passwordCalls).toBe(0);
      expect(
        await f.context.adapter.count({ model: "firstPartyAuthorization" }),
      ).toBe(0);
    });

    it("rejects an expired legacy handle before password work without creating replacement authority", async () => {
      const f = await fixture(database, true, true, true, false, true);
      const initial = await f.send({
        ...fields,
        email: f.testUser.email,
        device_attestation: await f.evidence(),
      });
      expect(initial.status).toBe(200);
      const state = (await initial.json()) as { auth_session: string };
      await f.context.adapter.updateMany({
        model: "firstPartyLegacySession",
        where: [{ field: "clientId", value: "mobile" }],
        update: { expiresAt: new Date(0) },
      });
      const response = await f.send({
        ...fields,
        auth_session: state.auth_session,
        email: f.testUser.email,
        password: f.testUser.password,
      });
      expect(response.status).toBe(400);
      expect(f.observed.passwordCalls).toBe(0);
      expect(
        await f.context.adapter.count({ model: "firstPartyLegacySession" }),
      ).toBe(1);
      expect(
        await f.context.adapter.count({ model: "firstPartyAuthorization" }),
      ).toBe(0);
      expect(
        await f.context.adapter.count({ model: "firstPartyTokenFamily" }),
      ).toBe(0);
    });

    it("honors low-level attestation rate limits without leaking hook cookies or private messages", async () => {
      const f = await fixture(database, true, true, true, false, true);
      f.observed.limitEvidence = true;
      const response = await f.send({
        ...fields,
        email: f.testUser.email,
        password: f.testUser.password,
        device_attestation: await f.evidence(),
      });
      expect(response.status).toBe(429);
      expect(response.headers.get("retry-after")).toBe("7");
      expect(response.headers.has("set-cookie")).toBe(false);
      expect(await response.json()).toEqual({
        error: "temporarily_unavailable",
      });
      expect(f.observed.passwordCalls).toBe(0);
      expect(
        await f.context.adapter.count({ model: "firstPartyLegacySession" }),
      ).toBe(0);
    });

    it.each([false, true])(
      "completes legacy verified profile setup with hook-aware APIs and proof-bound tokens (cache: %s)",
      async (secondary) => {
        const f = await prepareProfile(secondary);
        if (secondary)
          f.observed.onProfile = async (ctx) => {
            for (let index = 0; index < 2; index++)
              await ctx.context.internalAdapter.createSession(
                f.verified.verifiedUserId!,
                false,
                undefined,
                undefined,
                { deferSecondaryStorageWrites: true },
              );
          };
        if (secondary)
          f.observed.onPassword = async (ctx) => {
            for (let index = 0; index < 2; index++)
              await ctx.context.internalAdapter.createSession(
                f.verified.verifiedUserId!,
              );
          };
        const result = await f.setupProfile(f.created.authSession);
        expect(f.observed.profileCalls).toBe(1);
        expect(f.observed.setupCalls).toBe(1);
        expect(f.observed.passwordCalls).toBe(1);
        expect(
          await f.context.internalAdapter.findUserById(
            f.verified.verifiedUserId!,
          ),
        ).toMatchObject({
          name: "New User",
          email: f.email,
          emailVerified: true,
        });
        expect(await f.context.adapter.count({ model: "session" })).toBe(0);
        expect(
          [...f.secondary.values()].filter((entry) =>
            entry.value.includes('"session":'),
          ),
        ).toHaveLength(0);
        expect(
          f.secondary.has(`active-sessions-${f.verified.verifiedUserId!}`),
        ).toBe(false);
        const authorization = await f.context.adapter.findMany({
          model: "firstPartyAuthorization",
        });
        expect(authorization).toMatchObject([
          {
            assurance: {
              profile: "legacy-v1",
              challengeProof: false,
              amr: ["otp", "pwd"],
            },
            authenticatedAt: f.verified.authenticatedAt,
          },
        ]);
        expect(JSON.stringify(authorization)).not.toContain(
          "new-verified-password",
        );
        const exchanged = await f.exchange(
          codeFields(result.authorizationCode),
        );
        expect(exchanged.status).toBe(200);
        const tokens = (await exchanged.json()) as {
          refresh_token: string;
          token_type: string;
        };
        expect(tokens.token_type).toBe("DPoP");
        expect(
          (
            await f.exchange({
              grant_type: "refresh_token",
              refresh_token: tokens.refresh_token,
              resource: fields.resource,
            })
          ).status,
        ).toBe(200);
        await expect(f.setupProfile(f.created.authSession)).rejects.toThrow();
      },
    );

    it("isolates setup from ambient authentication and returns no Better Auth session cookie", async () => {
      const f = await prepareProfile();
      const signedIn = await f.auth.api.signInEmail({
        body: { email: f.testUser.email, password: f.testUser.password },
        asResponse: true,
      });
      const actor = (await signedIn.json()) as { token: string };
      const cookies = signedIn.headers
        .getSetCookie()
        .map((cookie) => cookie.split(";", 1)[0]!)
        .join("; ");
      f.observed.onProfile = (ctx) => {
        expect(ctx.context.session?.user.id).toBe(f.verified.verifiedUserId);
        expect(ctx.headers?.get("authorization")).toBeNull();
        expect(ctx.headers?.get("dpop")).toBeNull();
        return Promise.resolve();
      };
      const response = await f.runHTTP(
        (ctx) =>
          submitLegacyProfile(ctx, f.options, {
            ...fields,
            email: undefined,
            auth_session: f.created.authSession,
            display_name: "Isolated User",
            new_password: "new-verified-password",
          }),
        new Headers({
          cookie: cookies,
          authorization: `Bearer ${actor.token}`,
          dpop: "ambient-proof",
        }),
      );
      expect(response.status).toBe(200);
      expect(response.headers.has("set-cookie")).toBe(false);
      const body = (await response.json()) as {
        kind: string;
        authorizationCode: string;
      };
      expect(Object.keys(body).sort()).toEqual(["authorizationCode", "kind"]);
      expect(
        (await f.context.internalAdapter.findSession(actor.token))?.user.id,
      ).toBe(f.testUser.id);
      expect(await f.context.adapter.count({ model: "session" })).toBe(1);
      expect(
        (await f.context.internalAdapter.findUserById(f.testUser.id))?.name,
      ).toBe(f.testUser.name);
      expect(
        (await f.exchange(codeFields(body.authorizationCode))).status,
      ).toBe(200);
    });

    it("rolls back profile edits after a rejected password and accepts a corrected retry", async () => {
      const f = await prepareProfile();
      const before = await f.context.internalAdapter.findUserById(
        f.verified.verifiedUserId!,
      );
      await expect(
        f.setupProfile(f.created.authSession, { new_password: "short" }),
      ).rejects.toMatchObject({ statusCode: 400 });
      expect(
        await f.context.internalAdapter.findUserById(
          f.verified.verifiedUserId!,
        ),
      ).toEqual(before);
      expect(
        await f.context.internalAdapter.findCredentialAccount(
          f.verified.verifiedUserId!,
        ),
      ).toBeFalsy();
      expect(await f.context.adapter.count({ model: "session" })).toBe(0);
      expect(
        await f.context.adapter.count({ model: "firstPartyAuthorization" }),
      ).toBe(0);
      expect(
        await f.context.adapter.findMany({ model: "firstPartyLegacySession" }),
      ).toMatchObject([{ status: "ready", step: "profile_password" }]);
      expect(
        (await f.setupProfile(f.created.authSession)).authorizationCode,
      ).toMatch(/^fpl1_/);
    });

    it("honors host password-setup policy and does not accept fake success", async () => {
      const f = await prepareProfile();
      f.observed.fakeProfile = true;
      await expect(f.setupProfile(f.created.authSession)).rejects.toMatchObject(
        { statusCode: 400 },
      );
      expect(f.observed.setupCalls).toBe(0);
      f.observed.fakeProfile = false;
      f.observed.denySetup = true;
      await expect(f.setupProfile(f.created.authSession)).rejects.toMatchObject(
        { statusCode: 403 },
      );
      expect(f.observed.passwordCalls).toBe(0);
      f.observed.denySetup = false;
      f.observed.fakeSetup = true;
      await expect(f.setupProfile(f.created.authSession)).rejects.toMatchObject(
        { statusCode: 400 },
      );
      expect(
        await f.context.internalAdapter.findCredentialAccount(
          f.verified.verifiedUserId!,
        ),
      ).toBeFalsy();
      expect(await f.context.adapter.count({ model: "session" })).toBe(0);
      expect(
        await f.context.adapter.count({ model: "firstPartyAuthorization" }),
      ).toBe(0);
      f.observed.fakeSetup = false;
      expect((await f.setupProfile(f.created.authSession)).kind).toBe(
        "authorized",
      );
    });

    it("rolls back rate-limited setup and preserves the verified factor for an explicit retry", async () => {
      const f = await prepareProfile();
      f.observed.passwordLimit = true;
      await expect(f.setupProfile(f.created.authSession)).rejects.toMatchObject(
        { statusCode: 429 },
      );
      expect(
        await f.context.internalAdapter.findCredentialAccount(
          f.verified.verifiedUserId!,
        ),
      ).toBeFalsy();
      expect(await f.context.adapter.count({ model: "session" })).toBe(0);
      expect(
        await f.context.adapter.findMany({ model: "firstPartyLegacySession" }),
      ).toMatchObject([
        {
          status: "ready",
          step: "profile_password",
          userSecurityHash: f.verified.userSecurityHash,
        },
      ]);
      f.observed.passwordLimit = false;
      expect((await f.setupProfile(f.created.authSession)).kind).toBe(
        "authorized",
      );
    });

    it("rejects stale OTP authority before profile work and recipient substitution before reservation", async () => {
      const f = await prepareProfile();
      await expect(
        f.setupProfile(f.created.authSession, { email: f.testUser.email }),
      ).rejects.toMatchObject({ statusCode: 400 });
      expect(
        await f.context.adapter.findMany({ model: "firstPartyLegacySession" }),
      ).toMatchObject([{ status: "ready", step: "profile_password" }]);
      await f.context.internalAdapter.updateUser(f.verified.verifiedUserId!, {
        twoFactorEnabled: true,
      });
      await expect(f.setupProfile(f.created.authSession)).rejects.toMatchObject(
        { statusCode: 400 },
      );
      expect(f.observed.profileCalls).toBe(0);
      expect(f.observed.setupCalls).toBe(0);
      expect(await f.context.adapter.count({ model: "session" })).toBe(0);
      expect(
        await f.context.adapter.count({ model: "firstPartyAuthorization" }),
      ).toBe(0);
    });

    it("does not resnapshot an unrelated security change from a profile hook", async () => {
      const f = await prepareProfile();
      f.observed.onProfile = async (ctx) => {
        await ctx.context.internalAdapter.updateUser(
          f.verified.verifiedUserId!,
          { twoFactorEnabled: true },
        );
      };
      await expect(f.setupProfile(f.created.authSession)).rejects.toMatchObject(
        { statusCode: 400 },
      );
      expect(f.observed.profileCalls).toBe(1);
      expect(f.observed.setupCalls).toBe(0);
      expect(
        await f.context.internalAdapter.findCredentialAccount(
          f.verified.verifiedUserId!,
        ),
      ).toBeFalsy();
      expect(await f.context.adapter.count({ model: "session" })).toBe(0);
      expect(
        await f.context.adapter.count({ model: "firstPartyAuthorization" }),
      ).toBe(0);
    });

    it("allows only one concurrent profile completion for the same legacy handle", async () => {
      const f = await prepareProfile();
      const attempts = await Promise.allSettled([
        f.setupProfile(f.created.authSession),
        f.setupProfile(f.created.authSession),
      ]);
      expect(
        attempts.filter((result) => result.status === "fulfilled"),
      ).toHaveLength(1);
      expect(f.observed.setupCalls).toBe(1);
      expect(
        await f.context.adapter.count({ model: "firstPartyAuthorization" }),
      ).toBe(1);
      expect(await f.context.adapter.count({ model: "session" })).toBe(0);
    });

    it("rolls profile/password writes back with terminal code storage and removes cached sessions", async () => {
      const f = await prepareProfile(true);
      const before = await f.context.internalAdapter.findUserById(
        f.verified.verifiedUserId!,
      );
      const transaction = f.context.adapter.transaction;
      f.context.adapter.transaction = async (operation) =>
        transaction((adapter) =>
          operation({
            ...adapter,
            create: async (input) => {
              if (input.model === "firstPartyAuthorization")
                throw new Error("injected profile code failure");
              return adapter.create(input);
            },
          }),
        );
      await expect(f.setupProfile(f.created.authSession)).rejects.toThrow();
      expect(f.observed.setupCalls).toBe(1);
      expect(f.observed.passwordCalls).toBe(1);
      expect(
        await f.context.internalAdapter.findUserById(
          f.verified.verifiedUserId!,
        ),
      ).toEqual(before);
      expect(
        await f.context.internalAdapter.findCredentialAccount(
          f.verified.verifiedUserId!,
        ),
      ).toBeFalsy();
      expect(
        await f.context.adapter.count({ model: "firstPartyAuthorization" }),
      ).toBe(0);
      expect(
        await f.context.adapter.count({ model: "firstPartyCredential" }),
      ).toBe(0);
      expect(await f.context.adapter.count({ model: "session" })).toBe(0);
      expect(
        [...f.secondary.values()].filter((entry) =>
          entry.value.includes('"session":'),
        ),
      ).toHaveLength(0);
    });

    it("fails setup closed and cleans secondary storage after a temporary-session cleanup failure", async () => {
      const f = await prepareProfile(true);
      const remove = f.context.internalAdapter.deleteSession.bind(
        f.context.internalAdapter,
      );
      let failed = false;
      f.context.internalAdapter.deleteSession = async (token) => {
        if (!failed) {
          failed = true;
          throw new Error("injected cleanup failure");
        }
        await remove(token);
      };
      await expect(f.setupProfile(f.created.authSession)).rejects.toMatchObject(
        { statusCode: 500 },
      );
      expect(failed).toBe(true);
      expect(
        await f.context.internalAdapter.findCredentialAccount(
          f.verified.verifiedUserId!,
        ),
      ).toBeFalsy();
      expect(
        await f.context.adapter.count({ model: "firstPartyAuthorization" }),
      ).toBe(0);
      expect(await f.context.adapter.count({ model: "session" })).toBe(0);
      expect(
        [...f.secondary.values()].filter((entry) =>
          entry.value.includes('"session":'),
        ),
      ).toHaveLength(0);
    });

    it("removes a password session whose creation fails after writing to secondary storage", async () => {
      const f = await prepareProfile(true);
      f.observed.failPasswordSessionCache = true;
      await expect(f.setupProfile(f.created.authSession)).rejects.toMatchObject(
        { statusCode: 500 },
      );
      expect(f.observed.failPasswordSessionCache).toBe(false);
      expect(
        await f.context.internalAdapter.findCredentialAccount(
          f.verified.verifiedUserId!,
        ),
      ).toBeFalsy();
      expect(await f.context.adapter.count({ model: "session" })).toBe(0);
      expect(
        await f.context.adapter.count({ model: "firstPartyAuthorization" }),
      ).toBe(0);
      expect(
        [...f.secondary.values()].filter((entry) =>
          entry.value.includes('"session":'),
        ),
      ).toHaveLength(0);
    });

    it("routes legacy OTP delivery and retains verified setup authority without a bearer session", async () => {
      const f = await fixture(database, true, true, true);
      const email = "new-legacy-user@example.test";
      const created = await f.create({ intent: "create_account", email });
      const sent = await f.requestOTP(created.authSession, { email });
      expect(sent.outcome).toEqual({ kind: "requested" });
      expect(f.observed.genericDeliveryCalls).toBe(0);
      expect(f.observed.createOTPCalls).toBe(1);
      expect(f.observed.routed).toEqual([{ email, otp: "003147" }]);
      const result = await f.verifyOTP(created.authSession, { email });
      expect(result.kind).toBe("verified");
      if (result.kind !== "verified") throw new Error("OTP not verified");
      expect(result.session).toMatchObject({
        step: "profile_password",
        status: "ready",
        email,
      });
      expect(result.session.verifiedUserId).toBeTruthy();
      expect(result.session.userSecurityHash).toMatch(/^[a-f0-9]{64}$/);
      expect(JSON.stringify(result.session)).not.toContain(
        f.observed.routed[0]!.otp,
      );
      expect(await f.context.adapter.count({ model: "session" })).toBe(0);
      expect(
        await f.context.adapter.count({ model: "firstPartyAuthorization" }),
      ).toBe(0);
      expect(
        await f.context.adapter.count({ model: "firstPartyTokenFamily" }),
      ).toBe(0);
    });

    it("honors host policy hooks on the server-only OTP creation API", async () => {
      const f = await fixture(database, true, true, true);
      const created = await f.create({
        intent: "create_account",
        email: f.testUser.email,
      });
      f.observed.denyCreateOTP = true;
      expect(
        (await f.requestOTP(created.authSession, { email: f.testUser.email }))
          .outcome.kind,
      ).toBe("rejected");
      expect(f.observed.createOTPCalls).toBe(1);
      expect(f.observed.routed).toHaveLength(0);
      expect(f.observed.genericDeliveryCalls).toBe(0);
      expect(
        await f.context.adapter.findMany({ model: "firstPartyLegacySession" }),
      ).toMatchObject([
        { status: "ready", step: "email_verification", verifiedUserId: null },
      ]);
    });

    it("continues an existing verified legacy account from OTP to password and proof-bound tokens", async () => {
      const f = await fixture(database, true, true, true);
      await f.context.internalAdapter.updateUser(f.testUser.id, {
        emailVerified: true,
      });
      const created = await f.create({
        intent: "create_account",
        email: f.testUser.email,
      });
      expect(
        (await f.requestOTP(created.authSession, { email: f.testUser.email }))
          .outcome.kind,
      ).toBe("requested");
      const verified = await f.verifyOTP(created.authSession, {
        email: f.testUser.email,
      });
      expect(verified).toMatchObject({
        kind: "verified",
        session: { step: "email_password", verifiedUserId: f.testUser.id },
      });
      const result = await f.run((ctx) =>
        submitLegacyPassword(ctx, f.options, {
          ...fields,
          auth_session: created.authSession,
          email: f.testUser.email,
          password: f.testUser.password,
        }),
      );
      if (result.kind !== "authorized") throw new Error("No authorization");
      expect(
        (await f.exchange(codeFields(result.authorizationCode))).status,
      ).toBe(200);
      expect(
        await f.context.adapter.findMany({ model: "firstPartyLegacySession" }),
      ).toMatchObject([
        {
          status: "code-issued",
          email: null,
          verifiedUserId: null,
          userSecurityHash: null,
        },
      ]);
      expect(await f.context.adapter.count({ model: "session" })).toBe(0);
    });

    it("keeps failed legacy OTP retries bound to the original recipient", async () => {
      const f = await fixture(database, true, true, true);
      const created = await f.create({
        intent: "create_account",
        email: f.testUser.email,
      });
      await f.requestOTP(created.authSession, { email: f.testUser.email });
      await expect(
        f.verifyOTP(created.authSession, { email: "substitute@example.test" }),
      ).rejects.toMatchObject({ statusCode: 400 });
      expect(
        await f.verifyOTP(created.authSession, {
          email: f.testUser.email,
          verification_code: "wrong-code",
        }),
      ).toEqual({ kind: "rejected" });
      expect(
        await f.context.adapter.findMany({ model: "firstPartyLegacySession" }),
      ).toMatchObject([
        { status: "ready", step: "email_verification", verifiedUserId: null },
      ]);
      expect(
        (await f.verifyOTP(created.authSession, { email: f.testUser.email }))
          .kind,
      ).toBe("verified");
      await expect(
        f.verifyOTP(created.authSession, { email: f.testUser.email }),
      ).rejects.toMatchObject({ statusCode: 400 });
    });

    it("rejects a changed verified password recipient without consuming the legacy handle", async () => {
      const f = await fixture(database, true, true, true);
      await f.context.internalAdapter.updateUser(f.testUser.id, {
        emailVerified: true,
      });
      const created = await f.create({
        intent: "create_account",
        email: f.testUser.email,
      });
      await f.requestOTP(created.authSession, { email: f.testUser.email });
      await f.verifyOTP(created.authSession, { email: f.testUser.email });
      const before = await f.context.adapter.findMany({
        model: "firstPartyLegacySession",
      });
      await expect(
        f.run((ctx) =>
          submitLegacyPassword(ctx, f.options, {
            ...fields,
            auth_session: created.authSession,
            email: "substitute@example.test",
            password: f.testUser.password,
          }),
        ),
      ).rejects.toMatchObject({ statusCode: 400 });
      expect(f.observed.passwordCalls).toBe(0);
      expect(
        await f.context.adapter.findMany({ model: "firstPartyLegacySession" }),
      ).toEqual(before);
      const result = await f.run((ctx) =>
        submitLegacyPassword(ctx, f.options, {
          ...fields,
          auth_session: created.authSession,
          email: ` ${f.testUser.email.toUpperCase()} `,
          password: f.testUser.password,
        }),
      );
      if (result.kind !== "authorized") throw new Error("No authorization");
      expect(f.observed.passwordCalls).toBe(1);
      expect(
        (await f.exchange(codeFields(result.authorizationCode))).status,
      ).toBe(200);
    });

    it("leaves the password step retryable when its recipient is missing or malformed", async () => {
      const f = await fixture(database, true, true);
      const created = await f.create({ email: undefined });
      for (const email of [undefined, "", "not-an-email"]) {
        await expect(
          f.run((ctx) =>
            submitLegacyPassword(ctx, f.options, {
              ...fields,
              auth_session: created.authSession,
              email,
              password: f.testUser.password,
            }),
          ),
        ).rejects.toMatchObject({ statusCode: 400 });
        expect(f.observed.passwordCalls).toBe(0);
        expect(
          await f.context.adapter.findMany({
            model: "firstPartyLegacySession",
          }),
        ).toMatchObject([
          { status: "ready", step: "email_password", operationId: null },
        ]);
      }
      const result = await f.run((ctx) =>
        submitLegacyPassword(ctx, f.options, {
          ...fields,
          auth_session: created.authSession,
          email: f.testUser.email,
          password: f.testUser.password,
        }),
      );
      expect(result.kind).toBe("authorized");
    });

    it("charges uncertain legacy deliveries and enforces cooldown before another routed send", async () => {
      const f = await fixture(database, true, true, true);
      const created = await f.create({
        intent: "create_account",
        email: f.testUser.email,
      });
      f.observed.failDelivery = true;
      expect(
        (await f.requestOTP(created.authSession, { email: f.testUser.email }))
          .outcome.kind,
      ).toBe("unknown");
      f.observed.failDelivery = false;
      const retry = await f.requestOTP(created.authSession, {
        email: f.testUser.email,
      });
      expect(retry.outcome.kind).toBe("rejected");
      expect(Number(retry.retryAfter)).toBeGreaterThan(0);
      expect(f.observed.routed).toHaveLength(1);
      expect(
        await f.context.adapter.findMany({ model: "firstPartyEmailDelivery" }),
      ).toMatchObject([{ outcome: "unknown" }]);
      expect(await f.context.adapter.count({ model: "session" })).toBe(0);
    });

    it("does not preserve a legacy OTP factor for an account requiring MFA", async () => {
      const f = await fixture(database, true, true, true);
      await f.context.adapter.update({
        model: "user",
        where: [{ field: "id", value: f.testUser.id }],
        update: { emailVerified: true, twoFactorEnabled: true },
      });
      const created = await f.create({
        intent: "create_account",
        email: f.testUser.email,
      });
      await f.requestOTP(created.authSession, { email: f.testUser.email });
      expect(
        await f.verifyOTP(created.authSession, { email: f.testUser.email }),
      ).toEqual({ kind: "browser-required" });
      expect(
        await f.context.adapter.findMany({ model: "firstPartyLegacySession" }),
      ).toMatchObject([{ verifiedUserId: null, userSecurityHash: null }]);
      expect(await f.context.adapter.count({ model: "session" })).toBe(0);
    });

    it("rejects late legacy delivery after the admitted provider credential is retired", async () => {
      const f = await fixture(database, true, true, true);
      const created = await f.create({
        intent: "create_account",
        email: f.testUser.email,
      });
      f.observed.onDelivery = async () => {
        await f.context.adapter.update({
          model: "deviceAttestationCredential",
          where: [{ field: "id", value: f.credentialId }],
          update: { status: "revoked" },
        });
      };
      await expect(
        f.requestOTP(created.authSession, { email: f.testUser.email }),
      ).rejects.toMatchObject({ statusCode: 400 });
      expect(f.observed.routed).toHaveLength(1);
      expect(
        await f.context.adapter.findMany({ model: "firstPartyLegacySession" }),
      ).toMatchObject([{ status: "processing", verifiedUserId: null }]);
    });

    it("authenticates through Better Auth and atomically exchanges and refreshes explicitly legacy families", async () => {
      const f = await fixture(database, true, true);
      const authorized = await f.login();
      expect(authorized.authorization_code).toMatch(/^fpl1_/);
      expect(await f.context.adapter.count({ model: "session" })).toBe(0);
      expect(
        await f.context.adapter.findMany({
          model: "deviceAttestationCredential",
        }),
      ).toMatchObject([{ userId: null }]);
      const exchanged = await f.exchange(
        codeFields(authorized.authorization_code),
      );
      expect(exchanged.status).toBe(200);
      const tokens = (await exchanged.json()) as {
        access_token: string;
        refresh_token: string;
        token_type: string;
      };
      expect(tokens.token_type).toBe("DPoP");
      const families = await f.context.adapter.findMany<{
        id: string;
        userId: string;
        assurance: { profile: string };
      }>({ model: "firstPartyTokenFamily" });
      expect(families).toMatchObject([
        {
          userId: f.testUser.id,
          assurance: { profile: "legacy-v1", challengeProof: false },
        },
      ]);
      expect(
        await f.context.adapter.findMany({ model: "oauthRefreshToken" }),
      ).toMatchObject([
        { referenceId: families[0]!.id, userId: f.testUser.id },
      ]);
      expect(
        await f.context.adapter.findMany({
          model: "deviceAttestationCredential",
        }),
      ).toMatchObject([{ userId: f.testUser.id }]);
      // A resource requiring the native profile cannot accept legacy assurance.
      expect(
        await f.run(async (ctx) =>
          getOAuthProviderApi(ctx, f.options.oauth).requireActiveAccessToken(
            tokens.access_token,
            "mobile",
          ),
        ),
      ).toMatchObject({ active: true, sub: f.testUser.id });
      await expect(
        f.run((ctx) =>
          requireNativeAccess(ctx, f.tokenOptions, {
            headers: new Headers({
              authorization: `DPoP ${tokens.access_token}`,
              dpop: f.proof(signingKey, tokens.access_token),
            }),
            method: "GET",
            url: `${f.context.baseURL}/resource`,
            scopes: [],
          }),
        ),
      ).rejects.toThrow();
      const refresh = {
        grant_type: "refresh_token",
        refresh_token: tokens.refresh_token,
        resource: fields.resource,
      };
      expect((await f.exchange(refresh, null)).status).toBe(400);
      const renewed = await f.exchange(refresh);
      expect(renewed.status).toBe(200);
      const next = (await renewed.json()) as { refresh_token: string };
      expect(next.refresh_token).not.toBe(tokens.refresh_token);
      expect(
        await f.context.adapter.findMany({ model: "firstPartyTokenFamily" }),
      ).toMatchObject([{ assurance: { profile: "legacy-v1" } }]);
      expect((await f.exchange(refresh)).status).toBe(400);
      expect(
        await f.context.adapter.findMany({ model: "firstPartyTokenFamily" }),
      ).toMatchObject([{ status: "revoked" }]);
      expect(
        (await f.exchange({ ...refresh, refresh_token: next.refresh_token }))
          .status,
      ).toBe(400);
    });
    it("requires exact legacy code binding and proof without consuming a valid code on rejection", async () => {
      const f = await fixture(database, true, true);
      const { authorization_code: code } = await f.login();
      const body = codeFields(code);
      for (const change of [
        { resource: "https://other.example.test" },
        { resource: "" },
        { redirect_uri: "other:/callback" },
        { code_verifier: "x".repeat(43) },
        { client_id: "other" },
        { code: code.replace("fpl1_", "fp1_") },
        { profile: "device-attestation-fipa-v1" },
      ])
        expect((await f.exchange({ ...body, ...change })).status).toBe(400);
      expect((await f.exchange(body, null)).status).toBe(400);
      expect(
        (
          await f.exchange(
            body,
            f.proof(generateKeyPairSync("ec", { namedCurve: "prime256v1" })),
          )
        ).status,
      ).toBe(400);
      await f.context.adapter.update({
        model: "oauthClient",
        where: [{ field: "clientId", value: "mobile" }],
        update: { redirectUris: ["other:/callback"] },
      });
      expect((await f.exchange(body)).status).toBe(400);
      await f.context.adapter.update({
        model: "oauthClient",
        where: [{ field: "clientId", value: "mobile" }],
        update: { redirectUris: [fields.redirect_uri] },
      });
      expect((await f.exchange(body)).status).toBe(200);
      expect((await f.exchange(body)).status).toBe(400);
    });
    it("serializes legacy code redemption into exactly one token family", async () => {
      const f = await fixture(database, true, true);
      const { authorization_code: code } = await f.login();
      const results = await Promise.all([
        f.exchange(codeFields(code)),
        f.exchange(codeFields(code)),
      ]);
      expect(results.map((response) => response.status).sort()).toEqual([
        200, 400,
      ]);
      expect(
        await f.context.adapter.count({ model: "firstPartyTokenFamily" }),
      ).toBe(1);
    });
    it("rolls legacy issuance and ownership back on token indexing failure but never restores a used proof", async () => {
      const f = await fixture(database, true, true);
      const { authorization_code: code } = await f.login();
      const transaction = f.context.adapter.transaction;
      f.context.adapter.transaction = async (operation) =>
        transaction((adapter) =>
          operation({
            ...adapter,
            create: async (input) => {
              if (input.model === "firstPartyAccess")
                throw new Error("injected legacy indexing failure");
              return adapter.create(input);
            },
          }),
        );
      const proof = f.proof();
      expect((await f.exchange(codeFields(code), proof)).status).toBe(500);
      for (const model of [
        "firstPartyTokenFamily",
        "firstPartyAccess",
        "firstPartyRefresh",
        "oauthAccessToken",
        "oauthRefreshToken",
      ])
        expect(await f.context.adapter.count({ model })).toBe(0);
      expect(
        await f.context.adapter.findMany({
          model: "deviceAttestationCredential",
        }),
      ).toMatchObject([{ userId: null }]);
      f.context.adapter.transaction = transaction;
      expect((await f.exchange(codeFields(code), proof)).status).toBe(400);
      expect((await f.exchange(codeFields(code))).status).toBe(200);
    });
    it("rejects legacy pending codes and refresh after account links are removed", async () => {
      const f = await fixture(database, true, true);
      const first = await f.login();
      const exchange = await f.exchange(codeFields(first.authorization_code));
      expect(exchange.status).toBe(200);
      const token = (await exchange.json()) as { refresh_token: string };
      const pending = await f.login();
      await f.context.adapter.deleteMany({
        model: "account",
        where: [{ field: "userId", value: f.testUser.id }],
      });
      const redeemed = await f.exchange(codeFields(pending.authorization_code));
      expect(redeemed.status).toBe(400);
      expect(await redeemed.json()).toMatchObject({ error: "invalid_grant" });
      const refreshed = await f.exchange({
        grant_type: "refresh_token",
        refresh_token: token.refresh_token,
      });
      expect(refreshed.status).toBe(400);
      expect(await refreshed.json()).toMatchObject({ error: "invalid_grant" });
    });

    it("does not turn invalid passwords or MFA requirements into legacy authorization", async () => {
      const f = await fixture(database, true, true);
      const created = await f.create();
      const request = {
        ...fields,
        auth_session: created.authSession,
        email: f.testUser.email,
        password: "wrong-password",
      };
      expect((await f.send(request)).status).toBe(401);
      await f.context.adapter.update({
        model: "user",
        where: [{ field: "id", value: f.testUser.id }],
        update: { twoFactorEnabled: true },
      });
      expect(
        (await f.send({ ...request, password: f.testUser.password })).status,
      ).toBe(403);
      expect(await f.context.adapter.count({ model: "session" })).toBe(0);
      expect(
        await f.context.adapter.count({ model: "firstPartyAuthorization" }),
      ).toBe(0);
      await f.context.adapter.update({
        model: "user",
        where: [{ field: "id", value: f.testUser.id }],
        update: { twoFactorEnabled: false },
      });
      expect(
        (await f.send({ ...request, password: f.testUser.password })).status,
      ).toBe(200);
      expect(
        (await f.send({ ...request, password: f.testUser.password })).status,
      ).toBe(400);
    });
    it("rejects legacy token redemption when compatibility is disabled", async () => {
      const f = await fixture(database, false, true);
      const created = await f.create();
      const result = await f.run((ctx) =>
        submitLegacyPassword(ctx, f.options, {
          ...fields,
          auth_session: created.authSession,
          email: f.testUser.email,
          password: f.testUser.password,
        }),
      );
      if (result.kind !== "authorized") throw new Error("No code");
      expect(
        (await f.exchange(codeFields(result.authorizationCode))).status,
      ).toBe(400);
      expect(
        await f.context.adapter.count({ model: "firstPartyTokenFamily" }),
      ).toBe(0);
    });
    it("preserves the legacy continuation and Retry-After on password rate limiting", async () => {
      const f = await fixture(database, true, true);
      const created = await f.create();
      const request = {
        ...fields,
        auth_session: created.authSession,
        email: f.testUser.email,
        password: f.testUser.password,
      };
      f.observed.passwordLimit = true;
      const rejected = await f.send(request);
      expect(rejected.status).toBe(429);
      expect(rejected.headers.get("retry-after")).toBe("15");
      expect(
        await f.context.adapter.findMany({ model: "firstPartyLegacySession" }),
      ).toMatchObject([{ status: "ready", operationId: null }]);
      expect(
        await f.context.adapter.count({ model: "firstPartyAuthorization" }),
      ).toBe(0);
      f.observed.passwordLimit = false;
      expect((await f.send(request)).status).toBe(200);
    });
    it.each([
      "expiry",
      "provider-retirement",
      "binding-change",
      "account-security",
      "disabled-client",
    ] as const)(
      "rejects a successful password result whose reserved legacy authority changed: %s",
      async (reason) => {
        const f = await fixture(database, true, true);
        const created = await f.create();
        const reserved = await f.reserve(created.authSession);
        const factor = await f.run((ctx) =>
          authenticateWithPassword(ctx, {
            email: f.testUser.email,
            password: f.testUser.password,
          }),
        );
        if (factor.kind !== "authenticated")
          throw new Error("Fixture password failed");
        if (reason === "expiry")
          await f.context.adapter.update({
            model: "firstPartyLegacySession",
            where: [{ field: "id", value: created.session.id }],
            update: { expiresAt: new Date(0) },
          });
        else if (reason === "account-security")
          await f.context.adapter.deleteMany({
            model: "account",
            where: [{ field: "userId", value: f.testUser.id }],
          });
        else if (reason === "disabled-client")
          await f.context.adapter.update({
            model: "oauthClient",
            where: [{ field: "clientId", value: "mobile" }],
            update: { disabled: true },
          });
        else
          await f.context.adapter.update({
            model: "deviceAttestationCredential",
            where: [{ field: "id", value: f.credentialId }],
            update:
              reason === "provider-retirement"
                ? { status: "revoked" }
                : { bindingVersion: 1 },
          });
        await expect(
          f.run((ctx) =>
            authorizeLegacySession(ctx, f.options, reserved, factor),
          ),
        ).rejects.toThrow();
        expect(
          await f.context.adapter.count({ model: "firstPartyAuthorization" }),
        ).toBe(0);
        expect(
          await f.context.adapter.count({ model: "firstPartyCredential" }),
        ).toBe(0);
        expect(await f.context.adapter.count({ model: "session" })).toBe(0);
      },
    );
    it("rolls terminal legacy state and logical enrollment back if code storage fails", async () => {
      const f = await fixture(database, true, true);
      const created = await f.create();
      const reserved = await f.reserve(created.authSession);
      const factor = await f.run((ctx) =>
        authenticateWithPassword(ctx, {
          email: f.testUser.email,
          password: f.testUser.password,
        }),
      );
      if (factor.kind !== "authenticated")
        throw new Error("Fixture password failed");
      const transaction = f.context.adapter.transaction;
      f.context.adapter.transaction = async (operation) =>
        transaction((adapter) =>
          operation({
            ...adapter,
            create: async (input) => {
              if (input.model === "firstPartyAuthorization")
                throw new Error("injected legacy code persistence failure");
              return adapter.create(input);
            },
          }),
        );
      await expect(
        f.run((ctx) =>
          authorizeLegacySession(ctx, f.options, reserved, factor),
        ),
      ).rejects.toThrow();
      expect(
        await f.context.adapter.findMany({ model: "firstPartyLegacySession" }),
      ).toMatchObject([
        {
          status: "processing",
          revision: reserved.revision,
          operationId: reserved.operationId,
        },
      ]);
      expect(
        await f.context.adapter.count({ model: "firstPartyCredential" }),
      ).toBe(0);
      expect(
        await f.context.adapter.count({ model: "firstPartyAuthorization" }),
      ).toBe(0);
      f.context.adapter.transaction = transaction;
      expect(
        await f.run((ctx) =>
          authorizeLegacySession(ctx, f.options, reserved, factor),
        ),
      ).toMatch(/^fpl1_/);
      await expect(
        f.run((ctx) =>
          authorizeLegacySession(ctx, f.options, reserved, factor),
        ),
      ).rejects.toThrow();
    });
    it("routes the submitted JSON envelope and preserves 200 next_step responses and a stable opaque handle", async () => {
      const f = await fixture(database);
      const initial = await f.send({
        ...fields,
        device_attestation: await f.evidence(),
      });
      expect(initial.status).toBe(200);
      expect(initial.headers.get("cache-control")).toBe("no-store");
      const body = (await initial.json()) as { auth_session: string };
      expect(body).toMatchObject({
        error: "insufficient_authorization",
        next_step: "email_password",
        email: fields.email,
      });
      const next = await f.send({
        ...fields,
        auth_session: body.auth_session,
        password: "transient-password",
      });
      expect(next.status).toBe(200);
      expect(await next.json()).toMatchObject({
        auth_session: body.auth_session,
        next_step: "email_password",
      });
      const stored = await f.context.adapter.findMany<LegacySession>({
        model: "firstPartyLegacySession",
      });
      expect(stored).toHaveLength(1);
      expect(stored[0]?.profile).toBe("legacy-v1");
      expect(JSON.stringify(stored)).not.toContain(body.auth_session);
      expect(JSON.stringify(stored)).not.toContain("transient-password");
    });
    it("keeps JSON disabled unless an adapter is explicitly composed", async () => {
      const f = await fixture(database, false);
      expect((await f.send(fields)).status).toBe(415);
      expect(f.observed.legacyCalls).toBe(0);
    });
    it("never sends malformed/new/mixed requests or unknown clients to the legacy adapter", async () => {
      const f = await fixture(database);
      for (const body of [
        { ...fields, profile: "device-attestation-fipa-v1" },
        { ...fields, client_id: "other" },
        { ...fields, step_id: "new-step", response: "{}" },
        { ...fields, auth_session: `fpas1_${"n".repeat(43)}` },
        { ...fields, acr_values: "urn:example:require-mfa" },
      ])
        expect((await f.send(body)).status).toBe(400);
      expect(
        (await f.send(fields, "application/json", "invalid-proof")).status,
      ).toBe(400);
      expect(
        (await f.send(fields, "application/x-www-form-urlencoded")).status,
      ).toBe(400);
      expect(
        (
          await f.send(
            {
              profile: "device-attestation-fipa-v1",
              client_id: "mobile",
              response_type: "code",
              scope: "offline_access",
              code_challenge: fields.code_challenge,
              code_challenge_method: "S256",
              authorization_attempt: "a".repeat(43),
              device_attestation: "g".repeat(43),
            },
            "application/x-www-form-urlencoded",
          )
        ).status,
      ).toBe(400);
      expect(f.observed.legacyCalls).toBe(0);
    });
    it("atomically consumes admission, stores no input secrets and bounds authority by the original grant", async () => {
      const f = await fixture(database);
      const token = await f.grant();
      await expect(
        f.run(async (ctx) => {
          await createLegacySession(
            ctx,
            f.options,
            { ...fields, redirect_uri: "other:/callback" },
            token,
          );
        }),
      ).rejects.toThrow();
      const admitted = await f.run((ctx) =>
        createLegacySession(
          ctx,
          f.options,
          {
            ...fields,
            password: "secret-input",
            verification_code: "secret-otp",
          },
          token,
        ),
      );
      expect(
        admitted.session.expiresAt.getTime() - Date.now(),
      ).toBeLessThanOrEqual(300_000);
      expect(JSON.stringify(admitted.session)).not.toMatch(
        /secret-input|secret-otp/,
      );
      await expect(
        f.run((ctx) => createLegacySession(ctx, f.options, fields, token)),
      ).rejects.toThrow();
    });
    it("rolls admission back if continuation persistence fails", async () => {
      const f = await fixture(database);
      const token = await f.grant();
      await expect(
        f.run(async (ctx) => {
          const adapter = ctx.context.adapter;
          const transaction: typeof adapter.transaction = async (work) =>
            adapter.transaction((tx) =>
              work({
                ...tx,
                create: async (input) => {
                  if (input.model === "firstPartyLegacySession")
                    throw new Error("injected persistence failure");
                  return tx.create(input);
                },
              }),
            );
          const failed = {
            ...ctx,
            context: {
              ...ctx.context,
              adapter: {
                ...adapter,
                transaction,
              },
            },
          };
          return createLegacySession(failed, f.options, fields, token);
        }),
      ).rejects.toThrow();
      const retry = await f.run((ctx) =>
        createLegacySession(ctx, f.options, fields, token),
      );
      expect(retry.session.status).toBe("ready");
    });
    it("checks every stored authorization binding field before reserving work", async () => {
      const f = await fixture(database);
      const created = await f.create();
      for (const override of [
        { dpop_jkt: "k".repeat(43) },
        { code_challenge: "c".repeat(43) },
        { scope: "offline_access" },
        { resource: [] },
        { redirect_uri: "other:/callback" },
      ])
        await expect(
          f.reserve(created.authSession, override),
        ).rejects.toThrow();
      expect(
        (
          await f.reserve(created.authSession, {
            scope: "offline_access api:read",
            resource: ["https://api.example.test"],
          })
        ).status,
      ).toBe("processing");
    });
    it("serializes competing method requests and rejects a duplicated completion", async () => {
      const f = await fixture(database);
      const created = await f.create();
      const results = await Promise.allSettled([
        f.reserve(created.authSession),
        f.reserve(created.authSession),
      ]);
      expect(
        results.filter((result) => result.status === "fulfilled"),
      ).toHaveLength(1);
      const winner = results.find((result) => result.status === "fulfilled");
      if (winner?.status !== "fulfilled") throw new Error("No reservation");
      const finish = () =>
        f.run((ctx) =>
          finishLegacyStep(ctx, f.options, winner.value, {
            step: "email_verification",
          }),
        );
      expect((await finish()).step).toBe("email_verification");
      await expect(finish()).rejects.toThrow();
      expect((await f.reserve(created.authSession)).step).toBe(
        "email_verification",
      );
    });
    it.each([
      "expiry",
      "provider-retirement",
      "binding-change",
      "disabled-client",
    ] as const)("fences a late method result after %s", async (reason) => {
      const f = await fixture(database);
      const created = await f.create();
      const reservation = await f.reserve(created.authSession);
      if (reason === "disabled-client") {
        await f.run(async (ctx) => {
          const cached = await getOAuthProviderApi(
            ctx,
            f.options.oauth,
          ).getClient("mobile");
          expect(cached?.disabled).toBeFalsy();
        });
      }
      if (reason === "expiry")
        await f.context.adapter.update({
          model: "firstPartyLegacySession",
          where: [{ field: "id", value: created.session.id }],
          update: { expiresAt: new Date(0) },
        });
      else if (reason === "disabled-client")
        await f.context.adapter.update({
          model: "oauthClient",
          where: [{ field: "clientId", value: "mobile" }],
          update: { disabled: true },
        });
      else
        await f.context.adapter.update({
          model: "deviceAttestationCredential",
          where: [{ field: "id", value: f.credentialId }],
          update:
            reason === "provider-retirement"
              ? { status: "revoked" }
              : { bindingVersion: 1 },
        });
      await expect(
        f.run((ctx) =>
          finishLegacyStep(ctx, f.options, reservation, {
            step: "profile_password",
          }),
        ),
      ).rejects.toThrow();
    });
  });
