import {
  readNativeProviderCredential,
  type LifecycleProviderCredential,
} from "./first-party/provider-credential.js";
import { createHash, generateKeyPairSync, randomUUID, sign } from "node:crypto";
import type { GenericEndpointContext } from "@better-auth/core";
import { deriveDpopJkt } from "@better-auth/core/oauth2";
import {
  getOAuthProviderApi,
  oauthProvider,
  type OAuthOptions,
} from "@better-auth/oauth-provider";
import type { BetterAuthPlugin } from "better-auth";
import { createAuthEndpoint } from "better-auth/api";
import { getTestInstance } from "./fixtures/auth-instance.js";
import { describe, expect, it } from "vitest";
import { z } from "zod";
import { deviceAttestationSchema } from "./schema.js";
import type {
  StoredAttestationCredential,
  OAuthAuthorizationBinding,
} from "./types.js";
import {
  consumeOAuthAuthorizationGrant,
  grantIdentifier,
} from "./oauth-grant.js";
import { hashOAuthBinding } from "./protocol/binding.js";
import { randomToken } from "./protocol/crypto.js";
import { firstPartyStateSchema } from "./first-party/state-schema.js";
import {
  enrollLogicalCredential,
  recordAuthorizedAttempt,
  issueAuthorizationCode,
  redeemAuthorizationCode,
  retireLogicalCredential,
  type LogicalCredential,
  type FirstPartyTokenFamily,
  type AuthorizedAttempt,
} from "./first-party/authorization-store.js";

const CLIENT = "state-mobile";
const VERIFIER = "v".repeat(43);
const options = {
  loginPage: "/login",
  consentPage: "/consent",
  disableJwtPlugin: true,
  scopes: ["offline_access"],
} satisfies OAuthOptions;

async function fixture(
  testWith: "sqlite" | "postgres",
  prebound = false,
  android = false,
) {
  const providerId = android ? "android-hardware" : "apple-app-attest";
  const providerModel = android
    ? "firstPartyAndroidKey"
    : "deviceAttestationCredential";
  const applicationId = android ? "io.example.mobile" : "TEAM.test";
  const environment = android ? "production" : "development";
  const operations = new Map<
    string,
    (ctx: GenericEndpointContext) => Promise<unknown>
  >();
  const oauth = oauthProvider(options);
  const providerPlugin: BetterAuthPlugin = {
    ...oauth,
    // Upstream OpenAPI union is incompatible with exactOptionalPropertyTypes.
    endpoints: oauth.endpoints as unknown as NonNullable<
      BetterAuthPlugin["endpoints"]
    >,
  };
  const { auth, testUser } = await getTestInstance(
    {
      plugins: [
        providerPlugin,
        {
          id: "first-party-state-test",
          schema: { ...deviceAttestationSchema, ...firstPartyStateSchema },
          endpoints: {
            executeStore: createAuthEndpoint(
              "/test-only/state",
              { method: "POST", body: z.object({ id: z.string() }) },
              async (ctx) => {
                const operation = operations.get(ctx.body.id);
                if (!operation) throw new Error("Unknown fixture operation");
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
  const user = await context.adapter.findOne<{ id: string }>({
    model: "user",
    where: [{ field: "email", value: testUser.email }],
  });
  if (!user) throw new Error("Missing fixture user");
  const other = await auth.api.signUpEmail({
    body: {
      name: "Other",
      email: "other@example.com",
      password: "long-test-password",
    },
  });
  await context.adapter.create({
    model: "oauthClient",
    data: {
      clientId: CLIENT,
      redirectUris: [],
      tokenEndpointAuthMethod: "none",
      grantTypes: ["authorization_code", "refresh_token"],
      scopes: ["offline_access"],
      disabled: false,
    },
  });
  const key = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const jwk = key.publicKey.export({ format: "jwk" });
  const jkt = await deriveDpopJkt(jwk);
  const endpointUrl = `${context.baseURL}/oauth2/token`;
  const run = async <T>(
    operation: (ctx: GenericEndpointContext) => Promise<T>,
  ): Promise<T> => {
    const id = randomUUID();
    operations.set(id, operation);
    try {
      return (await auth.api.executeStore({ body: { id } })) as T;
    } finally {
      operations.delete(id);
    }
  };
  // Persist the real shared provider model, without claiming hardware verification.
  const providerCredential =
    await context.adapter.create<LifecycleProviderCredential>({
      model: providerModel,
      data: {
        lookupKey: randomUUID(),
        provider: providerId,
        applicationId,
        environment,
        publicKey: "fixture-public-key",
        ...(android
          ? {
              clientId: CLIENT,
              dpopJkt: jkt,
              createdAt: new Date(),
              updatedAt: new Date(),
              // Persistence/lifecycle fixture only, not simulated hardware evidence.
              keyVerifiedAt: new Date(),
              keyEvidence: { fixture: true },
            }
          : { counter: 0, extensionsPresent: false }),
        userId: prebound ? user.id : null,
        externallyBound: false,
        bindingVersion: prebound ? 1 : 0,
        status: "active",
        unboundExpiresAt: new Date(Date.now() + 3600_000),
      },
    });
  const credential = await run((ctx) =>
    enrollLogicalCredential(ctx, {
      issuer: context.baseURL,
      clientId: CLIENT,
      applicationId,
      environment,
      provider: providerId,
      providerCredentialId: providerCredential.id,
      dpopJkt: jkt,
    }),
  );
  const authorize = async (
    userId = user.id,
    change: Partial<Parameters<typeof recordAuthorizedAttempt>[1]> = {},
  ) =>
    run(async (ctx) => {
      const now = Date.now();
      const currentProvider =
        await ctx.context.adapter.findOne<StoredAttestationCredential>({
          model: providerModel,
          where: [{ field: "id", value: providerCredential.id }],
        });
      const attempt = await recordAuthorizedAttempt(ctx, {
        attemptId: randomUUID(),
        credentialId: credential.id,
        credentialVersion: credential.version,
        providerCredentialBindingVersion: currentProvider!.bindingVersion,
        clientId: CLIENT,
        userId,
        dpopJkt: jkt,
        codeChallenge: createHash("sha256")
          .update(VERIFIER)
          .digest("base64url"),
        scopes: ["offline_access"],
        resources: [],
        assurance: {
          profile: "device-attestation-fipa-v1",
          evidenceKind: "credential-key",
          provider: providerId,
        },
        authenticatedAt: new Date(now),
        assuranceExpiresAt: new Date(now + 300_000),
        expiresAt: new Date(now + 900_000),
        familyExpiresAt: new Date(now + 3600_000),
        ...change,
      });
      return { attempt, code: await issueAuthorizationCode(ctx, attempt.id) };
    });
  const headers = (proofKey = key) => {
    const encode = (value: unknown) =>
      Buffer.from(JSON.stringify(value)).toString("base64url");
    const unsigned = `${encode({ alg: "ES256", typ: "dpop+jwt", jwk: proofKey.publicKey.export({ format: "jwk" }) })}.${encode({ htm: "POST", htu: endpointUrl, iat: Math.floor(Date.now() / 1000), jti: randomUUID() })}`;
    return new Headers({
      dpop: `${unsigned}.${sign("sha256", Buffer.from(unsigned), { key: proofKey.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url")}`,
    });
  };
  const issue = async (
    ctx: GenericEndpointContext,
    authorization: AuthorizedAttempt,
    family: FirstPartyTokenFamily,
  ) => {
    const provider = getOAuthProviderApi(ctx, options, "authorization_code");
    const client = await provider.getClient(CLIENT);
    const subject = await ctx.context.internalAdapter.findUserById(
      authorization.userId,
    );
    if (!client || !subject) throw new Error("Missing fixture identity");
    return provider.issueTokens({
      client,
      user: subject,
      scopes: authorization.scopes,
      referenceId: family.id,
      confirmation: { jkt: family.dpopJkt },
    });
  };
  const redeem = (
    code: string,
    change: Partial<Parameters<typeof redeemAuthorizationCode>[1]> = {},
    fail = false,
  ) =>
    run((ctx) =>
      redeemAuthorizationCode(
        ctx,
        {
          code,
          clientId: CLIENT,
          codeVerifier: VERIFIER,
          headers: headers(),
          tokenEndpointUrl: endpointUrl,
          ...change,
        },
        async (transactionContext, authorization, family) => {
          const tokens = await issue(transactionContext, authorization, family);
          if (fail) throw new Error("injected-after-tokens");
          return tokens;
        },
      ),
    );
  const legacyGrant = async () => {
    if (android) throw new Error("Android is not a legacy provider");
    const current = await context.adapter.findOne<StoredAttestationCredential>({
      model: providerModel,
      where: [{ field: "id", value: providerCredential.id }],
    });
    const binding: OAuthAuthorizationBinding = {
      clientId: CLIENT,
      redirectUri: "test-app://callback",
      codeChallenge: "v".repeat(43),
      codeChallengeMethod: "S256",
      dpopJkt: jkt,
      scope: "offline_access",
    };
    const grantToken = randomToken();
    await context.internalAdapter.createVerificationValue({
      identifier: grantIdentifier(context.secret, grantToken),
      expiresAt: new Date(Date.now() + 120_000),
      value: JSON.stringify({
        version: 1,
        provider: providerCredential.provider,
        applicationId: providerCredential.applicationId,
        credentialId: providerCredential.id,
        credentialBindingVersion: current!.bindingVersion,
        purpose: "oauth-authorization",
        bindingHash: hashOAuthBinding(binding).toString("base64url"),
        counterExhausted: false,
      }),
    });
    return (userId = user.id) =>
      run((ctx) =>
        consumeOAuthAuthorizationGrant(ctx.context, {
          grantToken,
          binding,
          userId,
        }),
      );
  };
  const rows = (model: string) =>
    context.adapter.findMany<Record<string, unknown>>({ model });
  return {
    context,
    userId: user.id,
    otherUserId: other.user.id,
    credential,
    providerCredential,
    providerModel,
    jkt,
    legacyGrant,
    authorize,
    headers,
    redeem,
    rows,
    run,
  };
}

for (const database of ["sqlite", "postgres"] as const) {
  describe.runIf(
    database === "sqlite"
      ? process.env.TEST_POSTGRES !== "true" &&
          Number(process.versions.node.split(".")[0]) >= 22
      : process.env.TEST_POSTGRES === "true",
  )(`First-party authorization state (${database})`, () => {
    it("binds an Android certified-key record and actual token family without Apple fields", async () => {
      const f = await fixture(database, false, true);
      const row = (await f.rows(f.providerModel))[0]!;
      expect(row).not.toHaveProperty("counter");
      expect(row).not.toHaveProperty("extensionsPresent");
      expect(await f.rows("deviceAttestationCredential")).toEqual([]);
      const { code } = await f.authorize();
      const tokens = await f.redeem(code);
      expect(tokens.token_type).toBe("DPoP");
      expect(await f.rows(f.providerModel)).toMatchObject([
        { userId: f.userId, bindingVersion: 1, dpopJkt: f.jkt },
      ]);
      expect(await f.rows("firstPartyTokenFamily")).toMatchObject([
        { userId: f.userId, credentialId: f.credential.id },
      ]);
      for (const model of ["oauthAccessToken", "oauthRefreshToken"])
        expect(await f.rows(model)).toHaveLength(1);
      await expect(f.redeem(code)).rejects.toThrow();
    });

    it("rejects Android enrollment under a different key or client", async () => {
      const f = await fixture(database, false, true);
      for (const change of [
        { dpopJkt: "a".repeat(43) },
        { clientId: "other" },
      ]) {
        await expect(
          f.run((ctx) =>
            enrollLogicalCredential(ctx, {
              issuer: f.context.baseURL,
              clientId: CLIENT,
              applicationId: "io.example.mobile",
              environment: "production",
              provider: "android-hardware",
              providerCredentialId: f.providerCredential.id,
              dpopJkt: f.jkt,
              ...change,
            }),
          ),
        ).rejects.toThrow();
      }
      expect(await f.rows("firstPartyCredential")).toHaveLength(1);
    });

    it("keeps provider namespaces separate even when row IDs collide", async () => {
      const f = await fixture(database, false, true);
      await f.context.adapter.create({
        model: "deviceAttestationCredential",
        forceAllowId: true,
        data: {
          id: f.providerCredential.id,
          lookupKey: randomUUID(),
          provider: "apple-app-attest",
          applicationId: "TEAM.test",
          environment: "development",
          publicKey: "apple-fixture-key",
          counter: 9,
          extensionsPresent: false,
          status: "active",
          externallyBound: false,
          bindingVersion: 0,
          userId: null,
          unboundExpiresAt: new Date(Date.now() + 60_000),
        },
      });
      await f.run((ctx) => retireLogicalCredential(ctx, f.credential.id));
      expect(await f.rows("deviceAttestationCredential")).toMatchObject([
        { status: "active" },
      ]);
      await f.context.adapter.delete({
        model: f.providerModel,
        where: [{ field: "id", value: f.providerCredential.id }],
      });
      await expect(
        f.run((ctx) =>
          readNativeProviderCredential(ctx, {
            id: f.providerCredential.id,
            provider: "android-hardware",
            clientId: CLIENT,
            dpopJkt: f.jkt,
          }),
        ),
      ).resolves.toBeNull();
    });

    it("rolls back Android ownership and all issued tokens if issuance fails", async () => {
      const f = await fixture(database, false, true);
      const { code } = await f.authorize();
      await expect(f.redeem(code, {}, true)).rejects.toThrow(
        "injected-after-tokens",
      );
      expect(await f.rows(f.providerModel)).toMatchObject([
        { userId: null, bindingVersion: 0 },
      ]);
      expect(await f.rows("firstPartyAuthorization")).toMatchObject([
        { status: "code-issued" },
      ]);
      for (const model of [
        "firstPartyTokenFamily",
        "oauthAccessToken",
        "oauthRefreshToken",
      ])
        expect(await f.rows(model)).toEqual([]);
      await expect(f.redeem(code)).resolves.toHaveProperty("access_token");
    });

    it("allows only one subject to claim an Android key under concurrent redemption", async () => {
      const f = await fixture(database, false, true);
      const first = await f.authorize();
      const second = await f.authorize(f.otherUserId);
      const results = await Promise.allSettled([
        f.redeem(first.code),
        f.redeem(second.code),
      ]);
      expect(
        results.filter((result) => result.status === "fulfilled"),
      ).toHaveLength(1);
      const records = await f.rows(f.providerModel);
      expect(records).toHaveLength(1);
      expect([f.userId, f.otherUserId]).toContain(records[0]!.userId);
      expect(await f.rows("firstPartyTokenFamily")).toHaveLength(1);
    });

    it("rechecks Android key ownership before redemption and retires its families", async () => {
      const f = await fixture(database, false, true);
      const first = await f.authorize();
      await f.context.adapter.update({
        model: f.providerModel,
        where: [{ field: "id", value: f.providerCredential.id }],
        update: { dpopJkt: "b".repeat(43) },
      });
      await expect(f.redeem(first.code)).rejects.toThrow();
      await f.context.adapter.update({
        model: f.providerModel,
        where: [{ field: "id", value: f.providerCredential.id }],
        update: { dpopJkt: f.jkt },
      });
      await f.redeem(first.code);
      const pending = await f.authorize();
      await f.run((ctx) => retireLogicalCredential(ctx, f.credential.id));
      expect(await f.rows(f.providerModel)).toMatchObject([
        { status: "revoked", revocationReason: "user" },
      ]);
      expect(await f.rows("firstPartyTokenFamily")).toMatchObject([
        { status: "revoked" },
      ]);
      for (const model of ["oauthAccessToken", "oauthRefreshToken"])
        expect(await f.rows(model)).toEqual([]);
      await expect(f.redeem(pending.code)).rejects.toThrow();
    });

    it("stores only code hashes, consumes once, and associates actual tokens with the bound credential", async () => {
      const f = await fixture(database);
      const { code, attempt } = await f.authorize();
      expect(
        JSON.stringify(await f.rows("firstPartyAuthorization")),
      ).not.toContain(code);
      await expect(
        f.run((ctx) => issueAuthorizationCode(ctx, attempt.id)),
      ).rejects.toMatchObject({ body: { error: "invalid_grant" } });
      const tokens = await f.redeem(code);
      expect(tokens.token_type).toBe("DPoP");
      await expect(f.redeem(code)).rejects.toMatchObject({
        body: { error: "invalid_grant" },
      });
      expect(await f.rows("firstPartyCredential")).toMatchObject([
        { userId: f.userId, revision: 1 },
      ]);
      expect(await f.rows("deviceAttestationCredential")).toMatchObject([
        { userId: f.userId, bindingVersion: 1 },
      ]);
      const families = await f.context.adapter.findMany<FirstPartyTokenFamily>({
        model: "firstPartyTokenFamily",
      });
      expect(families).toHaveLength(1);
      expect(families[0]).toMatchObject({
        credentialId: f.credential.id,
        userId: f.userId,
        authorizationId: attempt.id,
      });
      for (const model of ["oauthAccessToken", "oauthRefreshToken"])
        expect(await f.rows(model)).toMatchObject([
          { referenceId: families[0]!.id },
        ]);
    });

    it("cannot create a second grant for one completed attempt", async () => {
      const f = await fixture(database);
      const attemptId = randomUUID();
      await f.authorize(f.userId, { attemptId });
      await expect(f.authorize(f.userId, { attemptId })).rejects.toThrow();
      expect(await f.rows("firstPartyAuthorization")).toHaveLength(1);
    });

    it("rolls back code consumption, ownership, family and tokens after an issuance failure", async () => {
      const f = await fixture(database);
      const { code } = await f.authorize();
      const proof = f.headers();
      await expect(f.redeem(code, { headers: proof }, true)).rejects.toThrow(
        "injected-after-tokens",
      );
      expect(await f.rows("firstPartyCredential")).toMatchObject([
        { userId: null, revision: 0 },
      ]);
      expect(await f.rows("deviceAttestationCredential")).toMatchObject([
        { userId: null, bindingVersion: 0 },
      ]);
      expect(await f.rows("firstPartyAuthorization")).toMatchObject([
        { status: "code-issued" },
      ]);
      for (const model of [
        "firstPartyTokenFamily",
        "oauthAccessToken",
        "oauthRefreshToken",
      ])
        expect(await f.rows(model)).toEqual([]);
      await expect(f.redeem(code, { headers: proof })).rejects.toMatchObject({
        code: "invalid_dpop_proof",
      });
      await expect(f.redeem(code)).resolves.toHaveProperty("access_token");
    });

    it("rejects a wrong client, PKCE verifier, or proof before binding ownership", async () => {
      const f = await fixture(database);
      const { code } = await f.authorize();
      for (const change of [
        { clientId: "other-client" },
        { codeVerifier: "x".repeat(43) },
        { code: "invalid-code" },
        { codeVerifier: "short" },
      ]) {
        await expect(f.redeem(code, change)).rejects.toMatchObject({
          body: { error: "invalid_grant" },
        });
      }
      await expect(
        f.redeem(code, { headers: new Headers() }),
      ).rejects.toMatchObject({ code: "invalid_dpop_proof" });
      expect(await f.rows("firstPartyCredential")).toMatchObject([
        { userId: null },
      ]);
      expect(await f.rows("firstPartyTokenFamily")).toEqual([]);
    });

    it("rejects a different proof key and stale credential bindings", async () => {
      const f = await fixture(database);
      const { code } = await f.authorize();
      const otherKey = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
      await expect(
        f.redeem(code, { headers: f.headers(otherKey) }),
      ).rejects.toMatchObject({ code: "invalid_dpop_proof" });
      await f.context.adapter.update({
        model: "firstPartyCredential",
        where: [{ field: "id", value: f.credential.id }],
        update: { version: 1 },
      });
      await expect(f.redeem(code)).rejects.toMatchObject({
        body: { error: "invalid_grant" },
      });
      expect(await f.rows("firstPartyTokenFamily")).toEqual([]);
    });

    it("permits fresh authorization for the same bound user without replacing keys", async () => {
      const f = await fixture(database);
      await f.redeem((await f.authorize()).code);
      await f.redeem((await f.authorize()).code);
      expect(await f.rows("firstPartyCredential")).toMatchObject([
        {
          id: f.credential.id,
          userId: f.userId,
          dpopJkt: f.credential.dpopJkt,
        },
      ]);
      expect(await f.rows("firstPartyTokenFamily")).toHaveLength(2);
      await expect(
        f.run((ctx) =>
          enrollLogicalCredential(ctx, {
            issuer: f.credential.issuer,
            clientId: CLIENT,
            applicationId: f.credential.applicationId,
            environment: f.credential.environment,
            provider: f.credential.provider,
            providerCredentialId: f.credential.providerCredentialId,
            dpopJkt: "another-key",
          }),
        ),
      ).rejects.toThrow();
      expect(await f.rows("firstPartyCredential")).toHaveLength(1);
    });

    it("rejects expired code, authorization, evidence, and family windows", async () => {
      const f = await fixture(database);
      for (const field of [
        "codeExpiresAt",
        "expiresAt",
        "assuranceExpiresAt",
        "familyExpiresAt",
      ]) {
        const { code, attempt } = await f.authorize();
        await f.context.adapter.update({
          model: "firstPartyAuthorization",
          where: [{ field: "id", value: attempt.id }],
          update: { [field]: new Date(0) },
        });
        await expect(f.redeem(code)).rejects.toMatchObject({
          body: { error: "invalid_grant" },
        });
      }
      expect(await f.rows("firstPartyTokenFamily")).toEqual([]);
      await expect(
        f.authorize(f.userId, { expiresAt: new Date(0) }),
      ).rejects.toMatchObject({ body: { error: "invalid_grant" } });
    });

    it("allows one winner for concurrent redemption of the same code", async () => {
      const f = await fixture(database);
      const { code } = await f.authorize();
      const results = await Promise.allSettled([
        f.redeem(code),
        f.redeem(code),
      ]);
      expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
      expect(await f.rows("firstPartyTokenFamily")).toHaveLength(1);
      expect(await f.rows("oauthRefreshToken")).toHaveLength(1);
    });

    it("never binds one credential to two competing users", async () => {
      const f = await fixture(database);
      const first = await f.authorize();
      const second = await f.authorize(f.otherUserId);
      const results = await Promise.allSettled([
        f.redeem(first.code),
        f.redeem(second.code),
      ]);
      expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
      const [credential] = await f.context.adapter.findMany<LogicalCredential>({
        model: "firstPartyCredential",
      });
      const families = await f.rows("firstPartyTokenFamily");
      expect(families).toHaveLength(1);
      expect(families).toMatchObject([{ userId: credential!.userId }]);
      const losing = credential!.userId === f.userId ? second : first;
      await expect(f.redeem(losing.code)).rejects.toMatchObject({
        body: { error: "invalid_grant" },
      });
    });

    it("preserves legacy ownership when enrolling a retained provider credential", async () => {
      const f = await fixture(database, true);
      expect(f.credential.userId).toBe(f.userId);
      await expect(
        f.redeem((await f.authorize(f.otherUserId)).code),
      ).rejects.toMatchObject({
        body: { error: "invalid_grant" },
      });
      await expect(
        f.redeem((await f.authorize()).code),
      ).resolves.toHaveProperty("access_token");
      expect(await f.rows("deviceAttestationCredential")).toMatchObject([
        { userId: f.userId, bindingVersion: 1 },
      ]);
    });

    it("rejects enrollment with a substituted provider identity", async () => {
      const f = await fixture(database);
      for (const change of [
        { issuer: "https://other.example" },
        { provider: "other" },
        { applicationId: "TEAM.other" },
        { environment: "production" as const },
        { providerCredentialId: "missing" },
      ]) {
        await expect(
          f.run((ctx) =>
            enrollLogicalCredential(ctx, { ...f.credential, ...change }),
          ),
        ).rejects.toThrow();
      }
      expect(await f.rows("firstPartyCredential")).toHaveLength(1);
    });

    it("invalidates pending native authorization after a legacy ownership claim", async () => {
      const f = await fixture(database);
      const pending = await f.authorize();
      await (
        await f.legacyGrant()
      )(f.otherUserId);
      await expect(f.redeem(pending.code)).rejects.toMatchObject({
        body: { error: "invalid_grant" },
      });
      expect(await f.rows("firstPartyCredential")).toMatchObject([
        { userId: null },
      ]);
      expect(await f.rows("deviceAttestationCredential")).toMatchObject([
        { userId: f.otherUserId },
      ]);
      expect(await f.rows("firstPartyTokenFamily")).toEqual([]);
      // Fresh admission can authorize only the owner established by the legacy path.
      await expect(f.redeem((await f.authorize()).code)).rejects.toMatchObject({
        body: { error: "invalid_grant" },
      });
      await expect(
        f.redeem((await f.authorize(f.otherUserId)).code),
      ).resolves.toHaveProperty("access_token");
    });

    it("allows only one user to win competing native and legacy claims", async () => {
      const f = await fixture(database);
      const pending = await f.authorize();
      const legacy = await f.legacyGrant();
      const results = await Promise.allSettled([
        f.redeem(pending.code),
        legacy(f.otherUserId),
      ]);
      expect(
        results.filter((result) => result.status === "fulfilled"),
      ).toHaveLength(1);
      const [provider] =
        await f.context.adapter.findMany<StoredAttestationCredential>({
          model: "deviceAttestationCredential",
        });
      const [logical] = await f.context.adapter.findMany<LogicalCredential>({
        model: "firstPartyCredential",
      });
      if (results[0].status === "fulfilled") {
        expect(provider!.userId).toBe(f.userId);
        expect(logical!.userId).toBe(f.userId);
        expect(await f.rows("firstPartyTokenFamily")).toMatchObject([
          { userId: f.userId },
        ]);
      } else {
        expect(provider!.userId).toBe(f.otherUserId);
        expect(logical!.userId).toBeNull();
        expect(await f.rows("firstPartyTokenFamily")).toEqual([]);
      }
    });

    it("rejects a provider credential revoked after admission", async () => {
      const f = await fixture(database);
      const { code } = await f.authorize();
      await f.context.adapter.update({
        model: "deviceAttestationCredential",
        where: [{ field: "id", value: f.providerCredential.id }],
        update: { status: "revoked" },
      });
      await expect(f.redeem(code)).rejects.toMatchObject({
        body: { error: "invalid_grant" },
      });
      expect(await f.rows("firstPartyTokenFamily")).toEqual([]);
      expect(await f.rows("firstPartyCredential")).toMatchObject([
        { userId: null },
      ]);
    });

    it("retirement revokes families and token rows and cancels pending codes", async () => {
      const f = await fixture(database);
      const first = await f.authorize();
      const tokens = await f.redeem(first.code);
      await expect(
        f.run(async (ctx) =>
          getOAuthProviderApi(ctx, options).requireActiveAccessToken(
            tokens.access_token,
            CLIENT,
          ),
        ),
      ).resolves.toMatchObject({ active: true });
      const pending = await f.authorize();
      await f.run((ctx) => retireLogicalCredential(ctx, f.credential.id));
      await f.run((ctx) => retireLogicalCredential(ctx, f.credential.id));
      expect(await f.rows("firstPartyCredential")).toMatchObject([
        { status: "revoked", userId: f.userId, version: 1 },
      ]);
      expect(await f.rows("deviceAttestationCredential")).toMatchObject([
        { status: "revoked", userId: f.userId },
      ]);
      expect(await f.rows("firstPartyTokenFamily")).toMatchObject([
        { status: "revoked" },
      ]);
      for (const model of ["oauthAccessToken", "oauthRefreshToken"])
        expect(await f.rows(model)).toEqual([]);
      await expect(
        f.run(async (ctx) =>
          getOAuthProviderApi(ctx, options).requireActiveAccessToken(
            tokens.access_token,
            CLIENT,
          ),
        ),
      ).rejects.toThrow();
      await expect(f.redeem(pending.code)).rejects.toMatchObject({
        body: { error: "invalid_grant" },
      });
    });

    // Exercise 101 complete serial issuances; this checks pagination, not throughput.
    // Coverage and parallel native builds can exceed Vitest's five-second default.
    it("retires all token families beyond the adapter's default page size", async () => {
      const f = await fixture(database);
      for (let index = 0; index < 101; index++)
        await f.redeem((await f.authorize()).code);
      expect(
        await f.context.adapter.count({ model: "firstPartyTokenFamily" }),
      ).toBe(101);
      await f.run((ctx) => retireLogicalCredential(ctx, f.credential.id));
      for (const model of ["oauthAccessToken", "oauthRefreshToken"])
        expect(await f.rows(model)).toEqual([]);
      expect(
        await f.context.adapter.count({
          model: "firstPartyTokenFamily",
          where: [{ field: "status", value: "active" }],
        }),
      ).toBe(0);
    }, 30_000);

    it("retirement racing with redemption leaves no live token family", async () => {
      const f = await fixture(database);
      const { code } = await f.authorize();
      const results = await Promise.allSettled([
        f.redeem(code),
        f.run((ctx) => retireLogicalCredential(ctx, f.credential.id)),
      ]);
      expect(results[1].status).toBe("fulfilled");
      expect(await f.rows("firstPartyCredential")).toMatchObject([
        { status: "revoked" },
      ]);
      expect(
        (
          await f.context.adapter.findMany<FirstPartyTokenFamily>({
            model: "firstPartyTokenFamily",
          })
        ).every((family) => family.status === "revoked"),
      ).toBe(true);
      for (const model of ["oauthAccessToken", "oauthRefreshToken"])
        expect(await f.rows(model)).toEqual([]);
    });
  });
}
