import type { GenericEndpointContext } from "@better-auth/core";
import { createAuthEndpoint } from "better-auth/api";
import { z } from "zod";
import {
  maintainAndroidUnboundCredentials,
  retireAndroidProviderCredential,
} from "./first-party/android-maintenance.js";
import { requireNativeAccess } from "./first-party/token-lifecycle.js";
import { createHash, randomUUID, sign } from "node:crypto";
import { getTestInstance } from "better-auth/test";
import type { BetterAuthPlugin } from "better-auth";
import { oauthProvider, type OAuthOptions } from "@better-auth/oauth-provider";
import { describe, expect, it } from "vitest";
import { createAndroidHardwareProvider } from "./android/provider.js";
import {
  policy as keyPolicy,
  signer,
} from "./android/fixtures/key-description.fixture.js";
import { attestedKey } from "./android/fixtures/attested-key.fixture.js";
import { createNativeFirstPartyPlugin } from "./first-party/plugin.js";
import { androidRegistrationRequestHash } from "./first-party/android-admission.js";
import type { NativeAdmissionBinding } from "./first-party/admission-binding.js";
import type { NativeTokenOptions } from "./first-party/token-lifecycle.js";
import type { NativeAttempt } from "./first-party/continuation.js";

interface Wire {
  keyChallengeToken: string;
  attestationChallenge: string;
  grantToken: string;
  credentialId: string;
  keyId: string;
  challengeToken: string;
  requestHash: string;
  expiresAt: string;
  issuedAt: string;
  auth_session: string;
  authorization_code: string;
  access_token: string;
  refresh_token: string;
  token_type: string;
  error: string;
  step: { id: string; kind: string };
}
async function fixture(database: "sqlite" | "postgres", trustSeconds = 3600) {
  let root = "";
  let offline = false;
  let revoked: Record<string, { status: string }> = {};
  const verdicts = new Map<string, unknown>();
  let decodes = 0;
  let holdDecode: (() => Promise<void>) | undefined;
  const fetcher: typeof fetch = (url, init) => {
    if (offline) return Promise.reject(new Error("test provider unavailable"));
    const headers = {
      "cache-control": "max-age=86400",
      date: new Date().toUTCString(),
    };
    if (url === "https://android.googleapis.com/attestation/root")
      return Promise.resolve(Response.json([root], { headers }));
    if (url === "https://android.googleapis.com/attestation/status")
      return Promise.resolve(Response.json({ entries: revoked }, { headers }));
    decodes++;
    if (typeof init?.body !== "string")
      throw new Error("Expected Google JSON request");
    const body = JSON.parse(init.body) as { integrity_token: string };
    return (holdDecode?.() ?? Promise.resolve()).then(() =>
      Response.json(verdicts.get(body.integrity_token) ?? {}),
    );
  };
  const provider = createAndroidHardwareProvider(
    {
      key: keyPolicy,
      play: {
        packageName: keyPolicy.packageName,
        policyVersion: "play-v1",
        signingCertificateSets: [[signer.toString("base64url")]],
        minimumVersionCode: "42",
        maxAgeSeconds: 120,
        clockSkewSeconds: 0,
        requireStrongIntegrity: false,
        getAccessToken: () => Promise.resolve("test-access-token"),
      },
      trust: { maxCacheSeconds: trustSeconds },
    },
    { fetch: fetcher },
  );
  const oauthOptions: OAuthOptions<string[]> = {
    loginPage: "/login",
    consentPage: "/consent",
    disableJwtPlugin: true,
    scopes: ["offline_access"],
  };
  const options: NativeTokenOptions = {
    oauth: oauthOptions,
    applications: [
      {
        clientId: "android-mobile",
        provider,
        applicationId: keyPolicy.packageName,
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
  const operations = new Map<
    string,
    (context: GenericEndpointContext) => Promise<unknown>
  >();
  const oauth = oauthProvider(oauthOptions);
  const { auth, testUser } = await getTestInstance(
    {
      plugins: [
        {
          ...oauth,
          endpoints: oauth.endpoints as unknown as NonNullable<
            BetterAuthPlugin["endpoints"]
          >,
        },
        createNativeFirstPartyPlugin(options),
        {
          id: "android-test-probe",
          endpoints: {
            androidTestOperation: createAuthEndpoint(
              "/test-only/android-operation",
              { method: "POST", body: z.object({ id: z.string() }) },
              async (context) => {
                const operation = operations.get(context.body.id);
                if (!operation) throw new Error("Missing test operation");
                return operation(context);
              },
            ),
            androidTestResource: createAuthEndpoint(
              "/test-only/android-resource",
              { method: "GET", requireRequest: true },
              async (context) => {
                const family = await requireNativeAccess(context, options, {
                  headers: context.request.headers,
                  method: "GET",
                  url: context.context.baseURL + "/test-only/android-resource",
                  scopes: [],
                });
                return context.json({ userId: family.userId });
              },
            ),
          },
        },
      ],
    },
    { testWith: database, transaction: true },
  );
  const ctx = await auth.$context;
  const run = async <T>(
    operation: (context: GenericEndpointContext) => Promise<T>,
  ): Promise<T> => {
    const id = randomUUID();
    operations.set(id, operation);
    try {
      return (await auth.api.androidTestOperation!({ body: { id } })) as T;
    } finally {
      operations.delete(id);
    }
  };
  await ctx.adapter.create({
    model: "oauthClient",
    data: {
      clientId: "android-mobile",
      redirectUris: [],
      tokenEndpointAuthMethod: "none",
      grantTypes: ["authorization_code", "refresh_token"],
      scopes: ["offline_access"],
      disabled: false,
    },
  });
  const keyStateResponse = await auth.handler(
    new Request(`${ctx.baseURL}/first-party/android/key-challenge`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ clientId: "android-mobile" }),
    }),
  );
  expect(keyStateResponse.status).toBe(200);
  const keyState = (await keyStateResponse.json()) as Wire;
  const key = await attestedKey(
    Buffer.from(keyState.attestationChallenge, "base64url"),
  );
  root = key.root;
  const binding: NativeAdmissionBinding = {
    profile: "device-attestation-fipa-v1",
    mode: "native",
    issuer: ctx.baseURL,
    clientId: "android-mobile",
    provider: provider.id,
    applicationId: keyPolicy.packageName,
    environment: "production",
    attemptId: Buffer.alloc(32, 2).toString("base64url"),
    codeChallenge: createHash("sha256")
      .update("v".repeat(43))
      .digest("base64url"),
    codeChallengeMethod: "S256",
    dpopJkt: key.jkt,
    scopes: ["offline_access"],
    resources: [],
  };
  const proof = (path: string, proofKey = key, accessToken?: string) => {
    const enc = (value: unknown) =>
      Buffer.from(JSON.stringify(value)).toString("base64url");
    const unsigned = `${enc({ alg: "ES256", typ: "dpop+jwt", jwk: proofKey.jwk })}.${enc({ htm: accessToken ? "GET" : "POST", ...(accessToken ? { ath: createHash("sha256").update(accessToken).digest("base64url") } : {}), htu: ctx.baseURL + path, iat: Math.floor(Date.now() / 1000), jti: randomUUID() })}`;
    return `${unsigned}.${sign("sha256", Buffer.from(unsigned), { key: proofKey.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url")}`;
  };
  const call = async (
    path: string,
    body: object,
    dpop: string | null = proof(path),
    form = false,
  ) => {
    const response = await auth.handler(
      new Request(ctx.baseURL + path, {
        method: "POST",
        headers: {
          "content-type": form
            ? "application/x-www-form-urlencoded"
            : "application/json",
          ...(dpop ? { dpop } : {}),
        },
        body: form
          ? new URLSearchParams(body as Record<string, string>)
          : JSON.stringify(body),
      }),
    );
    return { status: response.status, body: (await response.json()) as Wire };
  };
  const token = (requestHash: string) => {
    const value = randomUUID();
    verdicts.set(value, {
      tokenPayloadExternal: {
        requestDetails: {
          requestPackageName: keyPolicy.packageName,
          requestHash,
          timestampMillis: String(Date.now()),
        },
        appIntegrity: {
          appRecognitionVerdict: "PLAY_RECOGNIZED",
          packageName: keyPolicy.packageName,
          certificateSha256Digest: [signer.toString("base64url")],
          versionCode: "42",
        },
        accountDetails: { appLicensingVerdict: "LICENSED" },
        deviceIntegrity: {
          deviceRecognitionVerdict: ["MEETS_DEVICE_INTEGRITY"],
        },
      },
    });
    return value;
  };
  const registerBody = () => ({
    binding,
    keyChallengeToken: keyState.keyChallengeToken,
    certificateChain: key.chain,
    integrityToken: token(
      androidRegistrationRequestHash(binding, keyState.attestationChallenge),
    ),
  });
  const register = () => call("/first-party/android/register", registerBody());
  const challenge = () =>
    call("/first-party/attestation/challenge", { binding, keyId: key.jkt });
  const verify = (state: Wire, integrityToken = token(state.requestHash)) =>
    call("/first-party/attestation/verify", {
      clientId: binding.clientId,
      keyId: key.jkt,
      challengeToken: state.challengeToken,
      evidence: integrityToken,
    });
  const start = (grantToken: string) =>
    call(
      "/first-party/authorization-challenge",
      {
        profile: binding.profile,
        client_id: binding.clientId,
        response_type: "code",
        scope: "offline_access",
        code_challenge: binding.codeChallenge,
        code_challenge_method: "S256",
        authorization_attempt: binding.attemptId,
        device_attestation: grantToken,
      },
      undefined,
      true,
    );
  const login = async (grantToken: string) => {
    const pending = await start(grantToken);
    expect(pending.status).toBe(403);
    const completed = await call(
      "/first-party/authorization-challenge",
      {
        profile: binding.profile,
        client_id: binding.clientId,
        auth_session: pending.body.auth_session,
        step_id: pending.body.step.id,
        response: JSON.stringify({
          kind: "password",
          email: testUser.email,
          password: testUser.password,
        }),
      },
      undefined,
      true,
    );
    expect(completed.status).toBe(200);
    const tokens = await call(
      "/oauth2/token",
      {
        client_id: binding.clientId,
        grant_type: "authorization_code",
        code: completed.body.authorization_code,
        code_verifier: "v".repeat(43),
      },
      undefined,
      true,
    );
    expect(tokens.status).toBe(200);
    return tokens.body;
  };
  const access = (token: string) =>
    auth.handler(
      new Request(ctx.baseURL + "/test-only/android-resource", {
        headers: {
          authorization: `DPoP ${token}`,
          dpop: proof("/test-only/android-resource", key, token),
        },
      }),
    );
  return {
    auth,
    run,
    login,
    access,
    maintain: (batchSize = 25) =>
      run((context) =>
        maintainAndroidUnboundCredentials(
          context,
          {
            clientId: binding.clientId,
            applicationId: binding.applicationId,
            retentionSeconds: 7 * 86_400,
          },
          batchSize,
        ),
      ),
    ctx,
    testUser,
    binding,
    key,
    keyState,
    call,
    proof,
    register,
    registerBody,
    challenge,
    verify,
    start,
    token,
    decodes: () => decodes,
    offline: () => {
      offline = true;
    },
    replaceRoot: (value: string) => {
      root = value;
    },
    holdDecode: (callback: () => Promise<void>) => {
      holdDecode = callback;
    },
    revoke: () => {
      revoked = { "104": { status: "REVOKED" } };
    },
    rows: (model: string) =>
      ctx.adapter.findMany<Record<string, unknown>>({ model }),
  };
}
for (const database of ["sqlite", "postgres"] as const) {
  describe.runIf(
    database === "sqlite"
      ? Number(process.versions.node.split(".")[0]) >= 22
      : process.env.TEST_POSTGRES === "true",
  )(`Android native admission (${database})`, () => {
    it("registers the exact certified proof key and carries distinct evidence into native password login", async () => {
      const f = await fixture(database);
      const registered = await f.register();
      expect(registered.status).toBe(200);
      expect(registered.body.keyId).toBe(f.key.jkt);
      const rows = await f.rows("firstPartyAndroidKey");
      expect(rows).toHaveLength(1);
      expect(rows[0]).not.toHaveProperty("counter");
      const start = await f.start(registered.body.grantToken);
      expect(start.status).toBe(403);
      const attempts = await f.ctx.adapter.findMany<NativeAttempt>({
        model: "firstPartyAttempt",
      });
      expect(attempts[0]!.receipt.evidence).toMatchObject([
        {
          provider: "android-key-attestation",
          kind: "credential-key",
          dpopJkt: f.key.jkt,
        },
        { provider: "play-integrity", kind: "interaction-verdict" },
      ]);
      expect(attempts[0]!.evidenceExpiresAt.getTime()).toBeLessThanOrEqual(
        Date.parse(registered.body.expiresAt),
      );
      const completed = await f.call(
        "/first-party/authorization-challenge",
        {
          profile: f.binding.profile,
          client_id: f.binding.clientId,
          auth_session: start.body.auth_session,
          step_id: start.body.step.id,
          response: JSON.stringify({
            kind: "password",
            email: f.testUser.email,
            password: f.testUser.password,
          }),
        },
        undefined,
        true,
      );
      expect(completed.status).toBe(200);
      const tokens = await f.call(
        "/oauth2/token",
        {
          client_id: f.binding.clientId,
          grant_type: "authorization_code",
          code: completed.body.authorization_code,
          code_verifier: "v".repeat(43),
        },
        undefined,
        true,
      );
      expect(tokens.status).toBe(200);
      expect(tokens.body.token_type).toBe("DPoP");
      expect(await f.rows("firstPartyTokenFamily")).toMatchObject([
        {
          assurance: {
            evidenceKind: "combined",
            evidence: [
              { kind: "credential-key" },
              { kind: "interaction-verdict" },
            ],
          },
        },
      ]);
      const refreshed = await f.call(
        "/oauth2/token",
        {
          client_id: f.binding.clientId,
          grant_type: "refresh_token",
          refresh_token: tokens.body.refresh_token,
        },
        undefined,
        true,
      );
      expect(refreshed.status).toBe(200);
      expect(refreshed.body.refresh_token).not.toBe(tokens.body.refresh_token);
    });
    it("requires proof before registration and never falls back after a bad Play binding", async () => {
      const f = await fixture(database);
      expect(
        (await f.call("/first-party/android/register", f.registerBody(), null))
          .status,
      ).toBe(400);
      expect(f.decodes()).toBe(0);
      expect(
        (
          await f.call("/first-party/android/register", {
            ...f.registerBody(),
            integrityToken: f.token("a".repeat(43)),
          })
        ).status,
      ).toBe(400);
      expect(await f.rows("firstPartyAndroidKey")).toEqual([]);
      expect((await f.register()).status).toBe(400);
      expect(f.decodes()).toBe(1);
    });
    it("rejects a certificate for another key despite a valid proof", async () => {
      const f = await fixture(database);
      const other = await attestedKey(
        Buffer.from(f.keyState.attestationChallenge, "base64url"),
      );
      expect(
        (
          await f.call(
            "/first-party/android/register",
            {
              ...f.registerBody(),
              binding: { ...f.binding, dpopJkt: other.jkt },
            },
            f.proof("/first-party/android/register", other),
          )
        ).status,
      ).toBe(400);
      expect(f.decodes()).toBe(0);
      expect(await f.rows("firstPartyAndroidKey")).toEqual([]);
    });
    it("permits one registration winner and consumes the receipt once", async () => {
      const f = await fixture(database);
      const results = await Promise.all([f.register(), f.register()]);
      expect(results.map((r) => r.status).sort()).toEqual([200, 400]);
      expect(await f.rows("firstPartyAndroidKey")).toHaveLength(1);
      const accepted = results.find((r) => r.status === 200)!;
      expect((await f.start(accepted.body.grantToken)).status).toBe(403);
      expect((await f.start(accepted.body.grantToken)).status).toBe(400);
    });
    it("renews evidence with the retained key and independent replay checks", async () => {
      const f = await fixture(database);
      expect((await f.register()).status).toBe(200);
      const challenge = await f.challenge();
      expect(challenge.status).toBe(200);
      expect(
        (
          await f.call(
            "/first-party/attestation/challenge",
            { binding: f.binding, keyId: f.key.jkt },
            null,
          )
        ).status,
      ).toBe(400);
      const wrong = await attestedKey(Buffer.alloc(32, 8));
      expect(
        (
          await f.call(
            "/first-party/attestation/verify",
            {
              clientId: f.binding.clientId,
              keyId: wrong.jkt,
              challengeToken: challenge.body.challengeToken,
              evidence: f.token(challenge.body.requestHash),
            },
            f.proof("/first-party/attestation/verify", wrong),
          )
        ).status,
      ).toBe(400);
      // A proof from another key cannot burn the legitimate key's challenge.
      const first = await f.verify(challenge.body);
      expect(first.status).toBe(200);
      expect((await f.verify(challenge.body)).status).toBe(400);
      expect(await f.rows("firstPartyAndroidKey")).toHaveLength(1);
      expect((await f.start(first.body.grantToken)).status).toBe(403);
    });
    it("binds enrollment to the server nonce and rejects client-selected validation dates", async () => {
      const f = await fixture(database);
      expect(
        (
          await f.call("/first-party/android/register", {
            ...f.registerBody(),
            verifiedAtCreation: "2020-01-01T00:00:00Z",
          })
        ).status,
      ).toBe(400);
      const second = await f.call("/first-party/android/key-challenge", {
        clientId: f.binding.clientId,
      });
      expect(
        (
          await f.call("/first-party/android/register", {
            ...f.registerBody(),
            keyChallengeToken: second.body.keyChallengeToken,
          })
        ).status,
      ).toBe(400);
      expect(f.decodes()).toBe(0);
      expect(await f.rows("firstPartyAndroidKey")).toEqual([]);
    });
    it("rejects expired registration challenges and stale provider ownership", async () => {
      const f = await fixture(database);
      await f.ctx.adapter.updateMany({
        model: "verification",
        where: [
          {
            field: "identifier",
            operator: "starts_with",
            value: "first-party:android:key:",
          },
        ],
        update: { expiresAt: new Date(0) },
      });
      expect((await f.register()).status).toBe(400);
      const g = await fixture(database);
      expect((await g.register()).status).toBe(200);
      const challenge = await g.challenge();
      await g.ctx.adapter.updateMany({
        model: "firstPartyAndroidKey",
        where: [{ field: "dpopJkt", value: g.key.jkt }],
        update: { bindingVersion: 1 },
      });
      expect((await g.verify(challenge.body)).status).toBe(400);
      expect(g.decodes()).toBe(1);
    });
    it("never grants a retired key fresh admission", async () => {
      const f = await fixture(database);
      const registered = await f.register();
      expect(registered.status).toBe(200);
      const challenge = await f.challenge();
      await f.ctx.adapter.updateMany({
        model: "firstPartyAndroidKey",
        where: [{ field: "dpopJkt", value: f.key.jkt }],
        update: { status: "revoked" },
      });
      expect((await f.verify(challenge.body)).status).toBe(400);
      expect((await f.start(registered.body.grantToken)).status).toBe(400);
      expect((await f.challenge()).status).toBe(400);
    });
    it("rechecks retirement after remote verification finishes", async () => {
      const f = await fixture(database);
      expect((await f.register()).status).toBe(200);
      const challenge = await f.challenge();
      let started!: () => void;
      const waiting = new Promise<void>((resolve) => {
        started = resolve;
      });
      let release!: () => void;
      f.holdDecode(() => {
        started();
        return new Promise<void>((resolve) => {
          release = resolve;
        });
      });
      const verification = f.verify(challenge.body);
      await waiting;
      try {
        await f.ctx.adapter.updateMany({
          model: "firstPartyAndroidKey",
          where: [{ field: "dpopJkt", value: f.key.jkt }],
          update: { status: "revoked" },
        });
      } finally {
        release();
      }
      expect((await verification).status).toBe(400);
    });
    it("rolls key registration back when storing its receipt fails", async () => {
      const f = await fixture(database);
      const transaction = f.ctx.adapter.transaction.bind(f.ctx.adapter);
      f.ctx.adapter.transaction = (callback) =>
        transaction((adapter) => {
          const create = adapter.create.bind(adapter);
          adapter.create = (input: Parameters<typeof adapter.create>[0]) => {
            if (input.model === "verification")
              return Promise.reject(new Error("injected receipt failure"));
            return create(input);
          };
          return callback(adapter);
        });
      try {
        expect((await f.register()).status).toBe(400);
      } finally {
        f.ctx.adapter.transaction = transaction;
      }
      expect(await f.rows("firstPartyAndroidKey")).toEqual([]);
    });
    it("retires existing authority when current Google status revokes the key", async () => {
      const f = await fixture(database, 1);
      const registration = await f.register();
      expect(registration.status).toBe(200);
      const tokens = await f.login(registration.body.grantToken);
      expect((await f.access(tokens.access_token)).status).toBe(200);
      f.revoke();
      await new Promise((resolve) => setTimeout(resolve, 1100));
      const challenge = await f.challenge();
      expect((await f.verify(challenge.body)).status).toBe(400);
      expect(f.decodes()).toBe(1);
      expect(await f.rows("firstPartyAndroidKey")).toMatchObject([
        {
          status: "revoked",
          publicKey: null,
          certificateChain: null,
          revocationReason: "provider",
        },
      ]);
      expect(await f.rows("firstPartyCredential")).toMatchObject([
        { status: "revoked" },
      ]);
      expect(await f.rows("firstPartyTokenFamily")).toMatchObject([
        { status: "revoked" },
      ]);
      expect(await f.rows("firstPartySession")).toMatchObject([
        { status: "revoked" },
      ]);
      for (const model of ["oauthAccessToken", "oauthRefreshToken"])
        expect(await f.rows(model)).toEqual([]);
      expect((await f.access(tokens.access_token)).status).toBe(401);
      expect(
        (
          await f.call(
            "/oauth2/token",
            {
              client_id: f.binding.clientId,
              grant_type: "refresh_token",
              refresh_token: tokens.refresh_token,
            },
            undefined,
            true,
          )
        ).status,
      ).toBe(400);
      await f.run((context) =>
        retireAndroidProviderCredential(
          context,
          registration.body.credentialId,
        ),
      );
      expect(await f.rows("firstPartyAndroidKey")).toMatchObject([
        { bindingVersion: 2 },
      ]);
    });
    it("does not retire existing authority on a temporary Google failure", async () => {
      const f = await fixture(database, 1);
      const registered = await f.register();
      const tokens = await f.login(registered.body.grantToken);
      f.offline();
      await new Promise((resolve) => setTimeout(resolve, 1100));
      const challenge = await f.challenge();
      expect((await f.verify(challenge.body)).status).toBe(400);
      expect(await f.rows("firstPartyAndroidKey")).toMatchObject([
        { status: "active" },
      ]);
      expect((await f.access(tokens.access_token)).status).toBe(200);
    });
    it("retires a registered key after its root is withdrawn from a valid trust snapshot", async () => {
      const f = await fixture(database, 1);
      const registered = await f.register();
      const other = await attestedKey(Buffer.alloc(32, 10));
      f.replaceRoot(other.root);
      await new Promise((resolve) => setTimeout(resolve, 1100));
      const challenge = await f.challenge();
      expect((await f.verify(challenge.body)).status).toBe(400);
      expect(await f.rows("firstPartyAndroidKey")).toMatchObject([
        {
          id: registered.body.credentialId,
          status: "revoked",
          revocationReason: "provider",
        },
      ]);
    });
    it("rolls provider retirement and token deletion back together on storage failure", async () => {
      const f = await fixture(database);
      const registration = await f.register();
      const tokens = await f.login(registration.body.grantToken);
      const transaction = f.ctx.adapter.transaction.bind(f.ctx.adapter);
      f.ctx.adapter.transaction = (callback) =>
        transaction((adapter) => {
          const remove = adapter.deleteMany.bind(adapter);
          adapter.deleteMany = (input) => {
            if (input.model === "oauthRefreshToken")
              return Promise.reject(new Error("injected retirement failure"));
            return remove(input);
          };
          return callback(adapter);
        });
      try {
        await expect(
          f.run((context) =>
            retireAndroidProviderCredential(
              context,
              registration.body.credentialId,
            ),
          ),
        ).rejects.toThrow("injected retirement failure");
      } finally {
        f.ctx.adapter.transaction = transaction;
      }
      expect(await f.rows("firstPartyAndroidKey")).toMatchObject([
        { status: "active", bindingVersion: 1 },
      ]);
      expect(await f.rows("firstPartyCredential")).toMatchObject([
        { status: "active" },
      ]);
      expect(await f.rows("firstPartyTokenFamily")).toMatchObject([
        { status: "active" },
      ]);
      for (const model of ["oauthAccessToken", "oauthRefreshToken"])
        expect(await f.rows(model)).toHaveLength(1);
      expect((await f.access(tokens.access_token)).status).toBe(200);
    });
    it("preserves a key that acquired ownership after a stale cleanup read", async () => {
      const f = await fixture(database);
      const registration = await f.register();
      const user = await f.ctx.adapter.findOne<{ id: string }>({
        model: "user",
        where: [{ field: "email", value: f.testUser.email }],
      });
      await f.ctx.adapter.updateMany({
        model: "firstPartyAndroidKey",
        where: [{ field: "id", value: registration.body.credentialId }],
        update: { unboundExpiresAt: new Date(0) },
      });
      const findMany = f.ctx.adapter.findMany.bind(f.ctx.adapter);
      let changed = false;
      f.ctx.adapter.findMany = async <T>(
        input: Parameters<typeof findMany>[0],
      ) => {
        const result = await findMany<T>(input);
        if (!changed && input.model === "firstPartyAndroidKey") {
          changed = true;
          await f.ctx.adapter.updateMany({
            model: "firstPartyAndroidKey",
            where: [{ field: "id", value: registration.body.credentialId }],
            update: { userId: user!.id, bindingVersion: 1 },
          });
        }
        return result;
      };
      try {
        expect(await f.maintain()).toEqual({ expired: 0, purged: 0 });
      } finally {
        f.ctx.adapter.findMany = findMany;
      }
      expect(await f.rows("firstPartyAndroidKey")).toMatchObject([
        { status: "active", userId: user!.id, bindingVersion: 1 },
      ]);
    });
    it("expires never-bound keys, erases evidence and purges only after retention", async () => {
      const f = await fixture(database);
      const registration = await f.register();
      expect((await f.start(registration.body.grantToken)).status).toBe(403);
      await f.ctx.adapter.updateMany({
        model: "firstPartyAndroidKey",
        where: [{ field: "id", value: registration.body.credentialId }],
        update: { unboundExpiresAt: new Date(0) },
      });
      expect(await f.maintain()).toEqual({ expired: 1, purged: 0 });
      expect(await f.rows("firstPartyAndroidKey")).toMatchObject([
        {
          status: "expired",
          publicKey: null,
          certificateChain: null,
          attestationChallenge: null,
          keyEvidence: null,
          userId: null,
        },
      ]);
      expect(await f.rows("firstPartyCredential")).toMatchObject([
        { status: "revoked" },
      ]);
      expect(await f.rows("firstPartyAttempt")).toMatchObject([
        { status: "cancelled" },
      ]);
      expect((await f.challenge()).status).toBe(400);
      expect(await f.maintain()).toEqual({ expired: 0, purged: 0 });
      await f.ctx.adapter.updateMany({
        model: "firstPartyAndroidKey",
        where: [{ field: "id", value: registration.body.credentialId }],
        update: { updatedAt: new Date(Date.now() - 8 * 86_400_000) },
      });
      expect(await f.maintain()).toEqual({ expired: 0, purged: 1 });
      expect(await f.rows("firstPartyAndroidKey")).toEqual([]);
    });
    it("bounds each cleanup batch and isolates application and client scope", async () => {
      const f = await fixture(database);
      const registered = await f.register();
      const template = { ...(await f.rows("firstPartyAndroidKey"))[0]! };
      delete template.id;
      // Lifecycle selection fixtures; these clones are not attestation evidence.
      for (const change of [
        {},
        {},
        { clientId: "another-client" },
        { applicationId: "io.other.app" },
      ]) {
        await f.ctx.adapter.create({
          model: "firstPartyAndroidKey",
          data: {
            ...template,
            lookupKey: randomUUID(),
            unboundExpiresAt: new Date(0),
            ...change,
          },
        });
      }
      await f.ctx.adapter.updateMany({
        model: "firstPartyAndroidKey",
        where: [{ field: "id", value: registered.body.credentialId }],
        update: { unboundExpiresAt: new Date(0) },
      });
      expect(await f.maintain(1)).toEqual({ expired: 1, purged: 0 });
      expect(
        (await f.rows("firstPartyAndroidKey")).filter(
          (row) => row.status === "expired",
        ),
      ).toHaveLength(1);
      // The public preparation endpoint invokes the same bounded maintenance.
      expect(
        (
          await f.call("/first-party/android/key-challenge", {
            clientId: f.binding.clientId,
          })
        ).status,
      ).toBe(200);
      const rows = await f.rows("firstPartyAndroidKey");
      expect(rows.filter((row) => row.status === "expired")).toHaveLength(3);
      expect(rows.filter((row) => row.status === "active")).toHaveLength(2);
      await expect(f.maintain(101)).rejects.toThrow(
        "Invalid Android credential maintenance bounds",
      );
    });
    it("keeps bound and revoked ownership tombstones regardless of age", async () => {
      const f = await fixture(database);
      const registration = await f.register();
      await f.login(registration.body.grantToken);
      await f.ctx.adapter.updateMany({
        model: "firstPartyAndroidKey",
        where: [{ field: "id", value: registration.body.credentialId }],
        update: { unboundExpiresAt: new Date(0), updatedAt: new Date(0) },
      });
      expect(await f.maintain()).toEqual({ expired: 0, purged: 0 });
      await f.run((context) =>
        retireAndroidProviderCredential(
          context,
          registration.body.credentialId,
        ),
      );
      await f.ctx.adapter.updateMany({
        model: "firstPartyAndroidKey",
        where: [{ field: "id", value: registration.body.credentialId }],
        update: { updatedAt: new Date(0) },
      });
      expect(await f.maintain()).toEqual({ expired: 0, purged: 0 });
      expect(await f.rows("firstPartyAndroidKey")).toMatchObject([
        { status: "revoked", userId: expect.any(String) as unknown },
      ]);
    });
  });
}
