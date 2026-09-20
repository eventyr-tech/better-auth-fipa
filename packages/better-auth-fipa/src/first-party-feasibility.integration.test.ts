import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { createDpopReplayStore } from "@better-auth/core/oauth2";
import { verifyFirstPartyDpop } from "./first-party/dpop.js";
import { withFirstPartyTransaction } from "./first-party/transaction.js";
import {
  getOAuthProviderApi,
  oauthProvider,
  type OAuthOptions,
  type OAuthTokenResponse,
} from "@better-auth/oauth-provider";
import type { GenericEndpointContext } from "@better-auth/core";
import type { BetterAuthPlugin } from "better-auth";
import {
  APIError,
  createAuthEndpoint,
  createAuthMiddleware,
} from "better-auth/api";
import { getTestInstance } from "./fixtures/auth-instance.js";
import { describe, expect, it } from "vitest";
import { z } from "zod";

// These endpoints exist only in this test. They exercise the public minting seam,
// not an authorization flow: identity and confirmation below are fixture data.
const CLIENT_ID = "native-feasibility";
const REFERENCE_ID = "credential-family-fixture";
const CONFIRMATION = { jkt: "verified-key-fixture" };
const options = {
  loginPage: "/login",
  consentPage: "/consent",
  disableJwtPlugin: true,
  scopes: ["offline_access"],
} satisfies OAuthOptions;
const sqliteAvailable = Number(process.versions.node.split(".")[0]) >= 22;

for (const database of ["sqlite", "postgres"] as const) {
  describe.runIf(
    database === "sqlite"
      ? sqliteAvailable && process.env.TEST_POSTGRES !== "true"
      : process.env.TEST_POSTGRES === "true",
  )(`First-party issuance feasibility (${database})`, () => {
    it("reserves a challenge proof once across independent database replay stores", async () => {
      const { auth } = await getTestInstance({}, { testWith: database });
      const context = await auth.$context;
      const key = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
      const nowSeconds = Math.floor(Date.now() / 1000);
      const endpointUrl =
        "https://auth.example/api/auth/first-party/authorization-challenge";
      const encode = (value: unknown) =>
        Buffer.from(JSON.stringify(value)).toString("base64url");
      const unsigned = [
        encode({
          alg: "ES256",
          typ: "dpop+jwt",
          jwk: key.publicKey.export({ format: "jwk" }),
        }),
        encode({
          htm: "POST",
          htu: endpointUrl,
          iat: nowSeconds,
          jti: "same-proof-on-two-workers",
        }),
      ].join(".");
      const proof = `${unsigned}.${sign("sha256", Buffer.from(unsigned), { key: key.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url")}`;
      const verify = () =>
        verifyFirstPartyDpop({
          headers: new Headers({ dpop: proof }),
          endpointUrl,
          method: "POST",
          nowSeconds,
          replayStore: createDpopReplayStore(context.internalAdapter),
        });
      const results = await Promise.allSettled([verify(), verify()]);
      expect(
        results.filter((result) => result.status === "fulfilled"),
      ).toHaveLength(1);
      expect(
        results.filter((result) => result.status === "rejected"),
      ).toHaveLength(1);
      await expect(verify()).rejects.toMatchObject({
        code: "invalid_dpop_proof",
      });
    });

    it("commits token rows and association together and rolls both back on failure", async () => {
      const oauth = oauthProvider(options);
      // 1.7.5's generated OpenAPI union includes optional undefined properties
      // incompatible with exactOptionalPropertyTypes. Only erase endpoint
      // metadata inference here, not our probe's endpoint or response types.
      const oauthPlugin: BetterAuthPlugin = {
        ...oauth,
        endpoints: oauth.endpoints as unknown as NonNullable<
          BetterAuthPlugin["endpoints"]
        >,
      };
      const verifier = "v".repeat(43);
      const challenge = createHash("sha256")
        .update(verifier)
        .digest("base64url");
      const fixtureState: { userId: string | undefined } = {
        userId: undefined,
      };
      const fixture = await getTestInstance(
        {
          plugins: [
            oauthPlugin,
            {
              id: "first-party-feasibility",
              hooks: {
                before: [
                  {
                    matcher: (ctx) => ctx.path === "/oauth2/token",
                    handler: createAuthMiddleware(async (ctx) => {
                      const body = z
                        .object({
                          grant_type: z.literal("authorization_code"),
                          code: z.literal("fipa_test_code"),
                          client_id: z.literal(CLIENT_ID),
                          code_verifier: z.string(),
                        })
                        .safeParse(ctx.body);
                      if (!body.success || !fixtureState.userId)
                        throw new APIError("BAD_REQUEST", {
                          error: "invalid_grant",
                        });
                      if (
                        createHash("sha256")
                          .update(body.data.code_verifier)
                          .digest("base64url") !== challenge
                      ) {
                        throw new APIError("BAD_REQUEST", {
                          error: "invalid_grant",
                        });
                      }
                      const proof = await verifyFirstPartyDpop({
                        headers: ctx.headers ?? new Headers(),
                        endpointUrl: `${ctx.context.baseURL}/oauth2/token`,
                        method: "POST",
                        replayStore: createDpopReplayStore(
                          ctx.context.internalAdapter,
                        ),
                      });
                      ctx.setHeader("Cache-Control", "no-store");
                      return issueFixture(ctx, {
                        userId: fixtureState.userId,
                        fail: false,
                        referenceId: "native-http-fixture",
                        confirmation: { jkt: proof.jkt },
                      });
                    }),
                  },
                ],
              },
              schema: {
                feasibilityAssociation: {
                  fields: {
                    referenceId: {
                      type: "string",
                      required: true,
                      unique: true,
                    },
                    userId: { type: "string", required: true },
                  },
                },
              },
              endpoints: {
                probeIssuance: createAuthEndpoint(
                  "/test-only/issuance",
                  {
                    method: "POST",
                    body: z.object({ userId: z.string(), fail: z.boolean() }),
                  },
                  async (ctx) => {
                    return issueFixture(ctx, ctx.body);
                  },
                ),
              },
            },
          ],
        },
        { testWith: database, transaction: true },
      );
      const { auth, testUser } = fixture;
      const context = await auth.$context;
      const user = await context.adapter.findOne<{ id: string }>({
        model: "user",
        where: [{ field: "email", value: testUser.email }],
      });
      if (!user) throw new Error("Missing test user");
      fixtureState.userId = user.id;
      await context.adapter.create({
        model: "oauthClient",
        data: {
          clientId: CLIENT_ID,
          redirectUris: [],
          tokenEndpointAuthMethod: "none",
          grantTypes: ["authorization_code", "refresh_token"],
          scopes: ["offline_access"],
          disabled: false,
        },
      });
      await expect(
        auth.api.probeIssuance({ body: { userId: user.id, fail: true } }),
      ).rejects.toThrow("injected-after-mint");
      for (const model of [
        "feasibilityAssociation",
        "oauthAccessToken",
        "oauthRefreshToken",
      ]) {
        expect(await context.adapter.findMany({ model })).toEqual([]);
      }
      const response: OAuthTokenResponse = await auth.api.probeIssuance({
        body: { userId: user.id, fail: false },
      });
      expect(response.token_type).toBe("DPoP");
      expect(response.access_token).toBeTruthy();
      expect(response.refresh_token).toBeTruthy();
      const associations = await context.adapter.findMany({
        model: "feasibilityAssociation",
      });
      expect(associations).toHaveLength(1);
      for (const model of ["oauthAccessToken", "oauthRefreshToken"]) {
        const rows = await context.adapter.findMany({ model });
        expect(rows).toHaveLength(1);
        expect(rows[0]).toMatchObject({
          referenceId: REFERENCE_ID,
          userId: user.id,
          confirmation: CONFIRMATION,
        });
      }
      // Prove the public before-hook can handle a native code at the existing
      // token endpoint without a redirect URI or provider-private code rows.
      // Code/user authorization is still fixture-only, not a production store.
      const endpointUrl = `${context.baseURL}/oauth2/token`;
      const key = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
      const encode = (value: unknown) =>
        Buffer.from(JSON.stringify(value)).toString("base64url");
      const unsigned = [
        encode({
          alg: "ES256",
          typ: "dpop+jwt",
          jwk: key.publicKey.export({ format: "jwk" }),
        }),
        encode({
          htm: "POST",
          htu: endpointUrl,
          iat: Math.floor(Date.now() / 1000),
          jti: "native-token-proof",
        }),
      ].join(".");
      const proof = `${unsigned}.${sign("sha256", Buffer.from(unsigned), { key: key.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url")}`;
      const exchange = (codeVerifier: string) =>
        auth.handler(
          new Request(endpointUrl, {
            method: "POST",
            headers: {
              "content-type": "application/x-www-form-urlencoded",
              dpop: proof,
            },
            body: new URLSearchParams({
              grant_type: "authorization_code",
              code: "fipa_test_code",
              client_id: CLIENT_ID,
              code_verifier: codeVerifier,
            }),
          }),
        );
      expect((await exchange("wrong-verifier")).status).toBe(400);
      const exchanged = await exchange(verifier);
      expect(exchanged.status).toBe(200);
      expect(exchanged.headers.get("cache-control")).toBe("no-store");
      const tokens: unknown = await exchanged.json();
      expect(
        z
          .object({
            token_type: z.literal("DPoP"),
            access_token: z.string().min(1),
            refresh_token: z.string().min(1),
          })
          .safeParse(tokens).success,
      ).toBe(true);
      const httpTokens = await context.adapter.findMany({
        model: "oauthRefreshToken",
        where: [{ field: "referenceId", value: "native-http-fixture" }],
      });
      expect(httpTokens).toHaveLength(1);
    });
  });
}

async function issueFixture(
  ctx: GenericEndpointContext,
  input: {
    userId: string;
    fail: boolean;
    referenceId?: string;
    confirmation?: { jkt: string };
  },
) {
  return withFirstPartyTransaction(ctx, async (transactionContext) => {
    const adapter = transactionContext.context.adapter;
    const provider = getOAuthProviderApi(
      transactionContext,
      options,
      "authorization_code",
    );
    const client = await provider.getClient(CLIENT_ID);
    const user = await adapter.findOne<{
      id: string;
      name: string;
      email: string;
      emailVerified: boolean;
      createdAt: Date;
      updatedAt: Date;
    }>({
      model: "user",
      where: [{ field: "id", value: input.userId }],
    });
    if (!client || !user) throw new Error("Missing fixture");
    await adapter.create({
      model: "feasibilityAssociation",
      data: { referenceId: input.referenceId ?? REFERENCE_ID, userId: user.id },
    });
    const tokens = await provider.issueTokens({
      client,
      user,
      scopes: ["offline_access"],
      referenceId: input.referenceId ?? REFERENCE_ID,
      confirmation: input.confirmation ?? CONFIRMATION,
    });
    if (input.fail) throw new Error("injected-after-mint");
    return tokens;
  });
}
