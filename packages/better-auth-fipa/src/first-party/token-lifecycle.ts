import { developmentPolicyAllowed } from "../development.js";
import { requireUserSecurity } from "./user-security.js";
import type { GenericEndpointContext } from "@better-auth/core";
import {
  getCurrentAdapter,
  getCurrentAuthEndpointContext,
} from "@better-auth/core/context";
import {
  createDpopReplayStore,
  isDpopProofError,
  getConfirmationJkt,
} from "@better-auth/core/oauth2";
import {
  type OAuthOptions,
  type OAuthRefreshToken,
  type OAuthTokenResponse,
} from "@better-auth/oauth-provider";
import { APIError, createAuthMiddleware, isAPIError } from "better-auth/api";
import { randomBytes } from "node:crypto";
import { z } from "zod";
import { requireUsableCredential } from "../credential-store.js";
import {
  readNativeProviderCredential,
  nativeProviderCredentialModel,
} from "./provider-credential.js";
import { hmacSha256 } from "../protocol/crypto.js";
import type { NativeApplicationPolicy } from "./admission.js";
import {
  redeemAuthorizationCode,
  redeemLegacyAuthorizationCode,
  retireLogicalCredentialInTransaction,
  type FirstPartyTokenFamily,
  type LogicalCredential,
} from "./authorization-store.js";
import {
  rotateSession,
  validateContinuationPolicy,
  type ContinuationPolicy,
  type NativeSession,
} from "./continuation.js";
import { verifyFirstPartyDpop } from "./dpop.js";
import { withFirstPartyTransaction } from "./transaction.js";
import { FIRST_PARTY_PROFILE } from "./wire.js";
import { getFirstPartyOAuthApi } from "./oauth-api.js";
import type { LegacyClientPolicy } from "./legacy-v1/contract.js";
import { registeredLegacyClient } from "./legacy-v1/session.js";

import type { EmailDeliveryConfiguration } from "./email-otp-delivery.js";
import type { LegacyCompatibilityOptions } from "./legacy-v1/adapter.js";

export interface NativeTokenOptions {
  legacyCompatibility?: LegacyCompatibilityOptions;
  emailOTP?: EmailDeliveryConfiguration;
  browser?: { loginPage: string };
  oauth: OAuthOptions<string[]>;
  applications: readonly NativeApplicationPolicy[];
  lifetimes: ContinuationPolicy;
  accessTokenSeconds: number;
  maximumAssuranceAgeSeconds: number;
}

export interface FirstPartyTokenContext {
  familyId: string;
  credentialId: string;
  clientId: string;
  userId: string;
  profile: typeof FIRST_PARTY_PROFILE | "legacy-v1";
  /** Original authentication time in epoch seconds; refresh does not reset it. */
  authTime: number;
  scopes: readonly string[];
  resources: readonly string[];
  assurance: Readonly<Record<string, unknown>>;
}

/** Read-only host claims bridge for Better Auth's customAccessTokenClaims.
 * Reads the active transaction, including a family just created during code
 * redemption. Only an absent family returns null. Invalid known families throw
 * and cannot fall back to another interpretation of referenceId.
 * This does not verify a caller's token or DPoP proof; use the resource guards.
 */
export async function resolveFirstPartyTokenContext(
  options: NativeTokenOptions,
  info: Pick<
    Parameters<
      NonNullable<OAuthOptions<string[]>["customAccessTokenClaims"]>
    >[0],
    "referenceId" | "user" | "scopes" | "resources"
  >,
): Promise<FirstPartyTokenContext | null> {
  if (info.referenceId === undefined) return null;
  if (
    typeof info.referenceId !== "string" ||
    !info.referenceId ||
    info.referenceId.length > 256
  )
    throw invalidGrant();
  const ambient = getCurrentAuthEndpointContext();
  const adapter = await getCurrentAdapter(ambient.context.adapter);
  const ctx = {
    context: {
      ...ambient.context,
      adapter: { ...ambient.context.adapter, ...adapter },
    },
  };
  const known = await adapter.findOne<FirstPartyTokenFamily>({
    model: "firstPartyTokenFamily",
    where: [{ field: "id", value: info.referenceId }],
  });
  if (!known) return null;
  const profile = known.assurance.profile;
  if (
    (profile !== FIRST_PARTY_PROFILE && profile !== "legacy-v1") ||
    info.user?.id !== known.userId ||
    info.scopes.some((scope) => !known.scopes.includes(scope)) ||
    (info.resources ?? []).some(
      (resource) => !known.resources.includes(resource),
    )
  )
    throw invalidGrant();
  const family = await activeFamily(
    ctx,
    options,
    known.id,
    options.legacyCompatibility?.clients ?? [],
  );
  await checkCredential(ctx, family);
  return {
    familyId: family.id,
    credentialId: family.credentialId,
    clientId: family.clientId,
    userId: family.userId,
    profile,
    authTime: Math.floor(family.authenticatedAt.getTime() / 1000),
    scopes: [...info.scopes],
    resources: [...(info.resources ?? [])],
    assurance: structuredClone(family.assurance),
  };
}
interface AccessIndex {
  id: string;
  tokenHash: string;
  familyId: string;
  scopes: string[];
  resources: string[];
  expiresAt: Date;
}
interface RefreshIndex {
  id: string;
  tokenHash: string;
  providerTokenId: string;
  familyId: string;
  status: "active" | "used";
  expiresAt: Date;
}
type RefreshRow = OAuthRefreshToken<string[]> & { id: string };
const codeRequest = z.strictObject({
  grant_type: z.literal("authorization_code"),
  client_id: z.string().min(1),
  code: z.string().max(128),
  code_verifier: z.string().max(128),
  redirect_uri: z.string().min(1).max(2048).optional(),
});
const refreshRequest = z.strictObject({
  grant_type: z.literal("refresh_token"),
  client_id: z.string().min(1),
  refresh_token: z.string().min(1).max(16384),
  scope: z.string().max(2048).optional(),
  resource: z.union([z.string(), z.array(z.string())]).optional(),
});
const legacyCodeRequest = codeRequest.extend({
  redirect_uri: z.string().min(1).max(2048),
  resource: z
    .union([
      z.string().min(1).max(2048),
      z.array(z.string().min(1).max(2048)).max(8),
    ])
    .optional(),
});

/** Legacy policies are supplied only by an explicitly enabled composition. */
export function createNativeTokenHook(
  options: NativeTokenOptions,
  legacyPolicies: readonly LegacyClientPolicy[] = [],
) {
  validateContinuationPolicy(options.lifetimes);
  for (const seconds of [
    options.accessTokenSeconds,
    options.maximumAssuranceAgeSeconds,
  ])
    if (!Number.isSafeInteger(seconds) || seconds < 1 || seconds > 86400 * 365)
      throw new TypeError(
        "Native token and assurance lifetimes must be explicit positive seconds.",
      );
  const clients = new Set(
    options.applications.map((application) => application.clientId),
  );
  return {
    matcher: (ctx: { path?: string }) => ctx.path === "/oauth2/token",
    handler: createAuthMiddleware(async (ctx) => {
      const body = ctx.body as Record<string, unknown> | undefined;
      let native =
        (typeof body?.client_id === "string" && clients.has(body.client_id)) ||
        (typeof body?.code === "string" && /^(?:fp1|fpl1)_/.test(body.code));
      // Stored provenance wins over client-authentication hints. An indexed
      // native refresh token can never fall through to the provider's ordinary
      // refresh grant via Basic/assertion auth or an omitted/substituted id.
      if (
        !native &&
        typeof body?.refresh_token === "string" &&
        body.refresh_token.length > 0 &&
        body.refresh_token.length <= 16384
      ) {
        native = !!(await ctx.context.adapter.findOne<RefreshIndex>({
          model: "firstPartyRefresh",
          where: [
            {
              field: "tokenHash",
              value: tokenHash(ctx, "refresh", body.refresh_token),
            },
          ],
        }));
      }
      if (!native) return;
      ctx.setHeader("Cache-Control", "no-store");
      ctx.setHeader("Pragma", "no-cache");
      try {
        if (typeof body?.code === "string" && body.code.startsWith("fpl1_")) {
          const request = legacyCodeRequest.safeParse(body);
          if (
            !request.success ||
            !legacyPolicies.some(
              (policy) => policy.clientId === request.data.client_id,
            )
          )
            throw invalidGrant();
          return await redeemLegacyAuthorizationCode(
            ctx,
            {
              code: request.data.code,
              clientId: request.data.client_id,
              codeVerifier: request.data.code_verifier,
              redirectUri: request.data.redirect_uri,
              resources:
                typeof request.data.resource === "string"
                  ? [request.data.resource]
                  : (request.data.resource ?? []),
              headers: ctx.headers ?? new Headers(),
              tokenEndpointUrl: `${ctx.context.baseURL}/oauth2/token`,
            },
            async (tx, authorization, family) => {
              const policy = legacyPolicies.find(
                (value) => value.clientId === family.clientId,
              );
              if (
                !policy ||
                !policy.redirectUris.includes(authorization.redirectUri ?? "")
              )
                throw invalidGrant();
              await registeredLegacyClient(
                tx,
                { policy, oauth: options.oauth },
                {
                  clientId: authorization.clientId,
                  redirectUri: authorization.redirectUri!,
                  scope: authorization.scopes.join(" "),
                  resources: authorization.resources,
                  codeChallenge: authorization.codeChallenge,
                  codeChallengeMethod: "S256",
                  dpopJkt: authorization.dpopJkt,
                },
              );
              return issue(
                tx,
                options,
                family,
                "authorization_code",
                authorization.scopes,
                authorization.resources,
                undefined,
                undefined,
                legacyPolicies,
              );
            },
          );
        }
        const code = codeRequest.safeParse(ctx.body);
        if (code.success)
          return await redeemAuthorizationCode(
            ctx,
            {
              code: code.data.code,
              clientId: code.data.client_id,
              codeVerifier: code.data.code_verifier,
              ...(code.data.redirect_uri
                ? { redirectUri: code.data.redirect_uri }
                : {}),
              headers: ctx.headers ?? new Headers(),
              tokenEndpointUrl: `${ctx.context.baseURL}/oauth2/token`,
            },
            async (tx, authorization, family) =>
              issue(
                tx,
                options,
                family,
                "authorization_code",
                authorization.scopes,
                authorization.resources,
                undefined,
                authorization.nonce ?? undefined,
              ),
          );
        const refresh = refreshRequest.safeParse(ctx.body);
        if (!refresh.success) throw invalidGrant();
        const result = await refreshNativeTokens(
          ctx,
          options,
          refresh.data,
          legacyPolicies,
        );
        // Reuse revocation must commit, so throw only after the transaction returns.
        if (!result) throw invalidGrant();
        return result;
      } catch (error) {
        if (isDpopProofError(error))
          throw new APIError("BAD_REQUEST", { error: error.code });
        if (isAPIError(error)) throw error;
        throw new APIError("INTERNAL_SERVER_ERROR", { error: "server_error" });
      }
    }),
  };
}

async function refreshNativeTokens(
  ctx: GenericEndpointContext,
  options: NativeTokenOptions,
  request: z.infer<typeof refreshRequest>,
  legacyPolicies: readonly LegacyClientPolicy[],
): Promise<OAuthTokenResponse | null> {
  const index = await ctx.context.adapter.findOne<RefreshIndex>({
    model: "firstPartyRefresh",
    where: [
      {
        field: "tokenHash",
        value: tokenHash(ctx, "refresh", request.refresh_token),
      },
    ],
  });
  if (!index || index.expiresAt <= new Date()) throw invalidGrant();
  const original = await findFamily(ctx, index.familyId);
  if (original.clientId !== request.client_id) throw invalidGrant();
  await verifyFirstPartyDpop({
    headers: ctx.headers ?? new Headers(),
    method: "POST",
    endpointUrl: `${ctx.context.baseURL}/oauth2/token`,
    expectedJkt: original.dpopJkt,
    replayStore: createDpopReplayStore(ctx.context.internalAdapter),
  });
  return withFirstPartyTransaction(ctx, async (tx) => {
    await lockFamilyCredential(tx, original);
    const family = await activeFamily(tx, options, original.id, legacyPolicies);
    const current = await tx.context.adapter.findOne<RefreshIndex>({
      model: "firstPartyRefresh",
      where: [{ field: "id", value: index.id }],
    });
    if (!current || current.expiresAt <= new Date()) throw invalidGrant();
    if (current.status === "used") {
      await revokeNativeFamily(tx, family.id);
      return null;
    }
    const providerToken = await tx.context.adapter.findOne<RefreshRow>({
      model: "oauthRefreshToken",
      where: [{ field: "id", value: current.providerTokenId }],
    });
    if (
      !providerToken ||
      providerToken.revoked ||
      providerToken.expiresAt <= new Date() ||
      providerToken.referenceId !== family.id ||
      providerToken.clientId !== family.clientId ||
      providerToken.userId !== family.userId ||
      getConfirmationJkt(providerToken.confirmation) !== family.dpopJkt
    )
      throw invalidGrant();
    const scopes =
      request.scope === undefined
        ? providerToken.scopes
        : request.scope.split(" ");
    const resources =
      request.resource === undefined
        ? (providerToken.resources ?? [])
        : typeof request.resource === "string"
          ? [request.resource]
          : request.resource;
    if (
      !scopes.length ||
      scopes.some((scope) => !providerToken.scopes.includes(scope)) ||
      resources.some(
        (resource) => !(providerToken.resources ?? []).includes(resource),
      )
    )
      throw invalidGrant();
    const consumed = await tx.context.adapter.incrementOne<RefreshIndex>({
      model: "firstPartyRefresh",
      where: [
        { field: "id", value: current.id },
        { field: "status", value: "active" },
      ],
      increment: {},
      set: { status: "used" },
    });
    if (!consumed) throw invalidGrant();
    return issue(
      tx,
      options,
      family,
      "refresh_token",
      scopes,
      resources,
      providerToken,
      undefined,
      legacyPolicies,
    );
  });
}

async function issue(
  ctx: GenericEndpointContext,
  options: NativeTokenOptions,
  family: FirstPartyTokenFamily,
  grantType: "authorization_code" | "refresh_token",
  scopes: string[],
  resources: string[],
  refreshToken?: RefreshRow,
  nonce?: string,
  legacyPolicies: readonly LegacyClientPolicy[] = [],
): Promise<OAuthTokenResponse> {
  if (options.oauth.grantTypes && !options.oauth.grantTypes.includes(grantType))
    throw invalidGrant();
  checkPolicy(options, family, scopes, resources, legacyPolicies);
  // The public minting API calls ctx.json. Keep that return as data inside the
  // transaction; the outer middleware serializes only after commit.
  const provider = getFirstPartyOAuthApi(
    { ...ctx, json: (value) => Promise.resolve(value) },
    options.oauth,
    grantType,
  );
  const authenticated = await provider.authenticateClient({
    scopes,
    requireCredentials: false,
  });
  if (
    authenticated.clientId !== family.clientId ||
    authenticated.client.tokenEndpointAuthMethod !== "none"
  )
    throw invalidGrant();
  const user = await ctx.context.internalAdapter.findUserById(family.userId);
  if (!user) throw invalidGrant();
  const sessionHandle = await rotateFamilySession(
    ctx,
    family,
    options.lifetimes,
  );
  const now = Date.now();
  const assuranceDeadline = assuranceExpiresAt(options, family);
  const remaining = Math.floor(
    (Math.min(family.expiresAt.getTime(), assuranceDeadline) - now) / 1000,
  );
  if (remaining < 1) throw invalidGrant();
  const accessSeconds = Math.min(
    options.accessTokenSeconds,
    options.oauth.accessTokenExpiresIn ?? 3600,
    remaining,
  );
  const opts: OAuthOptions<string[]> = {
    ...options.oauth,
    accessTokenExpiresIn: accessSeconds,
    refreshTokenExpiresIn: Math.min(
      options.oauth.refreshTokenExpiresIn ?? 2592000,
      remaining,
    ),
    refreshTokenReuseInterval: 0,
  };
  const issuer = getFirstPartyOAuthApi(
    { ...ctx, json: (value) => Promise.resolve(value) },
    opts,
    grantType,
  );
  const response = await issuer.issueTokens({
    client: authenticated.client,
    user,
    scopes,
    resources,
    originalResources: resources,
    referenceId: family.id,
    authTime: family.authenticatedAt,
    confirmation: { jkt: family.dpopJkt },
    ...(refreshToken === undefined ? {} : { refreshToken }),
    ...(nonce === undefined ? {} : { nonce }),
    accessTokenClaims: { first_party_family: family.id },
    tokenResponse: {
      ...(sessionHandle === undefined ? {} : { auth_session: sessionHandle }),
      first_party_account: {
        sub: family.userId,
        credential_id: family.credentialId,
      },
    },
  });
  if (
    response.token_type !== "DPoP" ||
    response.expires_at * 1000 >
      Math.min(
        family.expiresAt.getTime(),
        assuranceDeadline,
        // Provider minting occurs after client lookup and host hooks. Measure
        // its relative lifetime at completion, not at the earlier request time.
        Date.now() + accessSeconds * 1000,
      )
  )
    throw new APIError("INTERNAL_SERVER_ERROR", {
      error: "server_error",
      error_description: "OAuth issuance exceeded the native lifetime policy.",
    });
  const issuedScopes = response.scope.split(" ");
  if (issuedScopes.some((scope) => !scopes.includes(scope)))
    throw invalidGrant();
  await ctx.context.adapter.create({
    model: "firstPartyAccess",
    data: {
      tokenHash: tokenHash(ctx, "access", response.access_token),
      familyId: family.id,
      scopes: issuedScopes,
      resources,
      expiresAt: new Date(response.expires_at * 1000),
    },
  });
  if (response.refresh_token) {
    const rows = await ctx.context.adapter.findMany<RefreshRow>({
      model: "oauthRefreshToken",
      where: [
        { field: "referenceId", value: family.id },
        { field: "revoked", value: null },
      ],
      limit: 2,
    });
    const row = rows[0];
    if (
      rows.length !== 1 ||
      !row ||
      getConfirmationJkt(row.confirmation) !== family.dpopJkt ||
      row.expiresAt.getTime() >
        Math.min(family.expiresAt.getTime(), assuranceDeadline)
    )
      throw invalidGrant();
    await ctx.context.adapter.create({
      model: "firstPartyRefresh",
      data: {
        tokenHash: tokenHash(ctx, "refresh", response.refresh_token),
        providerTokenId: row.id,
        familyId: family.id,
        status: "active",
        expiresAt: row.expiresAt,
      },
    });
  }
  return response;
}

/** Online resource verification applies equally to opaque and JWT access tokens. */
export async function requireNativeAccess(
  ctx: GenericEndpointContext,
  options: NativeTokenOptions,
  input: AccessRequest,
) {
  return requireProfileAccess(ctx, options, input, FIRST_PARTY_PROFILE, []);
}

/** Explicit legacy resource boundary. Enabling legacy challenges does not relax
 * requireNativeAccess; both guards require token-bound proofs and current state.
 */
export async function requireLegacyAccess(
  ctx: GenericEndpointContext,
  options: NativeTokenOptions,
  input: AccessRequest,
) {
  return requireProfileAccess(
    ctx,
    options,
    input,
    "legacy-v1",
    options.legacyCompatibility?.clients ?? [],
  );
}

interface AccessRequest {
  headers: Headers;
  method: string;
  url: string;
  resource?: string;
  scopes: readonly string[];
}

async function requireProfileAccess(
  ctx: GenericEndpointContext,
  options: NativeTokenOptions,
  input: AccessRequest,
  profile: typeof FIRST_PARTY_PROFILE | "legacy-v1",
  legacyPolicies: readonly LegacyClientPolicy[],
) {
  try {
    const authorization = input.headers.get("authorization");
    if (!authorization || !/^DPoP [^\s]+$/i.test(authorization))
      throw invalidGrant();
    const token = authorization.slice(5);
    const index = await ctx.context.adapter.findOne<AccessIndex>({
      model: "firstPartyAccess",
      where: [{ field: "tokenHash", value: tokenHash(ctx, "access", token) }],
    });
    if (!index || index.expiresAt <= new Date()) throw invalidGrant();
    const family = await activeFamily(
      ctx,
      options,
      index.familyId,
      legacyPolicies,
    );
    if (family.assurance.profile !== profile) throw invalidGrant();
    await checkCredential(ctx, family);
    if (
      input.scopes.some((scope) => !index.scopes.includes(scope)) ||
      (input.resource && !index.resources.includes(input.resource))
    )
      throw invalidGrant();
    const payload = await getFirstPartyOAuthApi(
      ctx,
      options.oauth,
    ).requireActiveAccessToken(token, family.clientId);
    const confirmation = z.object({ jkt: z.string() }).safeParse(payload.cnf);
    const audiences =
      typeof payload.aud === "string" ? [payload.aud] : payload.aud;
    if (
      payload.sub !== family.userId ||
      payload.client_id !== family.clientId ||
      !confirmation.success ||
      confirmation.data.jkt !== family.dpopJkt ||
      (input.resource &&
        (!Array.isArray(audiences) || !audiences.includes(input.resource)))
    )
      throw invalidGrant();
    await verifyFirstPartyDpop({
      headers: input.headers,
      method: input.method,
      endpointUrl: input.url,
      expectedJkt: family.dpopJkt,
      accessToken: token,
      replayStore: createDpopReplayStore(ctx.context.internalAdapter),
    });
    return {
      userId: family.userId,
      familyId: family.id,
      credentialId: family.credentialId,
      scopes: index.scopes,
      assurance: family.assurance,
    };
  } catch {
    throw new APIError(
      "UNAUTHORIZED",
      { error: "invalid_token" },
      { "www-authenticate": 'DPoP error="invalid_token"' },
    );
  }
}

/** Call within the same credential-locked transaction as refresh or logout. */
export async function revokeNativeFamily(
  ctx: GenericEndpointContext,
  familyId: string,
): Promise<void> {
  await ctx.context.adapter.update({
    model: "firstPartyTokenFamily",
    where: [{ field: "id", value: familyId }],
    update: { status: "revoked", revokedAt: new Date() },
  });
  for (const model of ["oauthAccessToken", "oauthRefreshToken"])
    await ctx.context.adapter.deleteMany({
      model,
      where: [{ field: "referenceId", value: familyId }],
    });
}

/**
 * Authenticate before opening the transaction so a rollback cannot restore a
 * used proof. Recheck family authority after taking the same credential lock
 * used by issuance and refresh. Targets come only from the verified token.
 */
export async function terminateNativeSession(
  ctx: GenericEndpointContext,
  options: NativeTokenOptions,
  input: {
    headers: Headers;
    url: string;
    action: "logout" | "retire";
    familyOnly?: boolean;
  },
): Promise<void> {
  const principal = await requireNativeAccess(ctx, options, {
    headers: input.headers,
    method: "POST",
    url: input.url,
    scopes: [],
  });
  await withFirstPartyTransaction(ctx, async (tx) => {
    const family = await findFamily(tx, principal.familyId);
    await lockFamilyCredential(tx, family);
    await activeFamily(tx, options, family.id);
    if (input.action === "retire") {
      await retireLogicalCredentialInTransaction(tx, family.credentialId);
      return;
    }
    // A retained continuation can have issued multiple families. Signing out
    // ends that whole session, including outstanding codes and factor work,
    // while leaving other sessions and the account's keys usable.
    if (!family.nativeSessionId || input.familyOnly === true) {
      await revokeNativeFamily(tx, family.id);
      return;
    }
    const adapter = tx.context.adapter;
    const session = await adapter.findOne<NativeSession>({
      model: "firstPartySession",
      where: [{ field: "id", value: family.nativeSessionId }],
    });
    if (
      !session ||
      session.credentialId !== family.credentialId ||
      session.clientId !== family.clientId ||
      session.userId !== family.userId ||
      session.dpopJkt !== family.dpopJkt
    )
      throw invalidGrant();
    await adapter.update({
      model: "firstPartySession",
      where: [{ field: "id", value: session.id }],
      update: { status: "revoked", activeAttemptId: null },
    });
    await adapter.updateMany({
      model: "firstPartyAttempt",
      where: [
        { field: "sessionId", value: session.id },
        {
          field: "status",
          operator: "in",
          value: [
            "password",
            "authentication",
            "email-otp",
            "email-otp-sending",
            "processing",
            "evidence",
            "browser",
          ],
        },
      ],
      update: {
        status: "cancelled",
        operationId: null,
        email: null,
        resumeStatus: null,
      },
    });
    await adapter.updateMany({
      model: "firstPartyAuthorization",
      where: [
        { field: "nativeSessionId", value: session.id },
        {
          field: "status",
          operator: "in",
          value: ["authorized", "code-issued"],
        },
      ],
      update: { status: "cancelled" },
    });
    // The shared credential lock prevents new families appearing between pages.
    for (let offset = 0; ; offset += 100) {
      const families = await adapter.findMany<FirstPartyTokenFamily>({
        model: "firstPartyTokenFamily",
        where: [{ field: "nativeSessionId", value: session.id }],
        sortBy: { field: "id", direction: "asc" },
        limit: 100,
        offset,
      });
      for (const member of families) await revokeNativeFamily(tx, member.id);
      if (families.length < 100) break;
    }
  });
}
async function findFamily(
  ctx: Pick<GenericEndpointContext, "context">,
  id: string,
): Promise<FirstPartyTokenFamily> {
  const family = await ctx.context.adapter.findOne<FirstPartyTokenFamily>({
    model: "firstPartyTokenFamily",
    where: [{ field: "id", value: id }],
  });
  if (!family) throw invalidGrant();
  return family;
}
async function activeFamily(
  ctx: Pick<GenericEndpointContext, "context">,
  options: NativeTokenOptions,
  id: string,
  legacyPolicies: readonly LegacyClientPolicy[] = [],
): Promise<FirstPartyTokenFamily> {
  const family = await findFamily(ctx, id);
  if (
    family.status !== "active" ||
    family.expiresAt <= new Date() ||
    assuranceExpiresAt(options, family) <= Date.now()
  )
    throw invalidGrant();
  checkPolicy(options, family, family.scopes, family.resources, legacyPolicies);
  await requireUserSecurity(ctx, family.userId, family.userSecurityHash);
  return family;
}

/** Internal legacy reauthentication boundary. Call inside a transaction; uses
 * the same credential/provider lock order as refresh, revocation and issuance. */
export async function lockActiveLegacyFamily(
  ctx: GenericEndpointContext,
  options: NativeTokenOptions,
  id: string,
): Promise<{ family: FirstPartyTokenFamily; credential: LogicalCredential }> {
  const original = await findFamily(ctx, id);
  if (original.assurance.profile !== "legacy-v1") throw invalidGrant();
  await lockFamilyCredential(ctx, original);
  const family = await activeFamily(
    ctx,
    options,
    id,
    options.legacyCompatibility?.clients ?? [],
  );
  return { family, credential: await checkCredential(ctx, family) };
}
async function checkCredential(
  ctx: Pick<GenericEndpointContext, "context">,
  family: FirstPartyTokenFamily,
): Promise<LogicalCredential> {
  const credential = await ctx.context.adapter.findOne<LogicalCredential>({
    model: "firstPartyCredential",
    where: [{ field: "id", value: family.credentialId }],
  });
  if (
    !credential ||
    credential.status !== "active" ||
    credential.version !== family.credentialVersion ||
    credential.issuer !== ctx.context.baseURL ||
    credential.clientId !== family.clientId ||
    credential.userId !== family.userId ||
    credential.dpopJkt !== family.dpopJkt
  )
    throw invalidGrant();
  const provider = await readNativeProviderCredential(ctx, {
    provider: credential.provider,
    id: credential.providerCredentialId,
    clientId: credential.clientId,
    dpopJkt: credential.dpopJkt,
  });
  try {
    requireUsableCredential(provider);
  } catch {
    throw invalidGrant();
  }
  if (
    provider.userId !== family.userId ||
    provider.provider !== credential.provider ||
    provider.applicationId !== credential.applicationId ||
    provider.environment !== credential.environment
  )
    throw invalidGrant();
  return credential;
}
async function lockFamilyCredential(
  ctx: GenericEndpointContext,
  family: FirstPartyTokenFamily,
): Promise<void> {
  const locked = await ctx.context.adapter.incrementOne<LogicalCredential>({
    model: "firstPartyCredential",
    where: [
      { field: "id", value: family.credentialId },
      { field: "status", value: "active" },
      { field: "version", value: family.credentialVersion },
    ],
    increment: { revision: 1 },
  });
  if (!locked) throw invalidGrant();
  const credential = await checkCredential(ctx, family);
  const provider = await ctx.context.adapter.incrementOne({
    model: nativeProviderCredentialModel(credential.provider),
    where: [
      { field: "id", value: credential.providerCredentialId },
      { field: "status", value: "active" },
      { field: "userId", value: family.userId },
    ],
    increment: {},
    set: { userId: family.userId },
  });
  if (!provider) throw invalidGrant();
}
function checkPolicy(
  options: NativeTokenOptions,
  family: FirstPartyTokenFamily,
  scopes: string[],
  resources: string[],
  legacyPolicies: readonly LegacyClientPolicy[] = [],
): void {
  const application = options.applications.find(
    (candidate) => candidate.clientId === family.clientId,
  );
  const legacy = legacyPolicies.find(
    (policy) => policy.clientId === family.clientId,
  );
  if (
    family.assurance.profile !== FIRST_PARTY_PROFILE &&
    (family.assurance.profile !== "legacy-v1" ||
      !legacy ||
      family.assurance.provider !== legacy.provider ||
      family.assurance.applicationId !== legacy.applicationId ||
      family.assurance.environment !== legacy.environment ||
      (family.assurance.acr !== undefined &&
        (typeof family.assurance.acr !== "string" ||
          !legacy.passwordAcrValues?.includes(family.assurance.acr) ||
          !Array.isArray(family.assurance.amr) ||
          family.assurance.amr.length !== 1 ||
          family.assurance.amr[0] !== "pwd")) ||
      scopes.some((scope) => !legacy.scopes.includes(scope)) ||
      resources.some((resource) => !legacy.resources.includes(resource)))
  )
    throw invalidGrant();
  if (
    !application ||
    !developmentPolicyAllowed(
      application.provider.id,
      application.environment,
    ) ||
    family.assurance.provider !== application.provider.id ||
    family.assurance.applicationId !== application.applicationId ||
    family.assurance.environment !== application.environment ||
    scopes.some(
      (scope) =>
        !application.scopes.includes(scope) || !family.scopes.includes(scope),
    ) ||
    resources.some(
      (resource) =>
        !application.resources.includes(resource) ||
        !family.resources.includes(resource),
    )
  )
    throw invalidGrant();
}
function assuranceExpiresAt(
  options: NativeTokenOptions,
  family: FirstPartyTokenFamily,
): number {
  const verified = z.iso
    .datetime()
    .safeParse(family.assurance.evidenceVerifiedAt);
  if (!verified.success) throw invalidGrant();
  return (
    new Date(verified.data).getTime() +
    options.maximumAssuranceAgeSeconds * 1000
  );
}
async function rotateFamilySession(
  ctx: GenericEndpointContext,
  family: FirstPartyTokenFamily,
  policy: ContinuationPolicy,
): Promise<string | undefined> {
  if (!family.nativeSessionId) return;
  const session = await ctx.context.adapter.findOne<NativeSession>({
    model: "firstPartySession",
    where: [{ field: "id", value: family.nativeSessionId }],
  });
  if (
    !session ||
    session.status !== "active" ||
    session.expiresAt <= new Date() ||
    session.absoluteExpiresAt <= new Date()
  )
    return;
  if (
    session.credentialId !== family.credentialId ||
    session.credentialVersion !== family.credentialVersion ||
    session.clientId !== family.clientId ||
    session.dpopJkt !== family.dpopJkt ||
    session.userId !== family.userId
  )
    throw invalidGrant();
  if (session.activeAttemptId) return;
  const handle = `fpas1_${randomBytes(32).toString("base64url")}`;
  await rotateSession(ctx, session, handle, policy);
  return handle;
}
function tokenHash(
  ctx: GenericEndpointContext,
  kind: "access" | "refresh",
  token: string,
): string {
  if (!token || token.length > 16384) throw invalidGrant();
  return hmacSha256(ctx.context.secret, `first-party-${kind}:v1:${token}`);
}
function invalidGrant(): APIError {
  return new APIError("BAD_REQUEST", { error: "invalid_grant" });
}
