import type { GenericEndpointContext } from "@better-auth/core";
import { createDpopReplayStore } from "@better-auth/core/oauth2";
import { APIError } from "better-auth/api";
import { randomBytes, createHash } from "node:crypto";
import { equalBytes, hmacSha256 } from "../protocol/crypto.js";
import { requireUsableCredential } from "../credential-store.js";
import {
  readNativeProviderCredential,
  nativeProviderCredentialModel,
  type LifecycleProviderCredential,
} from "./provider-credential.js";
import { verifyFirstPartyDpop } from "./dpop.js";
import { withFirstPartyTransaction } from "./transaction.js";
import { userSecurityHash, requireUserSecurity } from "./user-security.js";
import { FIRST_PARTY_PROFILE } from "./wire.js";

type CodeProfile = typeof FIRST_PARTY_PROFILE | "legacy-v1";

export interface LogicalCredential {
  id: string;
  issuer: string;
  clientId: string;
  applicationId: string;
  environment: "development" | "production";
  provider: string;
  providerCredentialId: string;
  dpopJkt: string;
  userId: string | null;
  status: "active" | "revoked";
  version: number;
  revision: number;
  createdAt: Date;
}
export interface AuthorizedAttempt {
  id: string;
  nativeSessionId?: string | null;
  nonce?: string | null;
  redirectUri?: string | null;
  attemptId: string;
  credentialId: string;
  credentialVersion: number;
  providerCredentialBindingVersion: number;
  clientId: string;
  userId: string;
  userSecurityHash: string;
  dpopJkt: string;
  codeChallenge: string;
  codeHash: string | null;
  codeExpiresAt: Date | null;
  status: "authorized" | "code-issued" | "consumed" | "cancelled";
  scopes: string[];
  resources: string[];
  assurance: Record<string, unknown>;
  assuranceExpiresAt: Date;
  authenticatedAt: Date;
  familyExpiresAt: Date;
  createdAt: Date;
  expiresAt: Date;
}
export interface FirstPartyTokenFamily {
  id: string;
  nativeSessionId?: string | null;
  scopes: string[];
  resources: string[];
  authorizationId: string;
  credentialId: string;
  credentialVersion: number;
  clientId: string;
  userId: string;
  userSecurityHash: string;
  dpopJkt: string;
  status: "active" | "revoked";
  assurance: Record<string, unknown>;
  authenticatedAt: Date;
  createdAt: Date;
  expiresAt: Date;
}

/** Called only after server-side platform verification; never with a request body. */
export async function enrollLogicalCredential(
  ctx: GenericEndpointContext,
  input: Pick<
    LogicalCredential,
    | "issuer"
    | "clientId"
    | "applicationId"
    | "environment"
    | "provider"
    | "providerCredentialId"
    | "dpopJkt"
  >,
): Promise<LogicalCredential> {
  const providerCredential = await readNativeProviderCredential(ctx, {
    provider: input.provider,
    id: input.providerCredentialId,
    clientId: input.clientId,
    dpopJkt: input.dpopJkt,
  });
  requireUsableCredential(providerCredential);
  if (
    input.issuer !== ctx.context.baseURL ||
    providerCredential.provider !== input.provider ||
    providerCredential.applicationId !== input.applicationId ||
    providerCredential.environment !== input.environment
  )
    throw invalidGrant();
  return ctx.context.adapter.create<LogicalCredential>({
    model: "firstPartyCredential",
    data: {
      ...input,
      // A retained provider key may already belong to a legacy user. Preserve
      // that ownership, and recheck it atomically at redemption.
      userId: providerCredential.userId ?? null,
      status: "active",
      version: 0,
      revision: 0,
      createdAt: new Date(),
    },
  });
}

/**
 * Persists a completed, server-authenticated authorization. Admission and factor
 * adapters own the supplied assurance and user; no client subject is accepted at
 * this internal boundary. The continuation coordinator calls this after factors.
 */
export async function recordAuthorizedAttempt(
  ctx: GenericEndpointContext,
  input: Omit<
    AuthorizedAttempt,
    | "id"
    | "codeHash"
    | "codeExpiresAt"
    | "status"
    | "createdAt"
    | "userSecurityHash"
  > & { userSecurityHash?: string },
): Promise<AuthorizedAttempt> {
  const now = new Date();
  if (
    !/^[A-Za-z0-9_-]{43}$/.test(input.codeChallenge) ||
    !input.userId ||
    input.expiresAt <= now ||
    input.assuranceExpiresAt <= now ||
    input.familyExpiresAt <= now
  )
    throw invalidGrant();
  const security =
    input.userSecurityHash ?? (await userSecurityHash(ctx, input.userId));
  await requireUserSecurity(ctx, input.userId, security);
  return ctx.context.adapter.create<AuthorizedAttempt>({
    model: "firstPartyAuthorization",
    data: {
      ...input,
      userSecurityHash: security,
      codeHash: null,
      codeExpiresAt: null,
      status: "authorized",
      createdAt: now,
    },
  });
}

/** A lost issuance response is not recovered by minting another code. */
export async function issueAuthorizationCode(
  ctx: GenericEndpointContext,
  authorizationId: string,
): Promise<string> {
  return issueCode(ctx, authorizationId, FIRST_PARTY_PROFILE);
}

export async function issueLegacyAuthorizationCode(
  ctx: GenericEndpointContext,
  authorizationId: string,
): Promise<string> {
  return issueCode(ctx, authorizationId, "legacy-v1");
}

async function issueCode(
  ctx: GenericEndpointContext,
  authorizationId: string,
  profile: CodeProfile,
): Promise<string> {
  const authorization = await ctx.context.adapter.findOne<AuthorizedAttempt>({
    model: "firstPartyAuthorization",
    where: [{ field: "id", value: authorizationId }],
  });
  if (!authorization || authorization.assurance.profile !== profile)
    throw invalidGrant();
  await requireUserSecurity(
    ctx,
    authorization.userId,
    authorization.userSecurityHash,
  );
  const now = new Date();
  const code = `${profile === "legacy-v1" ? "fpl1" : "fp1"}_${randomBytes(32).toString("base64url")}`;
  const result = await ctx.context.adapter.incrementOne<AuthorizedAttempt>({
    model: "firstPartyAuthorization",
    where: [
      { field: "id", value: authorizationId },
      { field: "status", value: "authorized" },
      { field: "expiresAt", operator: "gt", value: now },
      { field: "assuranceExpiresAt", operator: "gt", value: now },
    ],
    increment: {},
    set: {
      status: "code-issued",
      codeHash: hashCode(ctx, code),
      codeExpiresAt: new Date(now.getTime() + 60_000),
    },
  });
  if (!result) throw invalidGrant();
  return code;
}

export interface RedeemCodeInput {
  code: string;
  clientId: string;
  codeVerifier: string;
  redirectUri?: string;
  headers: Headers;
  /** From trusted issuer configuration; never caller-provided forwarded headers. */
  tokenEndpointUrl: string;
}

/**
 * The issuance callback must use the supplied transaction context and persist
 * its token referenceId as family.id. It is an internal Better Auth boundary.
 */
export async function redeemAuthorizationCode<T>(
  ctx: GenericEndpointContext,
  input: RedeemCodeInput,
  issue: (
    transactionContext: GenericEndpointContext,
    authorization: AuthorizedAttempt,
    family: FirstPartyTokenFamily,
  ) => Promise<T>,
): Promise<T> {
  return redeemCode(ctx, input, issue, FIRST_PARTY_PROFILE);
}

/** Legacy codes retain redirect/resource binding and never enter native parsing. */
export async function redeemLegacyAuthorizationCode<T>(
  ctx: GenericEndpointContext,
  input: RedeemCodeInput & { redirectUri: string; resources: string[] },
  issue: (
    transactionContext: GenericEndpointContext,
    authorization: AuthorizedAttempt,
    family: FirstPartyTokenFamily,
  ) => Promise<T>,
): Promise<T> {
  return redeemCode(ctx, input, issue, "legacy-v1", input.resources);
}

async function redeemCode<T>(
  ctx: GenericEndpointContext,
  input: RedeemCodeInput,
  issue: (
    transactionContext: GenericEndpointContext,
    authorization: AuthorizedAttempt,
    family: FirstPartyTokenFamily,
  ) => Promise<T>,
  profile: CodeProfile,
  resources?: string[],
): Promise<T> {
  if (
    !(
      profile === "legacy-v1"
        ? /^fpl1_[A-Za-z0-9_-]{43}$/
        : /^fp1_[A-Za-z0-9_-]{43}$/
    ).test(input.code) ||
    !/^[A-Za-z0-9._~-]{43,128}$/.test(input.codeVerifier)
  )
    throw invalidGrant();
  const codeHash = hashCode(ctx, input.code);
  const authorization = await ctx.context.adapter.findOne<AuthorizedAttempt>({
    model: "firstPartyAuthorization",
    where: [{ field: "codeHash", value: codeHash }],
  });
  if (
    !authorization ||
    authorization.assurance.profile !== profile ||
    authorization.clientId !== input.clientId ||
    (authorization.redirectUri ?? undefined) !== input.redirectUri ||
    authorization.status !== "code-issued"
  )
    throw invalidGrant();
  if (
    resources !== undefined &&
    JSON.stringify([...new Set(resources)].sort()) !==
      JSON.stringify([...new Set(authorization.resources)].sort())
  )
    throw invalidGrant();
  const expectedChallenge = createHash("sha256")
    .update(input.codeVerifier)
    .digest("base64url");
  if (
    !equalBytes(
      Buffer.from(expectedChallenge),
      Buffer.from(authorization.codeChallenge),
    )
  )
    throw invalidGrant();
  // Reserve proofs outside the issuance transaction: an issuance rollback must
  // not make a used proof reusable. A deliberate retry needs a new proof.
  await verifyFirstPartyDpop({
    headers: input.headers,
    endpointUrl: input.tokenEndpointUrl,
    method: "POST",
    expectedJkt: authorization.dpopJkt,
    replayStore: createDpopReplayStore(ctx.context.internalAdapter),
  });
  return withFirstPartyTransaction(ctx, async (transactionContext) => {
    const adapter = transactionContext.context.adapter;
    await requireUserSecurity(
      transactionContext,
      authorization.userId,
      authorization.userSecurityHash,
    );
    const credential = await adapter.findOne<LogicalCredential>({
      model: "firstPartyCredential",
      where: [{ field: "id", value: authorization.credentialId }],
    });
    if (
      !credential ||
      credential.issuer !== ctx.context.baseURL ||
      credential.clientId !== authorization.clientId ||
      credential.status !== "active" ||
      credential.version !== authorization.credentialVersion ||
      credential.dpopJkt !== authorization.dpopJkt ||
      (credential.userId && credential.userId !== authorization.userId)
    )
      throw invalidGrant();
    // Updating the credential serializes redemption, competing user claims, and
    // retirement on the same row even when the credential was already bound.
    const bound = await adapter.incrementOne<LogicalCredential>({
      model: "firstPartyCredential",
      where: [
        { field: "id", value: credential.id },
        { field: "status", value: "active" },
        { field: "version", value: credential.version },
        { field: "revision", value: credential.revision },
        { field: "userId", value: credential.userId },
      ],
      increment: { revision: 1 },
      set: { userId: authorization.userId },
    });
    if (!bound) throw invalidGrant();
    await bindProviderCredential(transactionContext, bound, authorization);
    const now = new Date();
    const claimed = await adapter.incrementOne<AuthorizedAttempt>({
      model: "firstPartyAuthorization",
      where: [
        { field: "id", value: authorization.id },
        { field: "status", value: "code-issued" },
        { field: "codeHash", value: codeHash },
        { field: "expiresAt", operator: "gt", value: now },
        { field: "codeExpiresAt", operator: "gt", value: now },
        { field: "assuranceExpiresAt", operator: "gt", value: now },
        { field: "familyExpiresAt", operator: "gt", value: now },
      ],
      increment: {},
      set: { status: "consumed" },
    });
    if (!claimed) throw invalidGrant();
    const family = await adapter.create<FirstPartyTokenFamily>({
      model: "firstPartyTokenFamily",
      data: {
        authorizationId: claimed.id,
        nativeSessionId: claimed.nativeSessionId ?? null,
        scopes: claimed.scopes,
        resources: claimed.resources,
        credentialId: bound.id,
        credentialVersion: bound.version,
        clientId: claimed.clientId,
        userId: claimed.userId,
        userSecurityHash: claimed.userSecurityHash,
        dpopJkt: claimed.dpopJkt,
        status: "active",
        assurance: claimed.assurance,
        authenticatedAt: claimed.authenticatedAt,
        createdAt: now,
        expiresAt: claimed.familyExpiresAt,
      },
    });
    return issue(transactionContext, claimed, family);
  });
}

/** Retires the logical credential and its provider token rows in one transaction. */
export async function retireLogicalCredential(
  ctx: GenericEndpointContext,
  credentialId: string,
): Promise<void> {
  await withFirstPartyTransaction(ctx, (tx) =>
    retireLogicalCredentialInTransaction(tx, credentialId),
  );
}

/** Internal primitive: the caller must already own a real transaction. */
export async function retireLogicalCredentialInTransaction(
  ctx: Pick<GenericEndpointContext, "context">,
  credentialId: string,
  reason: "user" | "user_deleted" | "provider" = "user",
): Promise<void> {
  const adapter = ctx.context.adapter;
  const now = new Date();
  const retired = await adapter.incrementOne<LogicalCredential>({
    model: "firstPartyCredential",
    where: [
      { field: "id", value: credentialId },
      { field: "status", value: "active" },
    ],
    increment: { version: 1, revision: 1 },
    set: { status: "revoked", revokedAt: now },
  });
  if (!retired) return;
  // New continuations acquire this credential lock before being created.
  // Revoke every existing session/attempt, including work currently outside
  // the transaction running a factor provider.
  for (let offset = 0; ; offset += 100) {
    const sessions = await adapter.findMany<{ id: string }>({
      model: "firstPartySession",
      where: [{ field: "credentialId", value: credentialId }],
      sortBy: { field: "id", direction: "asc" },
      limit: 100,
      offset,
    });
    if (!sessions.length) break;
    await adapter.updateMany({
      model: "firstPartyAttempt",
      where: [
        {
          field: "sessionId",
          operator: "in",
          value: sessions.map((session) => session.id),
        },
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
    if (sessions.length < 100) break;
  }
  await adapter.updateMany({
    model: "firstPartySession",
    where: [{ field: "credentialId", value: credentialId }],
    update: { status: "revoked", activeAttemptId: null },
  });
  // Same lock order as redemption: logical credential, then provider key.
  // A retired key must not remain usable through the legacy protocol.
  await adapter.incrementOne({
    model: nativeProviderCredentialModel(retired.provider),
    where: [
      { field: "id", value: retired.providerCredentialId },
      { field: "status", value: "active" },
    ],
    increment: { bindingVersion: 1 },
    set: {
      status: "revoked",
      revokedAt: now,
      revocationReason: reason,
    },
  });
  // Adapter reads may default to a finite page. The credential row lock keeps
  // the family set stable while every page is revoked in this transaction.
  for (let offset = 0; ; offset += 100) {
    const families = await adapter.findMany<FirstPartyTokenFamily>({
      model: "firstPartyTokenFamily",
      where: [{ field: "credentialId", value: credentialId }],
      sortBy: { field: "id", direction: "asc" },
      limit: 100,
      offset,
    });
    if (!families.length) break;
    const where = [
      {
        field: "referenceId",
        operator: "in" as const,
        value: families.map((family) => family.id),
      },
    ];
    // Access rows reference refresh rows, so delete children first.
    await adapter.deleteMany({ model: "oauthAccessToken", where });
    await adapter.deleteMany({ model: "oauthRefreshToken", where });
    if (families.length < 100) break;
  }
  await adapter.updateMany({
    model: "firstPartyTokenFamily",
    where: [{ field: "credentialId", value: credentialId }],
    update: { status: "revoked", revokedAt: now },
  });
  await adapter.updateMany({
    model: "firstPartyAuthorization",
    where: [
      { field: "credentialId", value: credentialId },
      {
        field: "status",
        operator: "in",
        value: ["authorized", "code-issued"],
      },
    ],
    update: { status: "cancelled" },
  });
}

async function bindProviderCredential(
  ctx: GenericEndpointContext,
  logical: LogicalCredential,
  authorization: AuthorizedAttempt,
): Promise<void> {
  const credential = await readNativeProviderCredential(ctx, {
    provider: logical.provider,
    id: logical.providerCredentialId,
    clientId: logical.clientId,
    dpopJkt: logical.dpopJkt,
  });
  if (
    !credential ||
    credential.provider !== logical.provider ||
    credential.applicationId !== logical.applicationId ||
    credential.environment !== logical.environment ||
    credential.bindingVersion !==
      authorization.providerCredentialBindingVersion ||
    (credential.userId && credential.userId !== authorization.userId)
  )
    throw invalidGrant();
  try {
    requireUsableCredential(credential);
  } catch {
    throw invalidGrant();
  }
  // This update takes the provider row lock even for an already-bound user.
  // Legacy claims/revocation therefore cannot race native token issuance.
  const bound =
    await ctx.context.adapter.incrementOne<LifecycleProviderCredential>({
      model: nativeProviderCredentialModel(logical.provider),
      where: [
        { field: "id", value: credential.id },
        { field: "status", value: "active" },
        { field: "bindingVersion", value: credential.bindingVersion },
        { field: "userId", value: credential.userId ?? null },
      ],
      increment: credential.userId ? {} : { bindingVersion: 1 },
      set: {
        userId: authorization.userId,
        ...(credential.userId
          ? {}
          : { boundAt: new Date(), unboundExpiresAt: null }),
      },
    });
  if (!bound) throw invalidGrant();
  // The lock can have waited behind another transaction. Expiry must still
  // hold at the time of the claim, using the pre-claim unbound deadline.
  if (
    !credential.userId &&
    !credential.externallyBound &&
    (!credential.unboundExpiresAt || credential.unboundExpiresAt <= new Date())
  )
    throw invalidGrant();
}

function hashCode(ctx: GenericEndpointContext, code: string): string {
  return hmacSha256(ctx.context.secret, `first-party-code:v1:${code}`);
}
function invalidGrant(): APIError {
  return new APIError("BAD_REQUEST", {
    error: "invalid_grant",
    error_description: "The authorization cannot be redeemed.",
  });
}
