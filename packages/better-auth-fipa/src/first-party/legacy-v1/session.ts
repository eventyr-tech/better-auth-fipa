import type { GenericEndpointContext } from "@better-auth/core";
import type { BetterAuthPlugin } from "better-auth";
import type { DBPrimitive } from "@better-auth/core/db";
import type { OAuthOptions } from "@better-auth/oauth-provider";
import { APIError } from "better-auth/api";
import { randomBytes } from "node:crypto";
import { z } from "zod";
import { CREDENTIAL_MODEL } from "../../credential-store.js";
import { consumeOAuthAdmissionGrant } from "../../oauth-grant.js";
import { hashOAuthBinding } from "../../protocol/binding.js";
import { hmacSha256 } from "../../protocol/crypto.js";
import type {
  OAuthAuthorizationBinding,
  StoredAttestationCredential,
} from "../../types.js";
import { requireUserSecurity } from "../user-security.js";
import { withFirstPartyTransaction } from "../transaction.js";
import { getFirstPartyOAuthApi } from "../oauth-api.js";
import {
  parseLegacyChallenge,
  legacyPasswordAcr,
  legacyStepSchema,
  type LegacyClientPolicy,
  type LegacyChallengeRequest,
  type LegacyStep,
} from "./contract.js";

const text = {
  type: "string",
  required: true,
  input: false,
  returned: false,
} as const;
const date = {
  type: "date",
  required: true,
  input: false,
  returned: false,
} as const;
const integer = {
  type: "number",
  required: true,
  input: false,
  returned: false,
} as const;
/** Separate table and handle domain. Not installed until the compatibility adapter is composed. */
export const legacySessionSchema = {
  firstPartyLegacySession: {
    fields: {
      profile: { ...text, type: ["legacy-v1"] },
      handleHash: { ...text, unique: true },
      issuer: text,
      clientId: text,
      binding: {
        ...text,
        type: "json",
        transform: {
          output: (value: DBPrimitive): DBPrimitive =>
            typeof value === "string"
              ? (JSON.parse(value) as DBPrimitive)
              : value,
        },
      },
      bindingHash: text,
      credentialId: { ...text, index: true },
      credentialBindingVersion: integer,
      revision: integer,
      status: {
        ...text,
        type: ["ready", "processing", "code-issued", "revoked"],
      },
      operationId: { ...text, required: false },
      authorizationId: { ...text, required: false },
      intent: text,
      requestedAcr: { ...text, required: false },
      step: text,
      email: { ...text, required: false },
      verifiedUserId: { ...text, required: false },
      userSecurityHash: { ...text, required: false },
      authenticatedAt: { ...date, required: false },
      createdAt: date,
      evidenceVerifiedAt: date,
      expiresAt: date,
    },
  },
} satisfies NonNullable<BetterAuthPlugin["schema"]>;
export interface LegacySession {
  id: string;
  profile: "legacy-v1";
  handleHash: string;
  issuer: string;
  clientId: string;
  binding: OAuthAuthorizationBinding;
  bindingHash: string;
  credentialId: string;
  credentialBindingVersion: number;
  revision: number;
  status: "ready" | "processing" | "code-issued" | "revoked";
  operationId: string | null;
  authorizationId: string | null;
  intent: "authenticate" | "login" | "create_account" | "step_up";
  requestedAcr: string | null;
  step: LegacyStep;
  email: string | null;
  verifiedUserId: string | null;
  userSecurityHash: string | null;
  authenticatedAt: Date | null;
  createdAt: Date;
  evidenceVerifiedAt: Date;
  expiresAt: Date;
}
interface Options {
  policy: LegacyClientPolicy;
  oauth: OAuthOptions<string[]>;
}

/** Input is the server-verified legacy grant, never a native admission receipt.
 * Consume it atomically with creation so a storage failure permits a safe retry.
 * No caller password, OTP, bearer token or account subject is persisted here. */
export async function createLegacySession(
  ctx: GenericEndpointContext,
  options: Options,
  parameters: Record<string, unknown>,
  grantToken: string,
): Promise<{ authSession: string; session: LegacySession }> {
  const { request, binding } = parseLegacyChallenge(parameters, options.policy);
  if (request.auth_session) throw invalidSession();
  const seconds = options.policy.sessionLifetimeSeconds;
  if (!Number.isSafeInteger(seconds) || seconds < 1 || seconds > 1800)
    throw new TypeError(
      "Legacy sessions require an explicit lifetime of at most 1800 seconds.",
    );
  await registeredLegacyClient(ctx, options, binding);
  return withFirstPartyTransaction(ctx, async (tx) => {
    const admitted = await consumeOAuthAdmissionGrant(
      tx.context,
      grantToken,
      binding,
    );
    const credential = admitted.credential;
    if (
      credential.provider !== options.policy.provider ||
      credential.applicationId !== options.policy.applicationId ||
      credential.environment !== options.policy.environment
    )
      throw invalidSession();
    const now = new Date();
    const authSession = `fpls1_${randomBytes(32).toString("base64url")}`;
    const session = await tx.context.adapter.create<LegacySession>({
      model: "firstPartyLegacySession",
      data: {
        profile: "legacy-v1",
        handleHash: handleHash(tx, authSession),
        issuer: tx.context.baseURL,
        clientId: binding.clientId,
        binding,
        bindingHash: hashOAuthBinding(binding).toString("base64url"),
        credentialId: credential.id,
        credentialBindingVersion: credential.bindingVersion,
        revision: 0,
        status: "ready",
        operationId: null,
        authorizationId: null,
        intent: request.intent ?? "login",
        requestedAcr: legacyPasswordAcr(request, options.policy),
        step:
          request.intent === "create_account"
            ? "email_verification"
            : "email_password",
        email:
          (request.email ?? request.login_hint)?.trim().toLowerCase() || null,
        verifiedUserId: null,
        userSecurityHash: null,
        authenticatedAt: null,
        createdAt: now,
        evidenceVerifiedAt: admitted.verifiedAt,
        // Consuming admission early must not extend the original legacy grant's authority.
        expiresAt: new Date(
          Math.min(
            now.getTime() + seconds * 1000,
            admitted.expiresAt.getTime(),
          ),
        ),
      },
    });
    return { authSession, session };
  });
}

/** Reserve before password validation, OTP delivery or any host method work.
 * A second request cannot run another method while this operation is in flight. */
export async function reserveLegacyStep(
  ctx: GenericEndpointContext,
  options: Options,
  parameters: Record<string, unknown>,
  expectedSteps?: readonly LegacyStep[],
  validate?: (session: LegacySession) => void,
): Promise<LegacySession> {
  const { request, binding } = parseLegacyChallenge(parameters, options.policy);
  if (!request.auth_session) throw invalidSession();
  await registeredLegacyClient(ctx, options, binding);
  return withFirstPartyTransaction(ctx, async (tx) => {
    const session = await findLegacySession(tx, request.auth_session!, binding);
    requireLegacyAcr(session, request, options.policy);
    if (expectedSteps && !expectedSteps.includes(session.step))
      throw invalidSession();
    validate?.(session);
    await lockLegacyProvider(tx, session, options.policy);
    const claimed = await tx.context.adapter.incrementOne<LegacySession>({
      model: "firstPartyLegacySession",
      where: [
        { field: "id", value: session.id },
        { field: "profile", value: "legacy-v1" },
        { field: "status", value: "ready" },
        { field: "revision", value: session.revision },
        { field: "expiresAt", operator: "gt", value: new Date() },
      ],
      increment: { revision: 1 },
      set: {
        status: "processing",
        operationId: randomBytes(32).toString("base64url"),
      },
    });
    if (!claimed) throw invalidSession();
    return claimed;
  });
}

/** Read a pending prompt without reserving a method or triggering another OTP.
 * Polling still requires the full registered-client, binding and provider checks.
 */
export async function inspectLegacySession(
  ctx: GenericEndpointContext,
  options: Options,
  parameters: Record<string, unknown>,
): Promise<LegacySession> {
  const { request, binding } = parseLegacyChallenge(parameters, options.policy);
  if (!request.auth_session) throw invalidSession();
  await registeredLegacyClient(ctx, options, binding);
  return withFirstPartyTransaction(ctx, async (tx) => {
    const session = await findLegacySession(tx, request.auth_session!, binding);
    requireLegacyAcr(session, request, options.policy);
    await lockLegacyProvider(tx, session, options.policy);
    return session;
  });
}

async function findLegacySession(
  ctx: GenericEndpointContext,
  handle: string,
  binding: OAuthAuthorizationBinding,
) {
  const session = await ctx.context.adapter.findOne<LegacySession>({
    model: "firstPartyLegacySession",
    where: [{ field: "handleHash", value: handleHash(ctx, handle) }],
  });
  if (
    !session ||
    session.profile !== "legacy-v1" ||
    session.issuer !== ctx.context.baseURL ||
    session.clientId !== binding.clientId ||
    session.status !== "ready" ||
    session.expiresAt <= new Date() ||
    session.bindingHash !== hashOAuthBinding(binding).toString("base64url") ||
    session.bindingHash !==
      hashOAuthBinding(session.binding).toString("base64url")
  )
    throw invalidSession();
  return session;
}

/** Omission retains the original requirement; a continuation cannot replace it. */
export function requireLegacyAcr(
  session: Pick<LegacySession, "requestedAcr" | "step">,
  request: Pick<LegacyChallengeRequest, "acr_values" | "intent">,
  policy: LegacyClientPolicy,
) {
  const selected = legacyPasswordAcr(request, policy);
  if (
    (selected !== null && selected !== session.requestedAcr) ||
    (session.requestedAcr &&
      (!policy.passwordAcrValues?.includes(session.requestedAcr) ||
        session.step !== "email_password" ||
        request.intent === "create_account"))
  )
    throw invalidSession();
}

/** Resume the exact reserved continuation after a non-terminal method result.
 * This is not an authorization result and cannot mint a code or token. Terminal
 * authentication/issuance is composed separately in the same database transaction. */
export async function finishLegacyStep(
  ctx: GenericEndpointContext,
  options: Options,
  reservation: LegacySession,
  input: {
    step: LegacyStep;
    email?: string;
    verified?: {
      userId: string;
      userSecurityHash: string;
      authenticatedAt: Date;
    };
  },
): Promise<LegacySession> {
  const result = z
    .strictObject({
      step: legacyStepSchema,
      email: z.string().max(320).optional(),
      verified: z
        .object({
          userId: z.string().min(1),
          userSecurityHash: z.string().regex(/^[a-f0-9]{64}$/),
          authenticatedAt: z.date(),
        })
        .optional(),
    })
    .parse(input);
  // A configured OAuth discovery adapter may perform network I/O. Keep lookup
  // outside the provider/session transaction; final issuance must recheck policy.
  await registeredLegacyClient(ctx, options, reservation.binding);
  return withFirstPartyTransaction(ctx, async (tx) => {
    const provider = await lockLegacyProvider(tx, reservation, options.policy);
    if (result.verified) {
      if (
        !reservation.operationId ||
        reservation.step !== "email_verification" ||
        !["profile_password", "email_password"].includes(result.step) ||
        result.verified.authenticatedAt < reservation.createdAt ||
        result.verified.authenticatedAt > new Date() ||
        (provider.userId && provider.userId !== result.verified.userId)
      )
        throw invalidSession();
      await requireUserSecurity(
        tx,
        result.verified.userId,
        result.verified.userSecurityHash,
      );
    }
    const updated = await tx.context.adapter.incrementOne<LegacySession>({
      model: "firstPartyLegacySession",
      where: [
        { field: "id", value: reservation.id },
        { field: "profile", value: "legacy-v1" },
        { field: "status", value: "processing" },
        { field: "revision", value: reservation.revision },
        { field: "operationId", value: reservation.operationId },
        { field: "expiresAt", operator: "gt", value: new Date() },
      ],
      increment: { revision: 1 },
      set: {
        status: "ready",
        operationId: null,
        step: result.step,
        ...(result.step === "email_verification"
          ? {
              verifiedUserId: null,
              userSecurityHash: null,
              authenticatedAt: null,
            }
          : {}),
        ...(result.verified
          ? {
              verifiedUserId: result.verified.userId,
              userSecurityHash: result.verified.userSecurityHash,
              authenticatedAt: result.verified.authenticatedAt,
            }
          : {}),
        ...(result.email === undefined
          ? {}
          : { email: result.email.trim().toLowerCase() }),
      },
    });
    if (!updated) throw invalidSession();
    return updated;
  });
}

export async function registeredLegacyClient(
  ctx: GenericEndpointContext,
  options: Options,
  binding: OAuthAuthorizationBinding,
) {
  const client = await getFirstPartyOAuthApi(ctx, options.oauth).getClient(
    binding.clientId,
  );
  const permitted = parseLegacyChallenge(
    {
      client_id: binding.clientId,
      scope: binding.scope,
      code_challenge: binding.codeChallenge,
      code_challenge_method: "S256",
      dpop_jkt: binding.dpopJkt,
      redirect_uri: binding.redirectUri,
      ...(binding.resources?.length ? { resource: binding.resources } : {}),
    },
    options.policy,
  );
  if (
    !client ||
    client.disabled ||
    (client.expiresAt && client.expiresAt <= new Date()) ||
    client.tokenEndpointAuthMethod !== "none" ||
    !client.grantTypes?.includes("authorization_code") ||
    !client.redirectUris?.includes(permitted.binding.redirectUri) ||
    binding.scope
      .split(" ")
      .some((scope) => !(client.scopes ?? []).includes(scope))
  )
    throw invalidSession();
}
export async function lockLegacyProvider(
  ctx: GenericEndpointContext,
  session: LegacySession,
  policy: LegacyClientPolicy,
) {
  const credential =
    await ctx.context.adapter.incrementOne<StoredAttestationCredential>({
      model: CREDENTIAL_MODEL,
      where: [
        { field: "id", value: session.credentialId },
        { field: "status", value: "active" },
        { field: "bindingVersion", value: session.credentialBindingVersion },
      ],
      increment: { bindingVersion: 0 },
    });
  if (
    !credential ||
    credential.provider !== policy.provider ||
    credential.applicationId !== policy.applicationId ||
    credential.environment !== policy.environment ||
    (!credential.userId &&
      !credential.externallyBound &&
      (!credential.unboundExpiresAt ||
        credential.unboundExpiresAt <= new Date()))
  )
    throw invalidSession();
  return credential;
}
export function handleHash(ctx: GenericEndpointContext, handle: string) {
  if (!/^fpls1_[A-Za-z0-9_-]{43}$/.test(handle)) throw invalidSession();
  return hmacSha256(
    ctx.context.secret,
    `first-party-legacy-session:v1:${handle}`,
  );
}
function invalidSession() {
  return new APIError("BAD_REQUEST", { error: "invalid_grant" });
}
