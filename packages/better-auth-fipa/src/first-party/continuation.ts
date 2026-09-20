import type { GenericEndpointContext } from "@better-auth/core";
import { createDpopReplayStore } from "@better-auth/core/oauth2";
import { APIError, isAPIError } from "better-auth/api";
import { randomBytes } from "node:crypto";
import { z } from "zod";
import { requireUsableCredential } from "../credential-store.js";
import {
  readNativeProviderCredential,
  type LifecycleProviderCredential,
} from "./provider-credential.js";
import { hmacSha256 } from "../protocol/crypto.js";
import {
  consumeNativeAdmission,
  type NativeAdmissionReceipt,
  type NativeApplicationPolicy,
} from "./admission.js";
import type { NativeAdmissionBinding } from "./admission-binding.js";
import {
  enrollLogicalCredential,
  recordAuthorizedAttempt,
  issueAuthorizationCode,
  type LogicalCredential,
} from "./authorization-store.js";
import { authenticateWithPassword } from "./password-method.js";
import { authenticateWithEmailOTP } from "./email-otp-method.js";
import type { AuthenticationMethodResult } from "./authentication-method.js";
import { verifyFirstPartyDpop } from "./dpop.js";
import { requireUserSecurity } from "./user-security.js";
import { withFirstPartyTransaction } from "./transaction.js";

export const AUTHORIZATION_CHALLENGE_PATH =
  "/first-party/authorization-challenge";
export interface ContinuationPolicy {
  sessionIdleSeconds: number;
  sessionAbsoluteSeconds: number;
  familyLifetimeSeconds: number;
  evidenceMaxAgeSeconds: number;
}
export interface NativeSession {
  id: string;
  handleHash: string;
  credentialId: string;
  credentialVersion: number;
  clientId: string;
  dpopJkt: string;
  activeAttemptId: string | null;
  userId: string | null;
  authenticatedAt: Date | null;
  generation: number;
  status: "active" | "revoked";
  createdAt: Date;
  expiresAt: Date;
  absoluteExpiresAt: Date;
}
export interface NativeAttempt {
  id: string;
  attemptId: string;
  sessionId: string;
  binding: NativeAdmissionBinding;
  receipt: NativeAdmissionReceipt;
  evidenceExpiresAt: Date;
  stepId: string;
  methods: ("password" | "email-otp")[];
  email: string | null;
  resumeStatus: "password" | "authentication" | "email-otp" | null;
  status:
    | "authentication"
    | "email-otp"
    | "email-otp-sending"
    | "password"
    | "processing"
    | "evidence"
    | "browser"
    | "code-issued"
    | "cancelled";
  operationId: string | null;
  userId: string | null;
  authenticatedAt: Date | null;
  authenticationMethods: string[];
  userSecurityHash: string | null;
  createdAt: Date;
  expiresAt: Date;
}
export type NativeStep =
  | {
      id: string;
      kind: "authentication";
      methods: ("password" | "email-otp")[];
    }
  | {
      id: string;
      kind: "password" | "email-otp" | "attestation" | "browser-required";
    };
export type NativeInteraction =
  | {
      kind: "step";
      authSession: string;
      step: NativeStep;
      binding?: NativeAdmissionBinding;
      failure?: "invalid_credentials" | "temporarily_unavailable";
      retryAfter?: string;
    }
  | { kind: "authorized"; authSession: string; authorizationCode: string }
  | { kind: "cancelled"; authSession: string }
  | {
      kind: "browser";
      authSession: string;
      requestUri: string;
      expiresIn: number;
      stepId: string;
    };
export interface ContinuationInput {
  authSession: string;
  clientId: string;
  headers: Headers;
}
const passwordInput = z.strictObject({
  email: z.email().max(320),
  password: z.string().min(1).max(1024),
});

export function validateContinuationPolicy(policy: ContinuationPolicy): void {
  for (const value of [
    policy.sessionIdleSeconds,
    policy.sessionAbsoluteSeconds,
    policy.familyLifetimeSeconds,
    policy.evidenceMaxAgeSeconds,
  ]) {
    if (!Number.isSafeInteger(value) || value < 1 || value > 86400 * 365)
      throw new TypeError(
        "First-party session, family and evidence lifetimes must be explicit positive seconds, at most one year.",
      );
  }
}

/** Admission consumption, logical-key pinning, attempt and session commit together. */
export async function startNativeAuthorization(
  ctx: GenericEndpointContext,
  application: NativeApplicationPolicy,
  policy: ContinuationPolicy,
  input: {
    binding: NativeAdmissionBinding;
    grantToken: string;
    headers: Headers;
    authSession?: string;
    methods?: ("password" | "email-otp")[];
  },
): Promise<NativeInteraction> {
  validateContinuationPolicy(policy);
  return consumeNativeAdmission(
    ctx,
    application,
    {
      ...input,
      challengeEndpointUrl: endpoint(ctx),
    },
    async (tx, receipt, provider) => {
      let logical = await tx.context.adapter.findOne<LogicalCredential>({
        model: "firstPartyCredential",
        where: [{ field: "providerCredentialId", value: provider.id }],
      });
      const binding = receipt.binding;
      if (!logical)
        logical = await enrollLogicalCredential(tx, {
          issuer: binding.issuer,
          clientId: binding.clientId,
          applicationId: binding.applicationId,
          environment: binding.environment,
          provider: binding.provider,
          providerCredentialId: provider.id,
          dpopJkt: binding.dpopJkt,
        });
      if (
        logical.issuer !== binding.issuer ||
        logical.clientId !== binding.clientId ||
        logical.dpopJkt !== binding.dpopJkt ||
        logical.applicationId !== binding.applicationId ||
        logical.environment !== binding.environment ||
        logical.provider !== binding.provider
      )
        throw invalidSession();
      await lockCredential(
        tx,
        logical.id,
        logical.version,
        binding.clientId,
        binding.dpopJkt,
      );
      const now = new Date();
      let session: NativeSession;
      const handle = newHandle();
      if (input.authSession) {
        session = await lookupSession(tx, input.authSession, binding.clientId);
        if (
          session.credentialId !== logical.id ||
          session.credentialVersion !== logical.version ||
          session.dpopJkt !== logical.dpopJkt
        )
          throw invalidSession();
        if (session.activeAttemptId) throw conflict();
        session = await rotateSession(tx, session, handle, policy);
      } else {
        session = await tx.context.adapter.create<NativeSession>({
          model: "firstPartySession",
          data: {
            handleHash: hashHandle(tx, handle),
            credentialId: logical.id,
            credentialVersion: logical.version,
            clientId: logical.clientId,
            dpopJkt: logical.dpopJkt,
            activeAttemptId: null,
            userId: null,
            authenticatedAt: null,
            generation: 0,
            status: "active",
            createdAt: now,
            expiresAt: new Date(
              now.getTime() +
                Math.min(
                  policy.sessionIdleSeconds,
                  policy.sessionAbsoluteSeconds,
                ) *
                  1000,
            ),
            absoluteExpiresAt: new Date(
              now.getTime() + policy.sessionAbsoluteSeconds * 1000,
            ),
          },
        });
      }
      const attempt = await tx.context.adapter.create<NativeAttempt>({
        model: "firstPartyAttempt",
        data: {
          attemptId: binding.attemptId,
          sessionId: session.id,
          binding,
          receipt,
          evidenceExpiresAt: evidenceExpiry(receipt, policy),
          stepId: randomId(),
          status: input.methods?.includes("email-otp")
            ? "authentication"
            : "password",
          methods: input.methods ?? ["password"],
          email: null,
          resumeStatus: null,
          authenticationMethods: [],
          userSecurityHash: null,
          operationId: null,
          userId: null,
          authenticatedAt: null,
          createdAt: now,
          expiresAt: new Date(now.getTime() + 900_000),
        },
      });
      if (attempt.evidenceExpiresAt <= now) throw invalidSession();
      await tx.context.adapter.update({
        model: "firstPartySession",
        where: [{ field: "id", value: session.id }],
        update: { activeAttemptId: attempt.id },
      });
      return interaction(handle, attempt);
    },
  );
}

/** Reserve the step before invoking account-sensitive work; never hold its DB lock during password hashing/hooks. */
export async function submitNativePassword(
  ctx: GenericEndpointContext,
  policy: ContinuationPolicy,
  input: ContinuationInput & {
    stepId: string;
    response: { email: string; password: string };
  },
): Promise<NativeInteraction> {
  const response = passwordInput.parse(input.response);
  return submitNativeFactor(ctx, policy, input, "password", () =>
    authenticateWithPassword(ctx, response),
  );
}

export async function submitNativeEmailOTP(
  ctx: GenericEndpointContext,
  policy: ContinuationPolicy,
  input: ContinuationInput & { stepId: string; otp: string },
): Promise<NativeInteraction> {
  const otp = z.string().min(1).max(128).parse(input.otp);
  return submitNativeFactor(ctx, policy, input, "email-otp", (attempt) => {
    if (!attempt.email) throw invalidSession();
    return authenticateWithEmailOTP(ctx, { email: attempt.email, otp });
  });
}

async function submitNativeFactor(
  ctx: GenericEndpointContext,
  policy: ContinuationPolicy,
  input: ContinuationInput & { stepId: string },
  method: "password" | "email-otp",
  authenticate: (
    attempt: NativeAttempt,
  ) => Promise<AuthenticationMethodResult<"pwd" | "otp">>,
): Promise<NativeInteraction> {
  validateContinuationPolicy(policy);
  const session = await proveSession(ctx, input);
  const claimed = await withFirstPartyTransaction(ctx, async (tx) => {
    await lockCredential(
      tx,
      session.credentialId,
      session.credentialVersion,
      session.clientId,
      session.dpopJkt,
    );
    const current = await lookupSession(tx, input.authSession, input.clientId);
    const attempt = await activeAttempt(tx, current, input.stepId);
    if (
      !attempt.methods.includes(method) ||
      (method === "password"
        ? attempt.status !== "password" && attempt.status !== "authentication"
        : attempt.status !== "email-otp")
    )
      throw conflict();
    if (attempt.evidenceExpiresAt <= new Date()) {
      const next = await updateAttempt(tx, attempt, {
        status: "evidence",
        resumeStatus: attempt.status as
          "password" | "authentication" | "email-otp",
        stepId: randomId(),
      });
      const handle = newHandle();
      await rotateSession(tx, current, handle, policy);
      return { interaction: interaction(handle, next) };
    }
    await checkProvider(tx, current, attempt);
    const pending = await updateAttempt(tx, attempt, {
      status: "processing",
      operationId: randomId(),
    });
    return { pending, session: current, returnStatus: attempt.status };
  });
  if ("interaction" in claimed) return claimed.interaction;
  let result: AuthenticationMethodResult<"pwd" | "otp">;
  let failure: "temporarily_unavailable" | undefined;
  let retryAfter: string | undefined;
  try {
    result = await authenticate(claimed.pending);
  } catch (error) {
    result = { kind: "rejected" };
    failure = "temporarily_unavailable";
    if (isAPIError(error) && error.statusCode === 429)
      retryAfter = new Headers(error.headers).get("retry-after") ?? undefined;
  }
  return withFirstPartyTransaction(ctx, async (tx) => {
    const logical = await lockCredential(
      tx,
      session.credentialId,
      session.credentialVersion,
      session.clientId,
      session.dpopJkt,
    );
    const current = await lookupSession(tx, input.authSession, input.clientId);
    const attempt = await activeAttempt(tx, current, input.stepId);
    if (
      attempt.status !== "processing" ||
      attempt.operationId !== claimed.pending.operationId
    )
      throw conflict();
    const provider = await checkProvider(tx, current, attempt);
    if (
      result.kind === "authenticated" &&
      ((logical.userId && logical.userId !== result.userId) ||
        (provider.userId && provider.userId !== result.userId))
    )
      throw invalidSession();
    const update: Partial<NativeAttempt> = {
      operationId: null,
      stepId: randomId(),
      status:
        result.kind === "browser-required" ? "browser" : claimed.returnStatus,
      email: result.kind === "rejected" ? attempt.email : null,
    };
    if (result.kind === "authenticated") {
      update.userId = result.userId;
      update.authenticatedAt = result.authenticatedAt;
      await requireUserSecurity(tx, result.userId, result.userSecurityHash);
      update.userSecurityHash = result.userSecurityHash;
      update.authenticationMethods = result.amr;
      update.status =
        attempt.evidenceExpiresAt <= new Date() ? "evidence" : "processing";
    }
    const next = await updateAttempt(tx, attempt, update);
    const handle = newHandle();
    const rotated = await rotateSession(tx, current, handle, policy);
    if (next.status === "processing")
      return completeAttempt(tx, policy, rotated, next, handle);
    const outcome = interaction(handle, next);
    if (outcome.kind === "step" && result.kind === "rejected") {
      outcome.failure = failure ?? "invalid_credentials";
      if (retryAfter) outcome.retryAfter = retryAfter;
    }
    return outcome;
  });
}

/** Fresh evidence commits to the original immutable attempt and retains verified factors. */
export async function renewNativeEvidence(
  ctx: GenericEndpointContext,
  application: NativeApplicationPolicy,
  policy: ContinuationPolicy,
  input: ContinuationInput & { stepId: string; grantToken: string },
): Promise<NativeInteraction> {
  validateContinuationPolicy(policy);
  const session = await lookupSession(ctx, input.authSession, input.clientId);
  const pending = await activeAttempt(ctx, session, input.stepId);
  if (pending.status !== "evidence") throw conflict();
  return consumeNativeAdmission(
    ctx,
    application,
    {
      grantToken: input.grantToken,
      binding: pending.binding,
      headers: input.headers,
      challengeEndpointUrl: endpoint(ctx),
    },
    async (tx, receipt, provider) => {
      const logical = await lockCredential(
        tx,
        session.credentialId,
        session.credentialVersion,
        session.clientId,
        session.dpopJkt,
      );
      if (logical.providerCredentialId !== provider.id) throw invalidSession();
      const current = await lookupSession(
        tx,
        input.authSession,
        input.clientId,
      );
      const attempt = await activeAttempt(tx, current, input.stepId);
      if (attempt.status !== "evidence") throw conflict();
      if (
        attempt.userId &&
        ((logical.userId && logical.userId !== attempt.userId) ||
          (provider.userId && provider.userId !== attempt.userId))
      )
        throw invalidSession();
      const next = await updateAttempt(tx, attempt, {
        receipt,
        evidenceExpiresAt: evidenceExpiry(receipt, policy),
        stepId: randomId(),
        status: attempt.userId
          ? "processing"
          : (attempt.resumeStatus ?? "password"),
        resumeStatus: null,
      });
      if (next.evidenceExpiresAt <= new Date()) throw invalidSession();
      const handle = newHandle();
      const rotated = await rotateSession(tx, current, handle, policy);
      if (next.userId)
        return completeAttempt(tx, policy, rotated, next, handle);
      return interaction(handle, next);
    },
  );
}

export async function cancelNativeAttempt(
  ctx: GenericEndpointContext,
  policy: ContinuationPolicy,
  input: ContinuationInput & { stepId: string },
): Promise<NativeInteraction> {
  validateContinuationPolicy(policy);
  const session = await proveSession(ctx, input);
  return withFirstPartyTransaction(ctx, async (tx) => {
    await lockCredential(
      tx,
      session.credentialId,
      session.credentialVersion,
      session.clientId,
      session.dpopJkt,
    );
    const current = await lookupSession(tx, input.authSession, input.clientId);
    if (!current.activeAttemptId) throw conflict();
    // Cancellation is valid even after attempt expiry, but must name the
    // current step. A stale UI action cannot cancel a different interaction.
    const attempt = await tx.context.adapter.findOne<NativeAttempt>({
      model: "firstPartyAttempt",
      where: [
        { field: "id", value: current.activeAttemptId },
        { field: "sessionId", value: current.id },
      ],
    });
    if (!attempt || attempt.stepId !== input.stepId)
      throw new APIError("BAD_REQUEST", { error: "invalid_request" });
    await tx.context.adapter.update({
      model: "firstPartyAttempt",
      where: [
        { field: "id", value: current.activeAttemptId },
        { field: "sessionId", value: current.id },
      ],
      update: {
        status: "cancelled",
        operationId: null,
        email: null,
        resumeStatus: null,
      },
    });
    const handle = newHandle();
    const rotated = await rotateSession(tx, current, handle, policy);
    await tx.context.adapter.update({
      model: "firstPartySession",
      where: [{ field: "id", value: rotated.id }],
      update: { activeAttemptId: null },
    });
    return { kind: "cancelled", authSession: handle };
  });
}

export async function completeAttempt(
  ctx: GenericEndpointContext,
  policy: ContinuationPolicy,
  session: NativeSession,
  attempt: NativeAttempt,
  handle: string,
  redirectUri?: string,
): Promise<NativeInteraction> {
  if (
    !attempt.userId ||
    !attempt.authenticatedAt ||
    !attempt.userSecurityHash ||
    attempt.evidenceExpiresAt <= new Date()
  )
    throw invalidSession();
  const binding = attempt.binding;
  const authorization = await recordAuthorizedAttempt(ctx, {
    attemptId: attempt.attemptId,
    nativeSessionId: session.id,
    nonce: binding.nonce ?? null,
    redirectUri: redirectUri ?? null,
    credentialId: session.credentialId,
    credentialVersion: session.credentialVersion,
    providerCredentialBindingVersion: attempt.receipt.credentialBindingVersion,
    clientId: session.clientId,
    userId: attempt.userId,
    userSecurityHash: attempt.userSecurityHash,
    dpopJkt: session.dpopJkt,
    codeChallenge: binding.codeChallenge,
    scopes: binding.scopes,
    resources: binding.resources,
    assurance: {
      profile: binding.profile,
      provider: binding.provider,
      applicationId: binding.applicationId,
      environment: binding.environment,
      evidenceKind: attempt.receipt.evidence ? "combined" : "credential-key",
      ...(attempt.receipt.evidence
        ? { evidence: attempt.receipt.evidence }
        : {}),
      evidenceVerifiedAt: attempt.receipt.verifiedAt,
      amr: attempt.authenticationMethods,
    },
    assuranceExpiresAt: attempt.evidenceExpiresAt,
    authenticatedAt: attempt.authenticatedAt,
    familyExpiresAt: new Date(Date.now() + policy.familyLifetimeSeconds * 1000),
    expiresAt: attempt.expiresAt,
  });
  const code = await issueAuthorizationCode(ctx, authorization.id);
  await updateAttempt(ctx, attempt, {
    status: "code-issued",
    operationId: null,
    email: null,
    resumeStatus: null,
  });
  await ctx.context.adapter.update({
    model: "firstPartySession",
    where: [{ field: "id", value: session.id }],
    update: {
      activeAttemptId: null,
      userId: attempt.userId,
      authenticatedAt: attempt.authenticatedAt,
    },
  });
  return { kind: "authorized", authSession: handle, authorizationCode: code };
}

export async function proveSession(
  ctx: GenericEndpointContext,
  input: ContinuationInput,
): Promise<NativeSession> {
  const session = await lookupSession(ctx, input.authSession, input.clientId);
  await verifyFirstPartyDpop({
    headers: input.headers,
    method: "POST",
    endpointUrl: endpoint(ctx),
    expectedJkt: session.dpopJkt,
    replayStore: createDpopReplayStore(ctx.context.internalAdapter),
  });
  return session;
}
export async function lookupSession(
  ctx: GenericEndpointContext,
  handle: string,
  clientId: string,
): Promise<NativeSession> {
  const session = await ctx.context.adapter.findOne<NativeSession>({
    model: "firstPartySession",
    where: [{ field: "handleHash", value: hashHandle(ctx, handle) }],
  });
  if (
    !session ||
    session.clientId !== clientId ||
    session.status !== "active" ||
    session.expiresAt <= new Date() ||
    session.absoluteExpiresAt <= new Date()
  )
    throw invalidSession();
  return session;
}
export async function activeAttempt(
  ctx: GenericEndpointContext,
  session: NativeSession,
  stepId: string,
): Promise<NativeAttempt> {
  if (!session.activeAttemptId) throw invalidSession();
  const attempt = await ctx.context.adapter.findOne<NativeAttempt>({
    model: "firstPartyAttempt",
    where: [
      { field: "id", value: session.activeAttemptId },
      { field: "sessionId", value: session.id },
    ],
  });
  if (!attempt || attempt.expiresAt <= new Date()) throw invalidSession();
  if (attempt.stepId !== stepId)
    throw new APIError("BAD_REQUEST", { error: "invalid_request" });
  return attempt;
}
export async function lockCredential(
  ctx: GenericEndpointContext,
  id: string,
  version: number,
  clientId: string,
  dpopJkt: string,
): Promise<LogicalCredential> {
  const credential = await ctx.context.adapter.incrementOne<LogicalCredential>({
    model: "firstPartyCredential",
    where: [
      { field: "id", value: id },
      { field: "version", value: version },
      { field: "status", value: "active" },
      { field: "issuer", value: ctx.context.baseURL },
      { field: "clientId", value: clientId },
      { field: "dpopJkt", value: dpopJkt },
    ],
    increment: { revision: 1 },
  });
  if (!credential) throw invalidSession();
  return credential;
}
export async function checkProvider(
  ctx: GenericEndpointContext,
  session: NativeSession,
  attempt: NativeAttempt,
): Promise<LifecycleProviderCredential> {
  const provider = await readNativeProviderCredential(ctx, {
    provider: attempt.binding.provider,
    id: attempt.receipt.credentialId,
    clientId: attempt.binding.clientId,
    dpopJkt: attempt.binding.dpopJkt,
  });
  try {
    requireUsableCredential(provider);
  } catch {
    throw invalidSession();
  }
  if (
    !provider ||
    provider.bindingVersion !== attempt.receipt.credentialBindingVersion ||
    provider.provider !== attempt.binding.provider ||
    provider.applicationId !== attempt.binding.applicationId ||
    provider.environment !== attempt.binding.environment ||
    session.dpopJkt !== attempt.binding.dpopJkt ||
    session.clientId !== attempt.binding.clientId
  )
    throw invalidSession();
  return provider;
}
export async function rotateSession(
  ctx: GenericEndpointContext,
  session: NativeSession,
  handle: string,
  policy: ContinuationPolicy,
): Promise<NativeSession> {
  const now = new Date();
  const result = await ctx.context.adapter.incrementOne<NativeSession>({
    model: "firstPartySession",
    where: [
      { field: "id", value: session.id },
      { field: "handleHash", value: session.handleHash },
      { field: "generation", value: session.generation },
      { field: "status", value: "active" },
      { field: "expiresAt", operator: "gt", value: now },
      { field: "absoluteExpiresAt", operator: "gt", value: now },
    ],
    increment: { generation: 1 },
    set: {
      handleHash: hashHandle(ctx, handle),
      expiresAt: new Date(
        Math.min(
          now.getTime() + policy.sessionIdleSeconds * 1000,
          session.absoluteExpiresAt.getTime(),
        ),
      ),
    },
  });
  if (!result) throw invalidSession();
  return result;
}
export async function updateAttempt(
  ctx: GenericEndpointContext,
  attempt: NativeAttempt,
  update: Partial<NativeAttempt>,
): Promise<NativeAttempt> {
  const result = await ctx.context.adapter.incrementOne<NativeAttempt>({
    model: "firstPartyAttempt",
    where: [
      { field: "id", value: attempt.id },
      { field: "status", value: attempt.status },
      { field: "stepId", value: attempt.stepId },
    ],
    increment: {},
    set: update,
  });
  if (!result) throw conflict();
  return result;
}
export function interaction(
  handle: string,
  attempt: NativeAttempt,
): NativeInteraction {
  return {
    kind: "step",
    authSession: handle,
    step:
      attempt.status === "authentication"
        ? {
            id: attempt.stepId,
            kind: "authentication",
            methods: attempt.methods,
          }
        : {
            id: attempt.stepId,
            kind:
              attempt.status === "evidence"
                ? "attestation"
                : attempt.status === "browser"
                  ? "browser-required"
                  : attempt.status === "email-otp"
                    ? "email-otp"
                    : "password",
          },
    ...(attempt.status === "evidence" ? { binding: attempt.binding } : {}),
  };
}
function evidenceExpiry(
  receipt: NativeAdmissionReceipt,
  policy: ContinuationPolicy,
): Date {
  return new Date(
    Math.min(
      new Date(receipt.verifiedAt).getTime() +
        policy.evidenceMaxAgeSeconds * 1000,
      receipt.expiresAt === undefined
        ? Infinity
        : new Date(receipt.expiresAt).getTime(),
    ),
  );
}
export function randomId(): string {
  return randomBytes(32).toString("base64url");
}
export function newHandle(): string {
  return `fpas1_${randomId()}`;
}
function hashHandle(ctx: GenericEndpointContext, handle: string): string {
  if (!/^fpas1_[A-Za-z0-9_-]{43}$/.test(handle)) throw invalidSession();
  return hmacSha256(ctx.context.secret, `first-party-session:v1:${handle}`);
}
function endpoint(ctx: GenericEndpointContext): string {
  return `${ctx.context.baseURL}${AUTHORIZATION_CHALLENGE_PATH}`;
}
function invalidSession(): APIError {
  return new APIError("BAD_REQUEST", { error: "invalid_session" });
}
function conflict(): APIError {
  return new APIError("CONFLICT", { error: "interaction_conflict" });
}
