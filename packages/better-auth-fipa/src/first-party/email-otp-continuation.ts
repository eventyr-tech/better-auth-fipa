import type { GenericEndpointContext } from "@better-auth/core";
import { APIError, isAPIError } from "better-auth/api";
import { z } from "zod";
import {
  activeAttempt,
  checkProvider,
  interaction,
  lockCredential,
  lookupSession,
  newHandle,
  proveSession,
  randomId,
  rotateSession,
  updateAttempt,
  type ContinuationInput,
  type NativeAttempt,
  type NativeInteraction,
} from "./continuation.js";
import {
  requestEmailOTPDelivery,
  type EmailDeliveryResult,
} from "./email-otp-delivery.js";
import { withFirstPartyTransaction } from "./transaction.js";
import type { NativeTokenOptions } from "./token-lifecycle.js";
import { FIRST_PARTY_PROFILE } from "./wire.js";
import { getFirstPartyOAuthApi } from "./oauth-api.js";

/** Delivery is allowed only from the server-offered method or the bound OTP
 * step. The selected recipient never comes back from a verification/resend
 * request, and delivery itself cannot authenticate or issue an OAuth code.
 */
export async function requestNativeEmailOTP(
  ctx: GenericEndpointContext,
  options: NativeTokenOptions,
  input: ContinuationInput & { stepId: string; email?: string },
): Promise<NativeInteraction> {
  const deliveryPolicy = options.emailOTP;
  if (!deliveryPolicy) throw invalid();
  const email =
    input.email === undefined
      ? undefined
      : z
          .string()
          .trim()
          .toLowerCase()
          .pipe(z.email().max(320))
          .parse(input.email);
  const session = await proveSession(ctx, input);
  const currentClient = async () => {
    const value = await getFirstPartyOAuthApi(ctx, options.oauth).getClient(
      input.clientId,
    );
    if (!value || value.disabled) throw invalid();
    return value;
  };
  let client = await currentClient();
  const application = options.applications.find(
    (value) => value.clientId === input.clientId,
  );
  const check = async (tx: GenericEndpointContext) => {
    await lockCredential(
      tx,
      session.credentialId,
      session.credentialVersion,
      session.clientId,
      session.dpopJkt,
    );
    const current = await lookupSession(tx, input.authSession, input.clientId);
    const attempt = await activeAttempt(tx, current, input.stepId);
    await checkProvider(tx, current, attempt);
    if (
      !application ||
      attempt.binding.provider !== application.provider.id ||
      attempt.binding.applicationId !== application.applicationId ||
      attempt.binding.environment !== application.environment ||
      attempt.binding.scopes.some(
        (scope) =>
          !application.scopes.includes(scope) ||
          !client.scopes?.includes(scope),
      ) ||
      attempt.binding.resources.some(
        (resource) => !application.resources.includes(resource),
      ) ||
      !attempt.methods.includes("email-otp")
    )
      throw invalid();
    return { current, attempt };
  };
  const claimed = await withFirstPartyTransaction(ctx, async (tx) => {
    const { current, attempt } = await check(tx);
    const source =
      attempt.status === "email-otp-sending"
        ? attempt.resumeStatus
        : attempt.status;
    if (source !== "authentication" && source !== "email-otp") throw invalid();
    if (
      (email === undefined
        ? source !== "email-otp"
        : source !== "authentication") ||
      (attempt.status === "email-otp-sending" &&
        email !== undefined &&
        email !== attempt.email)
    )
      throw invalid();
    if (attempt.status === "email-otp-sending") return { current, attempt };
    if (attempt.evidenceExpiresAt <= new Date()) {
      const next = await updateAttempt(tx, attempt, {
        status: "evidence",
        resumeStatus: source,
        stepId: randomId(),
      });
      const handle = newHandle();
      await rotateSession(tx, current, handle, options.lifetimes);
      return { interaction: interaction(handle, next) };
    }
    const pending = await updateAttempt(tx, attempt, {
      status: "email-otp-sending",
      operationId: randomId(),
      resumeStatus: source,
      email: email ?? attempt.email,
    });
    return { current, attempt: pending };
  });
  if ("interaction" in claimed) return claimed.interaction;
  const pending = claimed.attempt;
  if (
    !pending.email ||
    !pending.operationId ||
    (pending.resumeStatus !== "authentication" &&
      pending.resumeStatus !== "email-otp")
  )
    throw invalid();
  const returnStatus = pending.resumeStatus;
  let outcome: EmailDeliveryResult = { kind: "unknown" };
  let retryAfter: string | undefined;
  try {
    outcome = await requestEmailOTPDelivery(
      ctx,
      deliveryPolicy,
      {
        profile: FIRST_PARTY_PROFILE,
        operationId: pending.operationId,
        providerCredentialId: pending.receipt.credentialId,
        expiresAt: new Date(
          Math.min(
            pending.expiresAt.getTime(),
            claimed.current.expiresAt.getTime(),
            pending.evidenceExpiresAt.getTime(),
          ),
        ),
        email: pending.email,
      },
      async (tx) => {
        const { attempt } = await check(tx);
        if (
          attempt.status !== "email-otp-sending" ||
          attempt.operationId !== pending.operationId ||
          attempt.email !== pending.email ||
          attempt.evidenceExpiresAt <= new Date()
        )
          throw invalid();
      },
    );
  } catch (error) {
    if (isAPIError(error) && error.statusCode === 429) {
      outcome = { kind: "rejected" };
      retryAfter = new Headers(error.headers).get("retry-after") ?? undefined;
    }
    // Other failures may follow a send. Preserve the bound recipient and offer
    // explicit, budgeted resend; never invoke delivery again automatically.
  }
  // The sender may wait on external I/O; refresh registered-client policy before
  // allowing its result to advance the continuation.
  client = await currentClient();
  return withFirstPartyTransaction(ctx, async (tx) => {
    const { current, attempt } = await check(tx);
    if (
      attempt.status !== "email-otp-sending" ||
      attempt.operationId !== pending.operationId
    )
      throw invalid();
    const nextStatus = outcome.kind === "rejected" ? returnStatus : "email-otp";
    const update: Partial<NativeAttempt> = {
      status: nextStatus,
      operationId: null,
      resumeStatus: null,
      stepId: randomId(),
      email: nextStatus === "email-otp" ? pending.email : null,
    };
    if (attempt.evidenceExpiresAt <= new Date()) {
      update.status = "evidence";
      update.resumeStatus = nextStatus;
    }
    const next = await updateAttempt(tx, attempt, update);
    const handle = newHandle();
    await rotateSession(tx, current, handle, options.lifetimes);
    const result = interaction(handle, next);
    if (result.kind === "step" && outcome.kind !== "requested") {
      result.failure = "temporarily_unavailable";
      if (retryAfter) result.retryAfter = retryAfter;
    }
    return result;
  });
}

function invalid() {
  return new APIError("BAD_REQUEST", { error: "invalid_session" });
}
