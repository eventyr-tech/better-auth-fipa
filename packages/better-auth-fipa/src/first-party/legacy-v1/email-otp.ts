import type { GenericEndpointContext } from "@better-auth/core";
import type { OAuthOptions } from "@better-auth/oauth-provider";
import { APIError, isAPIError } from "better-auth/api";
import { z } from "zod";
import {
  requestEmailOTPDelivery,
  type EmailDeliveryConfiguration,
  type EmailDeliveryResult,
} from "../email-otp-delivery.js";
import {
  authenticateWithEmailOTP,
  type EmailOTPMethodResult,
} from "../email-otp-method.js";
import { parseLegacyChallenge, type LegacyClientPolicy } from "./contract.js";
import {
  reserveLegacyStep,
  finishLegacyStep,
  lockLegacyProvider,
  type LegacySession,
} from "./session.js";

interface Options {
  policy: LegacyClientPolicy;
  oauth: OAuthOptions<string[]>;
  emailOTP: EmailDeliveryConfiguration;
}
const emailSchema = z.string().trim().toLowerCase().pipe(z.email().max(320));

/** Internal legacy coordinator. The HTTP adapter owns the old 200/next_step
 * envelope. Neither delivery nor an account hint is an authentication result. */
export async function requestLegacyEmailOTP(
  ctx: GenericEndpointContext,
  options: Options,
  parameters: Record<string, unknown>,
) {
  const { request } = parseLegacyChallenge(parameters, options.policy);
  if (request.password || request.verification_code || request.new_password)
    throw invalid();
  const reservation = await reserveLegacyStep(
    ctx,
    options,
    parameters,
    ["email_password", "email_verification"],
    (session) => {
      recipient(session, request.email ?? request.login_hint);
    },
  );
  const email = recipient(reservation, request.email ?? request.login_hint);
  let outcome: EmailDeliveryResult = { kind: "unknown" };
  let retryAfter: string | undefined;
  try {
    outcome = await requestEmailOTPDelivery(
      ctx,
      options.emailOTP,
      {
        profile: "legacy-v1",
        operationId: reservation.operationId!,
        providerCredentialId: reservation.credentialId,
        expiresAt: reservation.expiresAt,
        email,
      },
      async (tx) => {
        await lockLegacyProvider(tx, reservation, options.policy);
        const current = await tx.context.adapter.findOne<LegacySession>({
          model: "firstPartyLegacySession",
          where: [{ field: "id", value: reservation.id }],
        });
        if (
          !current ||
          current.status !== "processing" ||
          current.revision !== reservation.revision ||
          current.operationId !== reservation.operationId ||
          current.expiresAt <= new Date()
        )
          throw invalid();
      },
    );
  } catch (error) {
    if (isAPIError(error) && error.statusCode === 429) {
      outcome = { kind: "rejected" };
      retryAfter = new Headers(error.headers).get("retry-after") ?? undefined;
    }
    // An error may follow delivery. Never repeat it automatically, and require
    // the same bound recipient if the user explicitly requests a budgeted resend.
  }
  const session = await finishLegacyStep(ctx, options, reservation, {
    step: "email_verification",
    email,
  });
  return { session, outcome, ...(retryAfter ? { retryAfter } : {}) };
}

/** Consumes a real OTP through Better Auth's complete authentication pipeline.
 * The temporary BA session is destroyed by the shared adapter. Only the bound
 * subject/security snapshot persists for later password/profile setup. */
export async function submitLegacyEmailOTP(
  ctx: GenericEndpointContext,
  options: Options,
  parameters: Record<string, unknown>,
) {
  const { request } = parseLegacyChallenge(parameters, options.policy);
  if (!request.verification_code || request.password || request.new_password)
    throw invalid();
  const reservation = await reserveLegacyStep(
    ctx,
    options,
    parameters,
    ["email_verification"],
    (session) => {
      recipient(session, request.email ?? request.login_hint);
    },
  );
  const email = recipient(reservation, request.email ?? request.login_hint);
  let result: EmailOTPMethodResult;
  try {
    result = await authenticateWithEmailOTP(ctx, {
      email,
      otp: request.verification_code,
    });
  } catch (error) {
    if (isAPIError(error) && error.statusCode === 429)
      await finishLegacyStep(ctx, options, reservation, {
        step: "email_verification",
        email,
      });
    throw error;
  }
  if (result.kind !== "authenticated") {
    await finishLegacyStep(ctx, options, reservation, {
      step: "email_verification",
      email,
    });
    return result;
  }
  const credential = await ctx.context.internalAdapter.findCredentialAccount(
    result.userId,
  );
  const session = await finishLegacyStep(ctx, options, reservation, {
    step: credential?.password ? "email_password" : "profile_password",
    email,
    verified: result,
  });
  return { kind: "verified" as const, session };
}

function recipient(session: LegacySession, requested: string | undefined) {
  const parsed = emailSchema.safeParse(requested ?? session.email);
  if (
    !parsed.success ||
    ((session.step === "email_verification" || session.verifiedUserId) &&
      session.email &&
      parsed.data !== session.email)
  )
    throw invalid();
  return parsed.data;
}
function invalid() {
  return new APIError("BAD_REQUEST", { error: "invalid_grant" });
}
