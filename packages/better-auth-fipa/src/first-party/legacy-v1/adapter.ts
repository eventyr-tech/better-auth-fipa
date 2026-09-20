import { isAndroidHardwareProvider } from "../../android/provider.js";
import type { GenericEndpointContext } from "@better-auth/core";
import { APIError, dispatchAuthEndpoint, isAPIError } from "better-auth/api";
import { z } from "zod";
import type { NativeTokenOptions } from "../token-lifecycle.js";
import type { LegacyChallengeAdapter } from "../challenge-endpoint.js";
import type { LegacyChallengeRequest, LegacyClientPolicy } from "./contract.js";
import { parseLegacyChallenge } from "./contract.js";
import {
  createLegacySession,
  inspectLegacySession,
  registeredLegacyClient,
  reserveLegacyStep,
  finishLegacyStep,
  type LegacySession,
} from "./session.js";
import { requestLegacyEmailOTP, submitLegacyEmailOTP } from "./email-otp.js";
import { submitLegacyPassword, submitLegacyProfile } from "./authorization.js";
import { reauthenticateLegacyPassword } from "./reauthentication.js";

/** Temporary, explicitly selected protocol support. This does not import a
 * host's pre-existing authorization/token records or confer native assurance. */
export interface LegacyCompatibilityOptions {
  clients: readonly LegacyClientPolicy[];
}

export function createLegacyChallengeAdapter(
  options: NativeTokenOptions,
  compatibility: LegacyCompatibilityOptions,
): LegacyChallengeAdapter {
  const policies = compatibility.clients;
  if (
    !policies.length ||
    new Set(policies.map((policy) => policy.clientId)).size !== policies.length
  )
    throw new TypeError(
      "Legacy compatibility requires explicit, unique client policies.",
    );
  for (const policy of policies) {
    const application = options.applications.find(
      (entry) => entry.clientId === policy.clientId,
    );
    if (
      !application ||
      isAndroidHardwareProvider(application.provider) ||
      application.provider.id !== policy.provider ||
      application.applicationId !== policy.applicationId ||
      application.environment !== policy.environment ||
      !policy.redirectUris.length ||
      !policy.scopes.length ||
      (policy.allowPasswordReauthentication !== undefined &&
        typeof policy.allowPasswordReauthentication !== "boolean") ||
      (policy.passwordAcrValues !== undefined &&
        (!Array.isArray(policy.passwordAcrValues) ||
          policy.passwordAcrValues.length > 16 ||
          new Set(policy.passwordAcrValues).size !==
            policy.passwordAcrValues.length ||
          policy.passwordAcrValues.some(
            (value) =>
              typeof value !== "string" || !/^[\x21-\x7e]{1,256}$/.test(value),
          ))) ||
      policy.scopes.some((scope) => !application.scopes.includes(scope)) ||
      policy.resources.some(
        (resource) => !application.resources.includes(resource),
      ) ||
      !Number.isSafeInteger(policy.sessionLifetimeSeconds) ||
      policy.sessionLifetimeSeconds < 1 ||
      policy.sessionLifetimeSeconds > 1800
    )
      throw new TypeError(
        "Legacy policies must match their native application and have explicit redirect URIs, scopes and a bounded lifetime.",
      );
  }
  return {
    policies,
    async handle(ctx, request, policy) {
      try {
        return await handle(ctx, options, policy, request);
      } catch (error) {
        const status = isAPIError(error) ? error.statusCode : 500;
        const retry = isAPIError(error)
          ? new Headers(error.headers).get("retry-after")
          : null;
        return reply(
          {
            error:
              status === 429
                ? "temporarily_unavailable"
                : status >= 500
                  ? "server_error"
                  : status === 401
                    ? "invalid_app_attest"
                    : "invalid_request",
          },
          status >= 500 ? 500 : status,
          retry && /^\d+$/.test(retry) && Number(retry) <= 3600
            ? retry
            : undefined,
        );
      }
    },
  };
}

async function handle(
  ctx: GenericEndpointContext,
  options: NativeTokenOptions,
  policy: LegacyClientPolicy,
  request: LegacyChallengeRequest,
): Promise<Response> {
  const settings = {
    policy,
    oauth: options.oauth,
    familyLifetimeSeconds: options.lifetimes.familyLifetimeSeconds,
  };
  let handle = request.auth_session;
  let session: LegacySession;
  const initial = !handle;
  if (handle) {
    if (request.device_attestation) throw invalid();
    if (
      request.intent === "step_up" &&
      policy.allowPasswordReauthentication === true
    ) {
      const reauthenticated = await reauthenticateLegacyPassword(
        ctx,
        options,
        policy,
        request,
      );
      if (reauthenticated)
        return reauthenticated.authorizationCode
          ? reply({
              authorization_code: reauthenticated.authorizationCode,
              auth_session: handle,
            })
          : prompt(handle, {
              step: "email_password",
              email: reauthenticated.email,
            });
    }
    session = await inspectLegacySession(ctx, settings, request);
  } else {
    if (
      request.verification_code ||
      request.new_password ||
      request.display_name
    )
      throw invalid();
    const { binding } = parseLegacyChallenge(request, policy);
    await registeredLegacyClient(ctx, settings, binding);
    const grant = await verifyInitialEvidence(ctx, request);
    const created = await createLegacySession(ctx, settings, request, grant);
    handle = created.authSession;
    session = created.session;
  }
  const fields = { ...request, auth_session: handle };
  const email = request.email ?? request.login_hint ?? session.email;
  if (
    session.email &&
    session.step !== "email_password" &&
    email !== null &&
    email.trim().toLowerCase() !== session.email
  )
    throw invalid();
  const send = async () => {
    if (!options.emailOTP) throw invalid();
    const result = await requestLegacyEmailOTP(
      ctx,
      { ...settings, emailOTP: options.emailOTP },
      fields,
    );
    if (result.retryAfter)
      return reply(
        { error: "temporarily_unavailable" },
        429,
        result.retryAfter,
      );
    if (result.outcome.kind !== "requested")
      return reply({ error: "invalid_request" }, 400);
    return prompt(handle, result.session);
  };
  if (session.step === "email_verification") {
    if (request.password || request.new_password || request.display_name)
      throw invalid();
    if (request.verification_code) {
      if (!options.emailOTP) throw invalid();
      const result = await submitLegacyEmailOTP(
        ctx,
        { ...settings, emailOTP: options.emailOTP },
        fields,
      );
      return prompt(
        handle,
        result.kind === "verified" ? result.session : session,
      );
    }
    if ((initial || !session.email) && request.email) return send();
    // The old wire format has no resend operation. Repeated polls never send.
    return prompt(handle, session);
  }
  if (session.step === "profile_password") {
    if (request.password || request.verification_code) throw invalid();
    if (!request.new_password || !request.display_name)
      return prompt(handle, session);
    const result = await submitLegacyProfile(ctx, settings, fields);
    return reply({
      authorization_code: result.authorizationCode,
      auth_session: handle,
    });
  }
  if (
    session.step !== "email_password" ||
    request.verification_code ||
    request.new_password ||
    request.display_name
  )
    throw invalid();
  if (request.intent === "create_account") return send();
  if (
    request.password &&
    email &&
    (!initial ||
      request.intent === "authenticate" ||
      request.intent === "step_up")
  ) {
    const result = await submitLegacyPassword(ctx, settings, {
      ...fields,
      email,
    });
    return result.kind === "authorized"
      ? reply({
          authorization_code: result.authorizationCode,
          auth_session: handle,
        })
      : prompt(handle, { ...session, email: email.trim().toLowerCase() });
  }
  if (email && email.trim().toLowerCase() !== session.email) {
    const normalized = z.email().max(320).safeParse(email.trim().toLowerCase());
    if (!normalized.success || session.verifiedUserId) throw invalid();
    const reserved = await reserveLegacyStep(ctx, settings, fields, [
      "email_password",
    ]);
    session = await finishLegacyStep(ctx, settings, reserved, {
      step: "email_password",
      email: normalized.data,
    });
  }
  return prompt(handle, session);
}

async function verifyInitialEvidence(
  ctx: GenericEndpointContext,
  request: LegacyChallengeRequest,
): Promise<string> {
  const evidence = request.device_attestation;
  if (!evidence)
    throw new APIError("UNAUTHORIZED", { error: "invalid_app_attest" });
  const plugins =
    ctx.context.options.plugins?.filter(
      (plugin) => plugin.id === "device-attestation",
    ) ?? [];
  const endpoint =
    plugins.length === 1
      ? plugins[0]?.endpoints?.verifyDeviceAttestation
      : undefined;
  if (!endpoint || endpoint.path !== "/device-attestation/verify")
    throw new APIError("INTERNAL_SERVER_ERROR", { error: "server_error" });
  const headers = new Headers(ctx.headers);
  for (const name of ["cookie", "authorization", "dpop"]) headers.delete(name);
  headers.set("content-type", "application/json");
  const body = {
    challengeToken: evidence.challenge_token,
    keyId: evidence.key_id,
    evidence: evidence.evidence,
  };
  const result = await dispatchAuthEndpoint(endpoint, {
    context: {
      ...ctx.context,
      session: null,
      newSession: null,
      responseHeaders: new Headers(),
    },
    headers,
    method: "POST",
    body,
    request: new Request(`${ctx.context.baseURL}${endpoint.path}`, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
    }),
    asResponse: true,
  });
  if (!(result instanceof Response) || !result.ok)
    throw new APIError(
      result instanceof Response && result.status === 429
        ? "TOO_MANY_REQUESTS"
        : "UNAUTHORIZED",
      { error: "invalid_app_attest" },
      result instanceof Response ? result.headers : undefined,
    );
  const verified = z
    .object({
      credentialState: z.literal("asserted"),
      grantToken: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
    })
    .safeParse(await result.json());
  if (!verified.success)
    throw new APIError("UNAUTHORIZED", { error: "invalid_app_attest" });
  return verified.data.grantToken;
}
function prompt(
  handle: string,
  session: Pick<LegacySession, "step" | "email">,
) {
  return reply({
    error: "insufficient_authorization",
    auth_session: handle,
    next_step: session.step,
    ...(session.email ? { email: session.email } : {}),
  });
}
function reply(
  body: Record<string, unknown>,
  status = 200,
  retryAfter?: string,
) {
  return Response.json(body, {
    status,
    headers: {
      "cache-control": "no-store",
      ...(retryAfter ? { "retry-after": retryAfter } : {}),
    },
  });
}
function invalid() {
  return new APIError("BAD_REQUEST", { error: "invalid_request" });
}
