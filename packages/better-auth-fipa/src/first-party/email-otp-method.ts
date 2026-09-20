import type { GenericEndpointContext } from "@better-auth/core";
import { APIError, dispatchAuthEndpoint, isAPIError } from "better-auth/api";
import { z } from "zod";
import {
  authenticateWithMethod,
  methodRateLimited,
  removeTemporarySessions,
  type AuthenticationMethodResult,
} from "./authentication-method.js";

export type EmailOTPMethodResult = AuthenticationMethodResult<"otp">;
export type EmailOTPDelivery = (input: {
  email: string;
  otp: string;
}) => Promise<void>;

/** Internal adapter. The coordinator must first admit and reserve the step and
 * enforce delivery budgets. By default use the installed email-otp sender.
 * Explicit routed delivery uses its supported server-only creation endpoint;
 * the OTP exists only in the trusted callback argument, never in a response or
 * our persisted continuation. Upstream OTP storage policy still applies.
 * A request acknowledgment inherits the host's background-delivery policy and
 * does not assert that a message reached the recipient.
 */
export async function sendEmailOTP(
  ctx: GenericEndpointContext,
  input: { email: string; delivery?: EmailOTPDelivery },
): Promise<{ kind: "requested" } | { kind: "rejected" }> {
  const parsed = email.safeParse(input.email);
  if (!parsed.success) return { kind: "rejected" };
  const endpoint = input.delivery
    ? configuredEndpoint(ctx, "createVerificationOTP", undefined)
    : configuredEndpoint(
        ctx,
        "sendVerificationOTP",
        "/email-otp/send-verification-otp",
      );
  const headers = new Headers(ctx.headers);
  for (const name of ["cookie", "authorization", "dpop"]) headers.delete(name);
  headers.set("content-type", "application/json");
  const body = { email: parsed.data, type: "sign-in" };
  // A host hook can create sessions even on a delivery endpoint. None may be
  // retained by this non-authenticating operation, including on failure.
  const original = ctx.context.internalAdapter;
  const created = new Set<string>();
  const send = async (): Promise<
    { kind: "requested" } | { kind: "rejected" }
  > => {
    try {
      const response = await dispatchAuthEndpoint(endpoint, {
        context: {
          ...ctx.context,
          session: null,
          newSession: null,
          internalAdapter: {
            ...original,
            createSession: async (...args) => {
              const session = await original.createSession(...args);
              if (session) created.add(session.token);
              return session;
            },
          },
        },
        method: "POST",
        headers,
        body,
        ...(endpoint.path
          ? {
              request: new Request(`${ctx.context.baseURL}${endpoint.path}`, {
                method: "POST",
                headers,
                body: JSON.stringify(body),
              }),
            }
          : {}),
        asResponse: !input.delivery,
        returnHeaders: Boolean(input.delivery),
      });
      if (input.delivery) {
        // Keep the server-only API's string result intact. HTTP serialization
        // would lose leading zeroes if a numeric OTP were parsed as JSON.
        const created = z
          .object({ response: z.string().min(1).max(128) })
          .safeParse(response);
        if (!created.success) throw unavailable();
        await input.delivery({
          email: parsed.data,
          otp: created.data.response,
        });
        return { kind: "requested" };
      }
      if (!(response instanceof Response)) throw unavailable();
      if (response.status === 429) throw methodRateLimited(response.headers);
      if (response.status >= 400 && response.status < 500)
        return { kind: "rejected" };
      if (!response.ok) throw unavailable();
      const value: unknown = await response.json();
      if (!z.object({ success: z.literal(true) }).safeParse(value).success)
        throw unavailable();
      return { kind: "requested" };
    } catch (error) {
      if (isAPIError(error)) {
        if (error.statusCode === 429)
          throw methodRateLimited(new Headers(error.headers));
        if (error.statusCode >= 400 && error.statusCode < 500)
          return { kind: "rejected" };
      }
      throw unavailable();
    }
  };
  const result = await send().then(
    (value) => ({ ok: true as const, value }),
    (error: unknown) => ({ ok: false as const, error }),
  );
  await removeTemporarySessions(ctx, created);
  if (!result.ok) throw result.error;
  return result.value;
}

/** Executes the consuming sign-in endpoint, never checkVerificationOTP (which
 * only checks an OTP and is not a completed authentication). Temporary bearer
 * sessions and cookies are removed before returning an authenticated subject.
 */
export async function authenticateWithEmailOTP(
  ctx: GenericEndpointContext,
  input: { email: string; otp: string },
): Promise<EmailOTPMethodResult> {
  const parsed = z
    .object({ email, otp: z.string().min(1).max(128) })
    .safeParse(input);
  if (!parsed.success) return { kind: "rejected" };
  return authenticateWithMethod(ctx, {
    endpoint: configuredEndpoint(ctx, "signInEmailOTP", "/sign-in/email-otp"),
    body: parsed.data,
    method: "otp",
    verifiedEmail: parsed.data.email,
  });
}

const email = z.string().trim().toLowerCase().pipe(z.email().max(320));

function configuredEndpoint(
  ctx: GenericEndpointContext,
  name: string,
  path: string | undefined,
) {
  const plugins =
    ctx.context.options.plugins?.filter(
      (plugin) => plugin.id === "email-otp",
    ) ?? [];
  const endpoint =
    plugins.length === 1 ? plugins[0]?.endpoints?.[name] : undefined;
  if (
    !endpoint ||
    endpoint.path !== path ||
    (path === undefined && endpoint.options?.metadata?.SERVER_ONLY !== true)
  )
    throw unavailable();
  return endpoint;
}
function unavailable() {
  return new APIError("INTERNAL_SERVER_ERROR", { error: "server_error" });
}
