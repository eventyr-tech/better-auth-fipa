import {
  isolatedAuthHeaders,
  isolatedAuthContext,
  captureSessionCreation,
} from "./auth-isolation.js";
import type { GenericEndpointContext } from "@better-auth/core";
import { APIError, dispatchAuthEndpoint, isAPIError } from "better-auth/api";
import { z } from "zod";
import { userSecurityHash } from "./user-security.js";

export type AuthenticationMethodResult<Method extends "pwd" | "otp"> =
  | {
      kind: "authenticated";
      userId: string;
      userSecurityHash: string;
      authenticatedAt: Date;
      amr: [Method];
    }
  | { kind: "rejected" }
  | { kind: "browser-required" };

/**
 * Run only after admission and step validation. Re-enter Better Auth's complete
 * hook pipeline, then remove every temporary session before accepting a factor.
 * Never return its cookies or bearer token to the native caller.
 */
export async function authenticateWithMethod<Method extends "pwd" | "otp">(
  ctx: GenericEndpointContext,
  input: {
    endpoint: Parameters<typeof dispatchAuthEndpoint>[0];
    body: Record<string, unknown>;
    method: Method;
    verifiedEmail?: string;
  },
): Promise<AuthenticationMethodResult<Method>> {
  const created = new Map<string, string>();
  const original = ctx.context.internalAdapter;
  const headers = isolatedAuthHeaders(ctx.headers);
  const body = input.body;
  const authenticate = async (): Promise<
    AuthenticationMethodResult<Method>
  > => {
    try {
      // Capture password authority before validation/hooks. Ownership promotion
      // or a password/security change while this method runs invalidates it.
      const prior =
        input.method === "pwd" && typeof body.email === "string"
          ? await original.findUserByEmail(body.email.trim().toLowerCase())
          : null;
      const before = prior ? await userSecurityHash(ctx, prior.user.id) : null;
      const result = await dispatchAuthEndpoint(input.endpoint, {
        context: isolatedAuthContext(
          ctx.context,
          captureSessionCreation(original, (token, userId) =>
            created.set(token, userId),
          ),
        ),
        method: "POST",
        headers,
        body,
        request: new Request(`${ctx.context.baseURL}${input.endpoint.path}`, {
          method: "POST",
          headers,
          body: JSON.stringify(body),
        }),
        asResponse: true,
      });
      if (!(result instanceof Response))
        throw new APIError("INTERNAL_SERVER_ERROR", { error: "server_error" });
      if (result.status === 400 || result.status === 401)
        return { kind: "rejected" };
      if (result.status === 429) throw methodRateLimited(result.headers);
      if (result.status >= 500)
        throw new APIError("INTERNAL_SERVER_ERROR", { error: "server_error" });
      if (!result.ok) return { kind: "browser-required" };
      const value: unknown = await result.json();
      const authenticated = z
        .object({
          token: z.string(),
          user: z.object({ id: z.string() }),
          twoFactorRedirect: z.literal(false).optional(),
        })
        .safeParse(value);
      // MFA and other plugin-specific steps cannot be converted into success.
      // A hook returning a subject without a newly created session also fails closed.
      if (
        !authenticated.success ||
        created.get(authenticated.data.token) !== authenticated.data.user.id
      )
        return { kind: "browser-required" };
      const live = await original.findSession(authenticated.data.token);
      if (
        !live ||
        live.user.id !== authenticated.data.user.id ||
        live.session.expiresAt <= new Date() ||
        // Better Auth 1.7.5's two-factor hook does not match email-OTP sign-in.
        // No single-factor adapter can treat that omission as completed MFA.
        (live.user as { twoFactorEnabled?: boolean }).twoFactorEnabled ===
          true ||
        (input.verifiedEmail !== undefined &&
          (!live.user.emailVerified ||
            live.user.email.toLowerCase() !== input.verifiedEmail))
      )
        return { kind: "browser-required" };
      const currentSecurity = await userSecurityHash(ctx, live.user.id);
      if (
        input.method === "pwd" &&
        (prior?.user.id !== live.user.id || before !== currentSecurity)
      )
        return { kind: "browser-required" };
      return {
        kind: "authenticated",
        userId: authenticated.data.user.id,
        userSecurityHash: currentSecurity,
        authenticatedAt: new Date(),
        amr: [input.method],
      };
    } catch (error) {
      if (isAPIError(error)) {
        if (error.statusCode === 400 || error.statusCode === 401)
          return { kind: "rejected" };
        if (error.statusCode === 403) return { kind: "browser-required" };
        if (error.statusCode === 429)
          throw methodRateLimited(new Headers(error.headers));
      }
      throw new APIError("INTERNAL_SERVER_ERROR", { error: "server_error" });
    }
  };
  const outcome = await authenticate().then(
    (value) => ({ ok: true as const, value }),
    (error: unknown) => ({ ok: false as const, error }),
  );
  await removeTemporarySessions(ctx, created.keys());
  if (!outcome.ok) throw outcome.error;
  return outcome.value;
}

/** BA's secondary-storage session index uses read/modify/write updates. Delete
 * serially so cleaning several sessions does not leave stale index entries.
 * Try every known token even after one deletion fails, then fail closed.
 */
export async function removeTemporarySessions(
  ctx: GenericEndpointContext,
  tokens: Iterable<string>,
): Promise<void> {
  let failed = false;
  for (const token of tokens) {
    try {
      await ctx.context.internalAdapter.deleteSession(token);
    } catch {
      failed = true;
    }
  }
  if (failed) {
    throw new APIError("INTERNAL_SERVER_ERROR", {
      error: "server_error",
      error_description: "Temporary authentication session cleanup failed.",
    });
  }
}

export function methodRateLimited(headers: Headers): APIError {
  const outgoing = new Headers();
  const retryAfter = headers.get("retry-after");
  if (retryAfter) outgoing.set("retry-after", retryAfter);
  return new APIError(
    "TOO_MANY_REQUESTS",
    { error: "temporarily_unavailable" },
    outgoing,
  );
}
