import {
  isolatedAuthHeaders,
  isolatedAuthContext,
  captureSessionCreation,
} from "../auth-isolation.js";
import { randomBytes } from "node:crypto";
import type { GenericEndpointContext } from "@better-auth/core";
import { runWithEndpointContext } from "@better-auth/core/context";
import {
  APIError,
  dispatchAuthEndpoint,
  setPassword,
  updateUser,
} from "better-auth/api";
import { serializeSignedCookie } from "better-call";
import { removeTemporarySessions } from "../authentication-method.js";
import { authenticateWithPassword } from "../password-method.js";
import { requireUserSecurity } from "../user-security.js";
import type { LegacySession } from "./session.js";

export interface LegacyProfileInput {
  displayName: string;
  password: string;
}

/** Internal only. The caller holds the admitted credential locks and composes
 * this with terminal authorization in the SAME database transaction. The OTP
 * subject comes from the reserved server record, never from the submitted body.
 */
export async function completeLegacyProfile(
  ctx: GenericEndpointContext,
  session: LegacySession,
  input: LegacyProfileInput,
  pendingSessions: Set<string>,
) {
  const userId = session.verifiedUserId;
  if (!userId || !session.email || !session.userSecurityHash) throw invalid();
  await requireUserSecurity(ctx, userId, session.userSecurityHash);
  const original = ctx.context.internalAdapter;
  const user = await original.findUserById(userId);
  const account = await original.findCredentialAccount(userId);
  if (
    !user ||
    !user.emailVerified ||
    user.email.toLowerCase() !== session.email ||
    (user as { twoFactorEnabled?: boolean }).twoFactorEnabled === true ||
    account?.password
  )
    throw invalid();

  const headers = isolatedAuthHeaders(ctx.headers);
  let profileUpdated = false;
  const expiresAt = new Date(
    Math.min(session.expiresAt.getTime(), Date.now() + 60_000),
  );
  const context: GenericEndpointContext["context"] & {
    responseHeaders: Headers;
  } = {
    ...isolatedAuthContext(ctx.context),
    responseHeaders: new Headers(),
    internalAdapter: captureSessionCreation(
      {
        ...original,
        updateUser: async <T extends Record<string, unknown>>(
          ...[id, data]: Parameters<typeof original.updateUser>
        ) => {
          if (id !== userId) throw invalid();
          const updated = await original.updateUser<T>(id, data);
          if (updated && Object.hasOwn(data, "name")) profileUpdated = true;
          return updated;
        },
        createSession: async (
          ...args: Parameters<typeof original.createSession>
        ) => {
          if (args[0] !== userId) throw invalid();
          // These are temporary sessions for this verified subject only. Choose
          // and track every token BEFORE BA writes SQL/cache, including the
          // password method and hooks, so a partial creation failure is cleanable.
          const token = randomBytes(32).toString("base64url");
          pendingSessions.add(token);
          const created = await original.createSession(
            userId,
            args[1],
            {
              ...args[2],
              token,
              userId,
              createdAt: new Date(),
              updatedAt: new Date(),
              expiresAt,
            },
            true,
            args[4],
          );
          if (created) pendingSessions.add(created.token);
          if (
            !created ||
            created.token !== token ||
            created.userId !== userId ||
            created.expiresAt > expiresAt ||
            created.expiresAt <= new Date()
          )
            throw invalid();
          return created;
        },
      },
      (token) => pendingSessions.add(token),
    ),
  };
  try {
    const temporary = await runWithEndpointContext({ headers, context }, () =>
      context.internalAdapter.createSession(userId, true),
    );
    const cookie = await serializeSignedCookie(
      ctx.context.authCookies.sessionToken.name,
      temporary.token,
      ctx.context.secret,
    );
    headers.set("cookie", cookie.split(";", 1)[0]!);
    const invoke = async (
      endpoint: Parameters<typeof dispatchAuthEndpoint>[0],
      body: Record<string, unknown>,
    ) => {
      const result = await dispatchAuthEndpoint(endpoint, {
        context: {
          ...isolatedAuthContext(context),
          responseHeaders: new Headers(),
        },
        headers: new Headers(headers),
        method: "POST",
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
        asResponse: true,
      });
      if (!(result instanceof Response) || !result.ok) {
        const status = result instanceof Response ? result.status : 500;
        throw new APIError(
          status === 429
            ? "TOO_MANY_REQUESTS"
            : status === 403
              ? "FORBIDDEN"
              : status < 500
                ? "BAD_REQUEST"
                : "INTERNAL_SERVER_ERROR",
          { error: status >= 500 ? "server_error" : "invalid_grant" },
          result instanceof Response && result.headers.has("retry-after")
            ? { "retry-after": result.headers.get("retry-after")! }
            : undefined,
        );
      }
    };
    await invoke(updateUser(), { name: input.displayName });
    if (!profileUpdated) throw invalid();
    // A name change cannot bless an unrelated security change in a host hook.
    await requireUserSecurity(ctx, userId, session.userSecurityHash);
    await invoke(setPassword, { newPassword: input.password });
    // Verify the stored password through the normal complete authentication
    // pipeline. A host hook returning success without a write, revocation or
    // an uncompleted MFA step cannot manufacture a terminal factor.
    const result = await authenticateWithPassword(
      { ...ctx, context },
      {
        email: session.email,
        password: input.password,
      },
    );
    if (result.kind !== "authenticated" || result.userId !== userId)
      throw invalid();
    return result;
  } finally {
    await cleanupProfileSessions(ctx, pendingSessions, false);
  }
}

/** Called before and after the transaction. SQL rollback cannot remove cached
 * sessions, and an after-commit hook may mirror a session already deleted inside
 * the transaction. Retain tokens until the outer cleanup has finished. */
export async function cleanupProfileSessions(
  ctx: GenericEndpointContext,
  pendingSessions: Set<string>,
  forget = true,
) {
  await removeTemporarySessions(ctx, pendingSessions);
  if (forget) pendingSessions.clear();
}

function invalid() {
  return new APIError("BAD_REQUEST", { error: "invalid_grant" });
}
