import type { GenericEndpointContext } from "@better-auth/core";
import type { OAuthOptions } from "@better-auth/oauth-provider";
import { APIError, isAPIError } from "better-auth/api";
import { z } from "zod";
import { hashOAuthBinding } from "../../protocol/binding.js";
import {
  enrollLogicalCredential,
  issueLegacyAuthorizationCode,
  recordAuthorizedAttempt,
  type LogicalCredential,
} from "../authorization-store.js";
import {
  authenticateWithPassword,
  type PasswordMethodResult,
} from "../password-method.js";
import { withFirstPartyTransaction } from "../transaction.js";
import { requireUserSecurity } from "../user-security.js";
import {
  completeLegacyProfile,
  cleanupProfileSessions,
  type LegacyProfileInput,
} from "./profile.js";
import { parseLegacyChallenge, type LegacyClientPolicy } from "./contract.js";
import {
  lockLegacyProvider,
  requireLegacyAcr,
  registeredLegacyClient,
  reserveLegacyStep,
  finishLegacyStep,
  type LegacySession,
} from "./session.js";

type LegacyAuthorizationOptions = {
  policy: LegacyClientPolicy;
  oauth: OAuthOptions<string[]>;
  familyLifetimeSeconds: number;
};

/** Executes the host's full password hook pipeline after a one-use reservation. */
export async function submitLegacyPassword(
  ctx: GenericEndpointContext,
  options: LegacyAuthorizationOptions,
  parameters: Record<string, unknown>,
) {
  const { request } = parseLegacyChallenge(parameters, options.policy);
  if (!request.password || request.new_password || request.verification_code)
    throw invalidGrant();
  const recipient = (session: LegacySession) => {
    const parsed = z
      .string()
      .trim()
      .toLowerCase()
      .pipe(z.email().max(320))
      .safeParse(request.email ?? session.email);
    if (
      !parsed.success ||
      (session.verifiedUserId && parsed.data !== session.email)
    )
      throw invalidGrant();
    return parsed.data;
  };
  const reservation = await reserveLegacyStep(
    ctx,
    options,
    parameters,
    ["email_password"],
    (session) => {
      recipient(session);
    },
  );
  const email = recipient(reservation);
  let result: PasswordMethodResult;
  try {
    result = await authenticateWithPassword(ctx, {
      email,
      password: request.password,
    });
  } catch (error) {
    // Rate limiting is a definite non-authentication result. Preserve the old
    // handle for retry, but never revive it after expiry or policy revocation.
    if (isAPIError(error) && error.statusCode === 429)
      await finishLegacyStep(ctx, options, reservation, {
        step: "email_password",
        email,
      });
    throw error;
  }
  if (result.kind === "authenticated")
    return {
      kind: "authorized" as const,
      authorizationCode: await authorizeLegacySession(
        ctx,
        options,
        reservation,
        result,
      ),
    };
  await finishLegacyStep(ctx, options, reservation, {
    step: "email_password",
    email,
  });
  return result;
}

/** Internal terminal boundary. The authentication result comes from the shared
 * Better Auth method adapter, never from an HTTP body or a client subject.
 * Code issuance and the terminal session transition commit together. Ownership
 * and the token family remain an atomic claim at proof-bound code redemption.
 */
export async function authorizeLegacySession(
  ctx: GenericEndpointContext,
  options: LegacyAuthorizationOptions,
  reservation: LegacySession,
  authenticated: Extract<PasswordMethodResult, { kind: "authenticated" }>,
  validateAuthority?: (tx: GenericEndpointContext) => Promise<void>,
): Promise<string> {
  return issueLegacySession(
    ctx,
    options,
    reservation,
    {
      kind: "password",
      authenticated,
    },
    validateAuthority,
  );
}

/** Complete the submitted client's OTP -> profile/password -> code transition. */
export async function submitLegacyProfile(
  ctx: GenericEndpointContext,
  options: LegacyAuthorizationOptions,
  parameters: Record<string, unknown>,
) {
  const { request } = parseLegacyChallenge(parameters, options.policy);
  if (
    !request.new_password ||
    !request.display_name?.trim() ||
    request.password ||
    request.verification_code
  )
    throw invalidGrant();
  const reservation = await reserveLegacyStep(
    ctx,
    options,
    parameters,
    ["profile_password"],
    (session) => {
      if (
        !session.verifiedUserId ||
        !session.email ||
        !session.userSecurityHash ||
        !session.authenticatedAt ||
        (request.email !== undefined &&
          request.email.trim().toLowerCase() !== session.email)
      )
        throw invalidGrant();
    },
  );
  const pendingSessions = new Set<string>();
  try {
    const authorizationCode = await issueLegacySession(
      ctx,
      options,
      reservation,
      {
        kind: "profile",
        input: {
          displayName: request.display_name.trim(),
          password: request.new_password,
        },
        pendingSessions,
      },
    );
    return { kind: "authorized" as const, authorizationCode };
  } catch (error) {
    // Resume only a rolled-back method rejection whose original OTP security
    // snapshot still matches. An after-commit error cannot reopen the terminal
    // state or reuse the snapshot from before the password was created.
    if (isAPIError(error) && [400, 403, 429].includes(error.statusCode)) {
      await requireUserSecurity(
        ctx,
        reservation.verifiedUserId!,
        reservation.userSecurityHash!,
      );
      await finishLegacyStep(ctx, options, reservation, {
        step: "profile_password",
      });
      const retryAfter = new Headers(error.headers).get("retry-after");
      throw new APIError(
        error.statusCode === 429
          ? "TOO_MANY_REQUESTS"
          : error.statusCode === 403
            ? "FORBIDDEN"
            : "BAD_REQUEST",
        {
          error:
            error.statusCode === 429
              ? "temporarily_unavailable"
              : "invalid_grant",
        },
        retryAfter && /^\d+$/.test(retryAfter) && Number(retryAfter) <= 3600
          ? { "retry-after": retryAfter }
          : undefined,
      );
    }
    throw new APIError("INTERNAL_SERVER_ERROR", { error: "server_error" });
  } finally {
    await cleanupProfileSessions(ctx, pendingSessions);
  }
}

async function issueLegacySession(
  ctx: GenericEndpointContext,
  options: LegacyAuthorizationOptions,
  reservation: LegacySession,
  submission:
    | {
        kind: "password";
        authenticated: Extract<PasswordMethodResult, { kind: "authenticated" }>;
      }
    | {
        kind: "profile";
        input: LegacyProfileInput;
        pendingSessions: Set<string>;
      },
  validateAuthority?: (tx: GenericEndpointContext) => Promise<void>,
): Promise<string> {
  const lifetime = options.familyLifetimeSeconds;
  if (!Number.isSafeInteger(lifetime) || lifetime < 1 || lifetime > 31536000)
    throw new TypeError(
      "Legacy token families require an explicit bounded lifetime.",
    );
  await registeredLegacyClient(ctx, options, reservation.binding);
  return withFirstPartyTransaction(ctx, async (tx) => {
    // Internal coordinators can require additional retained authority under the
    // same transaction. This callback is not part of consumer configuration.
    await validateAuthority?.(tx);
    const adapter = tx.context.adapter;
    const session = await adapter.findOne<LegacySession>({
      model: "firstPartyLegacySession",
      where: [
        { field: "id", value: reservation.id },
        { field: "status", value: "processing" },
        { field: "revision", value: reservation.revision },
        { field: "operationId", value: reservation.operationId },
      ],
    });
    const now = new Date();
    if (
      !session ||
      !reservation.operationId ||
      session.profile !== "legacy-v1" ||
      session.issuer !== tx.context.baseURL ||
      session.clientId !== options.policy.clientId ||
      session.step !==
        (submission.kind === "profile"
          ? "profile_password"
          : "email_password") ||
      session.expiresAt <= now ||
      session.bindingHash !==
        hashOAuthBinding(session.binding).toString("base64url")
    )
      throw invalidGrant();
    requireLegacyAcr(session, {}, options.policy);
    const factor =
      submission.kind === "password"
        ? submission.authenticated
        : {
            kind: "authenticated" as const,
            userId: session.verifiedUserId,
            authenticatedAt: session.authenticatedAt,
            amr: ["otp"],
          };
    if (
      factor.kind !== "authenticated" ||
      !factor.userId ||
      (session.verifiedUserId && session.verifiedUserId !== factor.userId) ||
      !factor.authenticatedAt ||
      !Number.isFinite(factor.authenticatedAt.getTime()) ||
      factor.authenticatedAt < session.createdAt ||
      factor.authenticatedAt > now ||
      factor.amr.length !== 1 ||
      factor.amr[0] !== (submission.kind === "profile" ? "otp" : "pwd")
    )
      throw invalidGrant();
    // Use the same logical-credential -> provider-key lock order as native
    // redemption and retirement, including when the key was retained on upgrade.
    let logical = await adapter.findOne<LogicalCredential>({
      model: "firstPartyCredential",
      where: [{ field: "providerCredentialId", value: session.credentialId }],
    });
    if (!logical)
      logical = await enrollLogicalCredential(tx, {
        issuer: session.issuer,
        clientId: session.clientId,
        applicationId: options.policy.applicationId,
        environment: options.policy.environment,
        provider: options.policy.provider,
        providerCredentialId: session.credentialId,
        dpopJkt: session.binding.dpopJkt,
      });
    if (
      logical.issuer !== session.issuer ||
      logical.clientId !== session.clientId ||
      logical.applicationId !== options.policy.applicationId ||
      logical.environment !== options.policy.environment ||
      logical.provider !== options.policy.provider ||
      logical.dpopJkt !== session.binding.dpopJkt ||
      (logical.userId && logical.userId !== factor.userId)
    )
      throw invalidGrant();
    const locked = await adapter.incrementOne<LogicalCredential>({
      model: "firstPartyCredential",
      where: [
        { field: "id", value: logical.id },
        { field: "status", value: "active" },
        { field: "version", value: logical.version },
        { field: "revision", value: logical.revision },
      ],
      increment: { revision: 1 },
    });
    if (!locked) throw invalidGrant();
    const provider = await lockLegacyProvider(tx, session, options.policy);
    if (
      (provider.userId && provider.userId !== factor.userId) ||
      !(await tx.context.internalAdapter.findUserById(factor.userId))
    )
      throw invalidGrant();
    const authenticated =
      submission.kind === "password"
        ? submission.authenticated
        : await completeLegacyProfile(
            tx,
            session,
            submission.input,
            submission.pendingSessions,
          );
    // Setup invokes host hooks. Check policy/provider again before its writes
    // and authorization are committed, just as expiry is checked by the CAS.
    if (submission.kind === "profile") {
      await registeredLegacyClient(tx, options, session.binding);
      await lockLegacyProvider(tx, session, options.policy);
    }
    const completed = await adapter.incrementOne<LegacySession>({
      model: "firstPartyLegacySession",
      where: [
        { field: "id", value: session.id },
        { field: "profile", value: "legacy-v1" },
        { field: "status", value: "processing" },
        { field: "revision", value: session.revision },
        { field: "operationId", value: session.operationId },
        { field: "expiresAt", operator: "gt", value: new Date() },
      ],
      increment: { revision: 1 },
      set: {
        status: "code-issued",
        operationId: null,
        email: null,
        verifiedUserId: null,
        userSecurityHash: null,
        authenticatedAt: null,
      },
    });
    if (!completed) throw invalidGrant();
    const authorization = await recordAuthorizedAttempt(tx, {
      attemptId: `legacy-v1:${session.id}:${session.revision}`,
      redirectUri: session.binding.redirectUri,
      credentialId: locked.id,
      credentialVersion: locked.version,
      providerCredentialBindingVersion: session.credentialBindingVersion,
      clientId: session.clientId,
      userId: authenticated.userId,
      userSecurityHash: authenticated.userSecurityHash,
      dpopJkt: session.binding.dpopJkt,
      codeChallenge: session.binding.codeChallenge,
      scopes: session.binding.scope.split(" "),
      resources: session.binding.resources ?? [],
      assurance: {
        profile: "legacy-v1",
        provider: options.policy.provider,
        applicationId: options.policy.applicationId,
        environment: options.policy.environment,
        evidenceKind: "credential-key",
        evidenceVerifiedAt: session.evidenceVerifiedAt.toISOString(),
        challengeProof: false,
        ...(session.requestedAcr ? { acr: session.requestedAcr } : {}),
        amr: submission.kind === "profile" ? ["otp", "pwd"] : authenticated.amr,
      },
      assuranceExpiresAt: session.expiresAt,
      authenticatedAt: factor.authenticatedAt,
      familyExpiresAt: new Date(Date.now() + lifetime * 1000),
      expiresAt: session.expiresAt,
    });
    const linked = await adapter.incrementOne({
      model: "firstPartyLegacySession",
      where: [
        { field: "id", value: session.id },
        { field: "status", value: "code-issued" },
        { field: "revision", value: completed.revision },
      ],
      increment: {},
      set: { authorizationId: authorization.id },
    });
    if (!linked) throw invalidGrant();
    return issueLegacyAuthorizationCode(tx, authorization.id);
  });
}

function invalidGrant() {
  return new APIError("BAD_REQUEST", { error: "invalid_grant" });
}
