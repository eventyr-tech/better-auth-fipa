import type { GenericEndpointContext } from "@better-auth/core";
import { APIError, isAPIError } from "better-auth/api";
import { randomBytes } from "node:crypto";
import { z } from "zod";
import { hashOAuthBinding } from "../../protocol/binding.js";
import { CREDENTIAL_MODEL } from "../../credential-store.js";
import type { StoredAttestationCredential } from "../../types.js";
import type {
  AuthorizedAttempt,
  FirstPartyTokenFamily,
} from "../authorization-store.js";
import {
  authenticateWithPassword,
  type PasswordMethodResult,
} from "../password-method.js";
import {
  lockActiveLegacyFamily,
  type NativeTokenOptions,
} from "../token-lifecycle.js";
import { withFirstPartyTransaction } from "../transaction.js";
import { authorizeLegacySession } from "./authorization.js";
import {
  legacyPasswordAcr,
  parseLegacyChallenge,
  type LegacyChallengeRequest,
  type LegacyClientPolicy,
} from "./contract.js";
import {
  handleHash,
  registeredLegacyClient,
  type LegacySession,
} from "./session.js";

/** Explicit completed-login operation, never a fallback from failed admission,
 * DPoP, or normal continuation validation. A ready handle still takes the normal
 * continuation path; every other unknown/terminal state fails closed. */
export async function reauthenticateLegacyPassword(
  ctx: GenericEndpointContext,
  options: NativeTokenOptions,
  policy: LegacyClientPolicy,
  request: LegacyChallengeRequest,
): Promise<{ authorizationCode?: string; email: string } | null> {
  const { binding } = parseLegacyChallenge(request, policy);
  if (
    !request.auth_session ||
    request.intent !== "step_up" ||
    policy.allowPasswordReauthentication !== true
  )
    throw invalid();
  const hash = handleHash(ctx, request.auth_session);
  const original = await ctx.context.adapter.findOne<LegacySession>({
    model: "firstPartyLegacySession",
    where: [{ field: "handleHash", value: hash }],
  });
  if (original?.status === "ready") return null;
  if (
    !original ||
    original.status !== "code-issued" ||
    !original.authorizationId ||
    original.issuer !== ctx.context.baseURL ||
    original.clientId !== policy.clientId ||
    original.expiresAt <= new Date() ||
    original.profile !== "legacy-v1"
  )
    throw invalid();
  if (
    request.device_attestation ||
    request.verification_code ||
    request.new_password ||
    request.display_name ||
    !request.password
  )
    throw invalid();
  const email = z
    .email()
    .max(320)
    .safeParse(
      (request.email ?? request.login_hint ?? "").trim().toLowerCase(),
    );
  if (!email.success) throw invalid();
  // A fresh factor may bind a new PKCE verifier, never a new device/client,
  // redirect, resource or scope. The original stored binding must be intact.
  if (
    original.bindingHash !==
      hashOAuthBinding(original.binding).toString("base64url") ||
    original.bindingHash !==
      hashOAuthBinding({
        ...binding,
        codeChallenge: original.binding.codeChallenge,
      }).toString("base64url")
  )
    throw invalid();
  const settings = {
    policy,
    oauth: options.oauth,
    familyLifetimeSeconds: options.lifetimes.familyLifetimeSeconds,
  };
  await registeredLegacyClient(ctx, settings, binding);
  const authorization = await ctx.context.adapter.findOne<AuthorizedAttempt>({
    model: "firstPartyAuthorization",
    where: [{ field: "id", value: original.authorizationId }],
  });
  if (
    !authorization ||
    authorization.status !== "consumed" ||
    authorization.assurance.profile !== "legacy-v1" ||
    authorization.clientId !== original.clientId ||
    authorization.dpopJkt !== original.binding.dpopJkt ||
    authorization.codeChallenge !== original.binding.codeChallenge
  )
    throw invalid();
  const source = await ctx.context.adapter.findOne<FirstPartyTokenFamily>({
    model: "firstPartyTokenFamily",
    where: [{ field: "authorizationId", value: authorization.id }],
  });
  if (
    !source ||
    source.credentialId !== authorization.credentialId ||
    source.userId !== authorization.userId ||
    source.clientId !== original.clientId ||
    source.dpopJkt !== original.binding.dpopJkt
  )
    throw invalid();
  const checkSource = async (tx: GenericEndpointContext) => {
    if (policy.allowPasswordReauthentication !== true) throw invalid();
    const { family: active, credential: logical } =
      await lockActiveLegacyFamily(tx, options, source.id);
    if (logical.providerCredentialId !== original.credentialId) throw invalid();
    const credential =
      await tx.context.adapter.findOne<StoredAttestationCredential>({
        model: CREDENTIAL_MODEL,
        where: [{ field: "id", value: original.credentialId }],
      });
    if (
      !credential ||
      credential.status !== "active" ||
      credential.userId !== active.userId
    )
      throw invalid();
    const user = await tx.context.internalAdapter.findUserById(active.userId);
    if (!user || user.email.trim().toLowerCase() !== email.data)
      throw invalid();
    return { ...active, providerBindingVersion: credential.bindingVersion };
  };
  const reservation = await withFirstPartyTransaction(ctx, async (tx) => {
    const active = await checkSource(tx);
    const reserved = await tx.context.adapter.incrementOne<LegacySession>({
      model: "firstPartyLegacySession",
      where: [
        { field: "id", value: original.id },
        { field: "status", value: "code-issued" },
        { field: "revision", value: original.revision },
        { field: "authorizationId", value: authorization.id },
        { field: "expiresAt", operator: "gt", value: new Date() },
      ],
      increment: { revision: 1 },
      set: {
        status: "processing",
        operationId: randomBytes(32).toString("base64url"),
        intent: "step_up",
        step: "email_password",
        binding,
        bindingHash: hashOAuthBinding(binding).toString("base64url"),
        requestedAcr: legacyPasswordAcr(request, policy),
        email: email.data,
        verifiedUserId: active.userId,
        userSecurityHash: active.userSecurityHash,
        credentialBindingVersion: active.providerBindingVersion,
        authenticatedAt: null,
        createdAt: new Date(),
      },
    });
    if (!reserved) throw invalid();
    return reserved;
  });
  const restore = () =>
    withFirstPartyTransaction(ctx, async (tx) => {
      await checkSource(tx);
      const restored = await tx.context.adapter.incrementOne({
        model: "firstPartyLegacySession",
        where: [
          { field: "id", value: reservation.id },
          { field: "status", value: "processing" },
          { field: "revision", value: reservation.revision },
          { field: "operationId", value: reservation.operationId },
          { field: "expiresAt", operator: "gt", value: new Date() },
        ],
        increment: { revision: 1 },
        set: {
          status: "code-issued",
          operationId: null,
          binding: original.binding,
          bindingHash: original.bindingHash,
          requestedAcr: original.requestedAcr,
          intent: original.intent,
          step: original.step,
          email: original.email,
          verifiedUserId: original.verifiedUserId,
          userSecurityHash: original.userSecurityHash,
          authenticatedAt: original.authenticatedAt,
          credentialBindingVersion: original.credentialBindingVersion,
          createdAt: original.createdAt,
        },
      });
      if (!restored) throw invalid();
    });
  let factor: PasswordMethodResult;
  try {
    factor = await authenticateWithPassword(ctx, {
      email: email.data,
      password: request.password,
    });
  } catch (error) {
    if (isAPIError(error) && error.statusCode === 429) await restore();
    throw error;
  }
  if (factor.kind !== "authenticated") {
    await restore();
    return { email: email.data };
  }
  if (factor.userId !== source.userId) throw invalid();
  // This creates a new immutable authorization under the reserved revision.
  // It cannot modify the consumed code or relabel the old token family.
  const authorizationCode = await authorizeLegacySession(
    ctx,
    settings,
    reservation,
    factor,
    async (tx) => {
      await checkSource(tx);
    },
  );
  return { authorizationCode, email: email.data };
}

function invalid() {
  return new APIError("BAD_REQUEST", { error: "invalid_grant" });
}
