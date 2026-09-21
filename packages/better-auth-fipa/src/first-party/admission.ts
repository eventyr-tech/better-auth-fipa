import { developmentPolicyAllowed } from "../development.js";
import type { GenericEndpointContext } from "@better-auth/core";
import { createDpopReplayStore } from "@better-auth/core/oauth2";
import { APIError } from "better-auth/api";
import { randomBytes } from "node:crypto";
import { z } from "zod";
import {
  CREDENTIAL_MODEL,
  advanceCounter,
  normalizeCredentialIntegers,
  requireUsableCredential,
} from "../credential-store.js";
import {
  decodeBase64Strict,
  decodeBase64UrlStrict,
} from "../encoding/base64.js";
import {
  credentialLookupKey,
  equalBytes,
  hmacSha256,
  randomToken,
  sha256,
} from "../protocol/crypto.js";
import type {
  DeviceAttestationProvider,
  StoredAttestationCredential,
} from "../types.js";
import {
  hashNativeAdmissionBinding,
  nativeAdmissionBindingSchema,
  normalizeNativeAdmissionBinding,
  type NativeAdmissionBinding,
} from "./admission-binding.js";
import { verifyFirstPartyDpop } from "./dpop.js";
import {
  readNativeProviderCredential,
  type LifecycleProviderCredential,
} from "./provider-credential.js";
import {
  isAndroidHardwareProvider,
  type AndroidHardwareProvider,
} from "../android/provider.js";
import { withFirstPartyTransaction } from "./transaction.js";

export interface NativeApplicationPolicy {
  clientId: string;
  provider: DeviceAttestationProvider | AndroidHardwareProvider;
  applicationId: string;
  environment: "development" | "production";
  scopes: readonly string[];
  resources: readonly string[];
}
const challengeStateSchema = z.strictObject({
  version: z.literal(1),
  binding: nativeAdmissionBindingSchema,
  credentialId: z.string(),
  keyLookupHash: z.string(),
  clientDataHash: z.string(),
});
const receiptSchema = z.strictObject({
  version: z.literal(1),
  purpose: z.literal("first-party-admission"),
  binding: nativeAdmissionBindingSchema,
  bindingHash: z.string(),
  credentialId: z.string(),
  credentialBindingVersion: z.number().int().nonnegative(),
  verifiedAt: z.iso.datetime(),
  expiresAt: z.iso.datetime().optional(),
  evidence: z.array(z.record(z.string(), z.unknown())).min(1).max(4).optional(),
});
export type NativeAdmissionReceipt = z.infer<typeof receiptSchema>;

/** Called by the new preparation endpoint. Registration keeps using the legacy core. */
export async function createNativeAdmissionChallenge(
  ctx: GenericEndpointContext,
  policy: NativeApplicationPolicy,
  input: { binding: NativeAdmissionBinding; keyId: string },
) {
  if (isAndroidHardwareProvider(policy.provider)) throw rejected();
  const binding = requireNativeApplicationPolicy(ctx, policy, input.binding);
  const keyId = policy.provider.decodeKeyId(input.keyId);
  const keyLookupHash = credentialLookupKey({
    provider: policy.provider.id,
    applicationId: policy.applicationId,
    keyId,
  });
  const credential =
    await ctx.context.adapter.findOne<StoredAttestationCredential>({
      model: CREDENTIAL_MODEL,
      where: [{ field: "lookupKey", value: keyLookupHash }],
    });
  requireUsableCredential(credential);
  if (credential.environment !== policy.environment) throw rejected();
  // The server nonce names this challenge. Both the transaction binding and
  // provider key reference are part of the bytes signed by the platform.
  const clientData = Buffer.from(
    JSON.stringify([
      "better-auth-device-attestation/first-party-admission-challenge/v1",
      randomBytes(32).toString("base64url"),
      keyLookupHash,
      hashNativeAdmissionBinding(binding).toString("base64url"),
    ]),
    "utf8",
  );
  const challengeToken = randomToken();
  const expiresAt = new Date(Date.now() + 120_000);
  await ctx.context.internalAdapter.createVerificationValue({
    identifier: identifier(ctx, "challenge", challengeToken),
    expiresAt,
    value: JSON.stringify({
      version: 1,
      binding,
      credentialId: credential.id,
      keyLookupHash,
      clientDataHash: sha256(clientData).toString("base64url"),
    } satisfies z.infer<typeof challengeStateSchema>),
  });
  return {
    challengeToken,
    clientData: clientData.toString("base64url"),
    expiresAt,
  };
}

/** Platform work occurs outside a database transaction; the counter update is CAS. */
export async function verifyNativeAdmission(
  ctx: GenericEndpointContext,
  policy: NativeApplicationPolicy,
  input: { challengeToken: string; keyId: string; evidence: string },
) {
  if (isAndroidHardwareProvider(policy.provider)) throw rejected();
  const stored = await ctx.context.internalAdapter.consumeVerificationValue(
    identifier(ctx, "challenge", input.challengeToken),
  );
  if (!stored) throw rejected();
  const state = challengeStateSchema.parse(JSON.parse(stored.value) as unknown);
  const binding = requireNativeApplicationPolicy(ctx, policy, state.binding);
  const keyId = policy.provider.decodeKeyId(input.keyId);
  const lookup = credentialLookupKey({
    provider: policy.provider.id,
    applicationId: policy.applicationId,
    keyId,
  });
  if (lookup !== state.keyLookupHash) throw rejected();
  const credential =
    await ctx.context.adapter.findOne<StoredAttestationCredential>({
      model: CREDENTIAL_MODEL,
      where: [{ field: "id", value: state.credentialId }],
    });
  requireUsableCredential(credential);
  if (
    credential.lookupKey !== lookup ||
    credential.environment !== policy.environment
  )
    throw rejected();
  const result = await policy.provider.verifyAssertion({
    credential: normalizeCredentialIntegers(credential),
    keyId,
    clientDataHash: Buffer.from(state.clientDataHash, "base64url"),
    evidence: decodeBase64Strict(input.evidence, {
      label: "evidence",
      maxBytes: policy.provider.maxEvidenceBytes,
    }),
  });
  const updated = await advanceCounter(
    ctx.context,
    normalizeCredentialIntegers(credential),
    result,
  );
  // Legacy grants allow the final assertion of an exhausted key. A new profile
  // admission requires a credential that remains active after verification.
  requireUsableCredential(updated);
  return issueNativeAdmissionReceipt(ctx, binding, updated);
}

/** Internal: called only after platform evidence and required possession checks. */
export async function issueNativeAdmissionReceipt(
  ctx: GenericEndpointContext,
  binding: NativeAdmissionBinding,
  credential: LifecycleProviderCredential,
  verified?: { evidence: Record<string, unknown>[]; expiresAt: Date },
) {
  const now = new Date();
  const expiresAt = new Date(
    Math.min(
      now.getTime() + 120_000,
      verified?.expiresAt.getTime() ?? Infinity,
    ),
  );
  if (!Number.isSafeInteger(expiresAt.getTime()) || expiresAt <= now)
    throw rejected();
  const receipt: NativeAdmissionReceipt = {
    version: 1,
    purpose: "first-party-admission",
    binding,
    bindingHash: hashNativeAdmissionBinding(binding).toString("base64url"),
    credentialId: credential.id,
    credentialBindingVersion: credential.bindingVersion,
    verifiedAt: now.toISOString(),
    ...(verified
      ? { evidence: verified.evidence, expiresAt: expiresAt.toISOString() }
      : {}),
  };
  const grantToken = randomToken();
  await ctx.context.internalAdapter.createVerificationValue({
    identifier: identifier(ctx, "grant", grantToken),
    value: JSON.stringify(receipt),
    expiresAt,
  });
  return { grantToken, expiresAt };
}

/**
 * Validate proof before entering a transaction, then consume admission together
 * with the continuation record. The callback must perform database work only.
 */
export async function consumeNativeAdmission<T>(
  ctx: GenericEndpointContext,
  policy: NativeApplicationPolicy,
  input: {
    grantToken: string;
    binding: NativeAdmissionBinding;
    headers: Headers;
    challengeEndpointUrl: string;
  },
  accept: (
    transactionContext: GenericEndpointContext,
    receipt: NativeAdmissionReceipt,
    credential: LifecycleProviderCredential,
  ) => Promise<T>,
): Promise<T> {
  const binding = requireNativeApplicationPolicy(ctx, policy, input.binding);
  const bindingHash = hashNativeAdmissionBinding(binding);
  await verifyFirstPartyDpop({
    headers: input.headers,
    endpointUrl: input.challengeEndpointUrl,
    method: "POST",
    expectedJkt: binding.dpopJkt,
    replayStore: createDpopReplayStore(ctx.context.internalAdapter),
  });
  return withFirstPartyTransaction(ctx, async (transactionContext) => {
    const stored =
      await transactionContext.context.internalAdapter.consumeVerificationValue(
        identifier(transactionContext, "grant", input.grantToken),
      );
    if (!stored) throw rejected();
    const receipt = receiptSchema.parse(JSON.parse(stored.value) as unknown);
    if (
      (receipt.expiresAt !== undefined &&
        new Date(receipt.expiresAt) <= new Date()) ||
      !developmentPolicyAllowed(policy.provider, policy.environment) ||
      (isAndroidHardwareProvider(policy.provider) &&
        (!receipt.expiresAt || !receipt.evidence)) ||
      !equalBytes(bindingHash, Buffer.from(receipt.bindingHash, "base64url")) ||
      !equalBytes(bindingHash, hashNativeAdmissionBinding(receipt.binding))
    )
      throw rejected();
    const credential = await readNativeProviderCredential(transactionContext, {
      provider: policy.provider.id,
      id: receipt.credentialId,
      clientId: binding.clientId,
      dpopJkt: binding.dpopJkt,
    });
    requireUsableCredential(credential);
    if (
      credential.provider !== policy.provider.id ||
      credential.applicationId !== policy.applicationId ||
      credential.environment !== policy.environment ||
      credential.bindingVersion !== receipt.credentialBindingVersion
    )
      throw rejected();
    return accept(transactionContext, receipt, credential);
  });
}

export function requireNativeApplicationPolicy(
  ctx: GenericEndpointContext,
  policy: NativeApplicationPolicy,
  input: NativeAdmissionBinding,
): NativeAdmissionBinding {
  const binding = normalizeNativeAdmissionBinding(input);
  if (
    !developmentPolicyAllowed(policy.provider, policy.environment) ||
    (isAndroidHardwareProvider(policy.provider) &&
      (policy.applicationId !== policy.provider.applicationId ||
        policy.environment !== "production")) ||
    binding.issuer !== ctx.context.baseURL ||
    binding.clientId !== policy.clientId ||
    binding.provider !== policy.provider.id ||
    binding.applicationId !== policy.applicationId ||
    binding.environment !== policy.environment ||
    binding.scopes.some((scope) => !policy.scopes.includes(scope)) ||
    binding.resources.some((resource) => !policy.resources.includes(resource))
  )
    throw rejected();
  return binding;
}
function identifier(
  ctx: GenericEndpointContext,
  purpose: "challenge" | "grant",
  token: string,
): string {
  decodeBase64UrlStrict(token, {
    label: "admission_token",
    exactBytes: 32,
    maxBytes: 32,
  });
  return `first-party:admission:${purpose}:${hmacSha256(ctx.context.secret, token)}`;
}
function rejected(): APIError {
  return new APIError("BAD_REQUEST", {
    error: "invalid_request",
    error_description: "The application admission could not be verified.",
  });
}
