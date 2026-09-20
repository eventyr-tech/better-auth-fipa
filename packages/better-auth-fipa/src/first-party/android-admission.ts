import { DeviceAttestationError } from "../errors.js";
import {
  maintainAndroidUnboundCredentials,
  retireAndroidProviderCredential,
} from "./android-maintenance.js";
import type { GenericEndpointContext } from "@better-auth/core";
import { createDpopReplayStore } from "@better-auth/core/oauth2";
import { APIError } from "better-auth/api";
import { z } from "zod";
import {
  isAndroidHardwareProvider,
  type AndroidHardwareProvider,
} from "../android/provider.js";
import { requireUsableCredential } from "../credential-store.js";
import {
  decodeBase64Strict,
  decodeBase64UrlStrict,
} from "../encoding/base64.js";
import {
  credentialLookupKey,
  hmacSha256,
  randomToken,
  sha256,
} from "../protocol/crypto.js";
import {
  hashNativeAdmissionBinding,
  nativeAdmissionBindingSchema,
  type NativeAdmissionBinding,
} from "./admission-binding.js";
import {
  issueNativeAdmissionReceipt,
  requireNativeApplicationPolicy,
  type NativeApplicationPolicy,
} from "./admission.js";
import {
  ANDROID_KEY_MODEL,
  ANDROID_PROVIDER,
  type LifecycleProviderCredential,
} from "./provider-credential.js";
import { verifyFirstPartyDpop } from "./dpop.js";
import { withFirstPartyTransaction } from "./transaction.js";

const digest = z.string().regex(/^[A-Za-z0-9_-]{43}$/);
const encodedChain = z.array(z.string().min(1).max(21_848)).min(4).max(5);
const initialState = z.strictObject({
  version: z.literal(1),
  clientId: z.string(),
  applicationId: z.string(),
  issuer: z.string(),
  challenge: digest,
  issuedAt: z.iso.datetime(),
  expiresAt: z.iso.datetime(),
});
const admissionState = z.strictObject({
  version: z.literal(1),
  binding: nativeAdmissionBindingSchema,
  credentialId: z.string(),
  credentialVersion: z.number().int().nonnegative(),
  requestHash: digest,
  issuedAt: z.iso.datetime(),
  expiresAt: z.iso.datetime(),
});
export const androidRegistrationSchema = z.strictObject({
  binding: nativeAdmissionBindingSchema,
  keyChallengeToken: digest,
  certificateChain: encodedChain,
  integrityToken: z.string().min(1).max(32_768),
});
export interface StoredAndroidKey extends LifecycleProviderCredential {
  clientId: string;
  dpopJkt: string;
  attestationChallenge: string;
  certificateChain: string[];
  keyVerifiedAt: Date;
  keyEvidence: Record<string, unknown>;
  createdAt: Date;
  updatedAt: Date;
}

/** Wire commitment for initial registration: the key's nonce was issued before
 * its thumbprint existed. This joins it to the final admission binding. */
export function androidRegistrationRequestHash(
  binding: NativeAdmissionBinding,
  challenge: string,
) {
  decodeDigest(challenge);
  return sha256(
    Buffer.from(
      JSON.stringify([
        "better-auth-device-attestation/android-registration/v1",
        challenge,
        hashNativeAdmissionBinding(binding).toString("base64url"),
      ]),
    ),
  ).toString("base64url");
}

export async function createAndroidKeyChallenge(
  ctx: GenericEndpointContext,
  policy: NativeApplicationPolicy,
) {
  const provider = androidProvider(policy);
  await maintainAndroidUnboundCredentials(ctx, {
    clientId: policy.clientId,
    applicationId: policy.applicationId,
    retentionSeconds: provider.expiredCredentialRetentionSeconds,
  });
  const issuedAt = new Date();
  const expiresAt = new Date(issuedAt.getTime() + 120_000);
  const challenge = randomToken();
  const keyChallengeToken = randomToken();
  await ctx.context.internalAdapter.createVerificationValue({
    identifier: identifier(ctx, "key", keyChallengeToken),
    expiresAt,
    value: JSON.stringify({
      version: 1,
      issuer: ctx.context.baseURL,
      clientId: policy.clientId,
      applicationId: policy.applicationId,
      challenge,
      issuedAt: issuedAt.toISOString(),
      expiresAt: expiresAt.toISOString(),
    } satisfies z.infer<typeof initialState>),
  });
  return {
    keyChallengeToken,
    attestationChallenge: challenge,
    issuedAt,
    expiresAt,
  };
}

export async function registerAndroidKey(
  ctx: GenericEndpointContext,
  policy: NativeApplicationPolicy,
  input: z.infer<typeof androidRegistrationSchema>,
  headers: Headers,
) {
  const provider = androidProvider(policy);
  const binding = requireNativeApplicationPolicy(ctx, policy, input.binding);
  await proof(ctx, binding, headers, "/first-party/android/register");
  const stored = await ctx.context.internalAdapter.consumeVerificationValue(
    identifier(ctx, "key", input.keyChallengeToken),
  );
  if (!stored) throw rejected();
  const state = initialState.parse(JSON.parse(stored.value) as unknown);
  if (
    state.clientId !== policy.clientId ||
    state.applicationId !== policy.applicationId ||
    state.issuer !== ctx.context.baseURL
  )
    throw rejected();
  requireWindow(state.issuedAt, state.expiresAt);
  const chain = decodeChain(input.certificateChain);
  const trust = await provider.trust.get();
  const key = provider.verifyKey({
    certificateChain: chain,
    expectedChallenge: decodeDigest(state.challenge),
    expectedDpopJkt: binding.dpopJkt,
    trust,
  });
  const play = await provider.verifyPlay(input.integrityToken, {
    requestHash: androidRegistrationRequestHash(binding, state.challenge),
    challengeIssuedAt: new Date(state.issuedAt),
    challengeExpiresAt: new Date(state.expiresAt),
  });
  const expiry = new Date(
    Math.min(trust.expiresAt.getTime(), play.expiresAt.getTime()),
  );
  return withFirstPartyTransaction(ctx, async (tx) => {
    requireWindow(state.issuedAt, expiry.toISOString());
    // Unique lookup prevents duplicate registration, including retired keys.
    // A lost response resumes through normal admission with this same JKT.
    const now = new Date();
    const credential = await tx.context.adapter.create<StoredAndroidKey>({
      model: ANDROID_KEY_MODEL,
      data: {
        lookupKey: lookup(policy, binding.dpopJkt),
        provider: ANDROID_PROVIDER,
        clientId: policy.clientId,
        applicationId: policy.applicationId,
        environment: "production",
        dpopJkt: key.dpopJkt,
        publicKey: key.publicKeySpki,
        attestationChallenge: state.challenge,
        certificateChain: input.certificateChain,
        keyVerifiedAt: key.verifiedAt,
        keyEvidence: { ...key, verifiedAt: key.verifiedAt.toISOString() },
        userId: null,
        externallyBound: false,
        bindingVersion: 0,
        status: "active",
        unboundExpiresAt: new Date(
          now.getTime() + provider.unboundCredentialTtlSeconds * 1000,
        ),
        createdAt: now,
        updatedAt: now,
      },
    });
    const receipt = await issueNativeAdmissionReceipt(tx, binding, credential, {
      expiresAt: expiry,
      evidence: [
        keyAssurance(key, key.verifiedAt),
        {
          ...play,
          verifiedAt: play.verifiedAt.toISOString(),
          expiresAt: play.expiresAt.toISOString(),
        },
      ],
    });
    return { ...receipt, credentialId: credential.id, keyId: key.dpopJkt };
  });
}

export async function createAndroidAdmissionChallenge(
  ctx: GenericEndpointContext,
  policy: NativeApplicationPolicy,
  input: { binding: NativeAdmissionBinding; keyId: string },
  headers: Headers,
) {
  androidProvider(policy);
  const binding = requireNativeApplicationPolicy(ctx, policy, input.binding);
  if (input.keyId !== binding.dpopJkt) throw rejected();
  await proof(ctx, binding, headers, "/first-party/attestation/challenge");
  const credential = await ctx.context.adapter.findOne<StoredAndroidKey>({
    model: ANDROID_KEY_MODEL,
    where: [{ field: "lookupKey", value: lookup(policy, input.keyId) }],
  });
  usable(credential, policy, binding);
  const issuedAt = new Date();
  const expiresAt = new Date(issuedAt.getTime() + 120_000);
  const clientData = Buffer.from(
    JSON.stringify([
      "better-auth-device-attestation/android-admission/v1",
      randomToken(),
      credential.lookupKey,
      hashNativeAdmissionBinding(binding).toString("base64url"),
    ]),
  );
  const challengeToken = randomToken();
  const requestHash = sha256(clientData).toString("base64url");
  await ctx.context.internalAdapter.createVerificationValue({
    identifier: identifier(ctx, "admission", challengeToken),
    expiresAt,
    value: JSON.stringify({
      version: 1,
      binding,
      credentialId: credential.id,
      credentialVersion: credential.bindingVersion,
      requestHash,
      issuedAt: issuedAt.toISOString(),
      expiresAt: expiresAt.toISOString(),
    } satisfies z.infer<typeof admissionState>),
  });
  return {
    challengeToken,
    clientData: clientData.toString("base64url"),
    requestHash,
    issuedAt,
    expiresAt,
  };
}

/** Android evidence is the opaque standard token, not a synthetic App Attest assertion. */
export async function verifyAndroidAdmission(
  ctx: GenericEndpointContext,
  policy: NativeApplicationPolicy,
  input: { challengeToken: string; keyId: string; evidence: string },
  headers: Headers,
) {
  const provider = androidProvider(policy);
  decodeDigest(input.keyId);
  const stateId = identifier(ctx, "admission", input.challengeToken);
  const preview =
    await ctx.context.internalAdapter.findVerificationValue(stateId);
  if (!preview) throw rejected();
  const state = admissionState.parse(JSON.parse(preview.value) as unknown);
  const binding = requireNativeApplicationPolicy(ctx, policy, state.binding);
  if (binding.dpopJkt !== input.keyId) throw rejected();
  requireWindow(state.issuedAt, state.expiresAt);
  await proof(ctx, binding, headers, "/first-party/attestation/verify");
  const stored =
    await ctx.context.internalAdapter.consumeVerificationValue(stateId);
  if (!stored || stored.value !== preview.value) throw rejected();
  const credential = await ctx.context.adapter.findOne<StoredAndroidKey>({
    model: ANDROID_KEY_MODEL,
    where: [{ field: "id", value: state.credentialId }],
  });
  usable(credential, policy, binding);
  if (credential.bindingVersion !== state.credentialVersion) throw rejected();
  const trust = await provider.trust.get();
  // Revalidate certificate signatures/claims under current policy and current
  // roots/revocation, at the original SERVER verification time for RKP validity.
  // Expiry of a provisioning CA does not expire an already enrolled signing key.
  if (!(credential.keyVerifiedAt instanceof Date)) throw rejected();
  let key: ReturnType<AndroidHardwareProvider["verifyKey"]>;
  try {
    key = provider.verifyKey({
      certificateChain: decodeChain(credential.certificateChain),
      expectedChallenge: decodeDigest(credential.attestationChallenge),
      expectedDpopJkt: binding.dpopJkt,
      trust,
      verifiedAtCreation: credential.keyVerifiedAt,
    });
  } catch (error) {
    if (
      error instanceof DeviceAttestationError &&
      [
        "android_certificate_revoked",
        "untrusted_android_certificate_root",
      ].includes(error.reason)
    )
      await retireAndroidProviderCredential(ctx, credential.id);
    throw error;
  }
  if (key.publicKeySpki !== credential.publicKey) throw rejected();
  const play = await provider.verifyPlay(input.evidence, {
    requestHash: state.requestHash,
    challengeIssuedAt: new Date(state.issuedAt),
    challengeExpiresAt: new Date(state.expiresAt),
  });
  const expiry = new Date(
    Math.min(trust.expiresAt.getTime(), play.expiresAt.getTime()),
  );
  return withFirstPartyTransaction(ctx, async (tx) => {
    requireWindow(state.issuedAt, expiry.toISOString());
    const locked = await tx.context.adapter.incrementOne<StoredAndroidKey>({
      model: ANDROID_KEY_MODEL,
      where: [
        { field: "id", value: credential.id },
        { field: "status", value: "active" },
        { field: "bindingVersion", value: state.credentialVersion },
        { field: "dpopJkt", value: binding.dpopJkt },
        { field: "clientId", value: binding.clientId },
      ],
      increment: {},
      set: { lastUsedAt: new Date() },
    });
    usable(locked, policy, binding);
    return issueNativeAdmissionReceipt(tx, binding, locked, {
      expiresAt: expiry,
      evidence: [
        keyAssurance(key, credential.keyVerifiedAt),
        {
          ...play,
          verifiedAt: play.verifiedAt.toISOString(),
          expiresAt: play.expiresAt.toISOString(),
        },
      ],
    });
  });
}

function keyAssurance(
  key: ReturnType<AndroidHardwareProvider["verifyKey"]>,
  enrolledAt: Date,
) {
  return {
    provider: key.provider,
    kind: key.kind,
    properties: key.properties,
    dpopJkt: key.dpopJkt,
    verifiedAt: key.verifiedAt.toISOString(),
    enrolledAt: enrolledAt.toISOString(),
    trustVersion: key.trustVersion,
    provisioning: key.provisioning,
  };
}

function androidProvider(policy: NativeApplicationPolicy) {
  if (
    !isAndroidHardwareProvider(policy.provider) ||
    policy.applicationId !== policy.provider.applicationId ||
    policy.environment !== "production"
  )
    throw rejected();
  return policy.provider;
}
function lookup(policy: NativeApplicationPolicy, jkt: string) {
  return credentialLookupKey({
    provider: ANDROID_PROVIDER,
    applicationId: policy.applicationId,
    keyId: decodeDigest(jkt),
  });
}
function decodeDigest(value: string) {
  return decodeBase64UrlStrict(value, {
    exactBytes: 32,
    maxBytes: 32,
    label: "android_digest",
  });
}
function decodeChain(input: string[]) {
  return encodedChain.parse(input).map((cert) =>
    decodeBase64Strict(cert, {
      maxBytes: 16_384,
      label: "android_certificate",
    }),
  );
}
function identifier(
  ctx: GenericEndpointContext,
  purpose: "key" | "admission",
  token: string,
) {
  decodeDigest(token);
  return `first-party:android:${purpose}:${hmacSha256(ctx.context.secret, token)}`;
}
function requireWindow(issuedAt: string, expiresAt: string) {
  const now = Date.now();
  if (
    !Number.isSafeInteger(Date.parse(issuedAt)) ||
    !Number.isSafeInteger(Date.parse(expiresAt)) ||
    Date.parse(issuedAt) > now ||
    Date.parse(expiresAt) <= now ||
    Date.parse(expiresAt) - Date.parse(issuedAt) > 120_000
  )
    throw rejected();
}
function proof(
  ctx: GenericEndpointContext,
  binding: { dpopJkt: string },
  headers: Headers,
  path: string,
) {
  return verifyFirstPartyDpop({
    headers,
    method: "POST",
    endpointUrl: `${ctx.context.baseURL}${path}`,
    expectedJkt: binding.dpopJkt,
    replayStore: createDpopReplayStore(ctx.context.internalAdapter),
  });
}
function usable(
  row: StoredAndroidKey | null,
  policy: NativeApplicationPolicy,
  binding: NativeAdmissionBinding,
): asserts row is StoredAndroidKey {
  requireUsableCredential(row);
  if (
    row.provider !== ANDROID_PROVIDER ||
    row.clientId !== binding.clientId ||
    row.dpopJkt !== binding.dpopJkt ||
    row.applicationId !== policy.applicationId ||
    row.environment !== "production" ||
    row.lookupKey !== lookup(policy, binding.dpopJkt)
  )
    throw rejected();
}
function rejected() {
  return new APIError("BAD_REQUEST", {
    error: "invalid_request",
    error_description: "The Android admission could not be verified.",
  });
}
