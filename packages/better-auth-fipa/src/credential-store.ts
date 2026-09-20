import type { BetterAuthPlugin } from "better-auth";

import { DeviceAttestationError, rejection } from "./errors.js";
import type {
  AssertionVerificationResult,
  DeviceAttestationProvider,
  RegistrationVerificationResult,
  StoredAttestationCredential,
} from "./types.js";

export const CREDENTIAL_MODEL = "deviceAttestationCredential";
const UINT32_MAX = 0xffff_ffff;

export type RuntimeContext = Parameters<
  NonNullable<BetterAuthPlugin["init"]>
>[0];

export async function registerCredential(
  context: RuntimeContext,
  provider: DeviceAttestationProvider,
  lookupKey: string,
  expectedApplicationId: string,
  result: RegistrationVerificationResult,
  unboundCredentialTtlSeconds: number,
): Promise<StoredAttestationCredential> {
  if (result.applicationId !== expectedApplicationId || result.counter !== 0) {
    throw rejection("app-identity", "invalid_registration_result");
  }
  const existing = await context.adapter.findOne<StoredAttestationCredential>({
    model: CREDENTIAL_MODEL,
    where: [{ field: "lookupKey", value: lookupKey }],
  });
  if (existing) {
    throw new DeviceAttestationError({
      code: "DEVICE_ATTESTATION_CREDENTIAL_REQUIRED",
      stage: "credential-binding",
      reason: "credential_already_registered",
    });
  }

  return context.adapter.create<StoredAttestationCredential>({
    model: CREDENTIAL_MODEL,
    data: {
      lookupKey,
      provider: provider.id,
      applicationId: result.applicationId,
      environment: result.environment,
      publicKey: result.publicKey,
      counter: 0,
      userId: null,
      externallyBound: false,
      bindingVersion: 0,
      status: "active",
      extensionsPresent: result.extensionsPresent,
      unboundExpiresAt: new Date(
        Date.now() + unboundCredentialTtlSeconds * 1000,
      ),
      ...(result.validationCategory === undefined
        ? {}
        : { validationCategory: result.validationCategory }),
      ...(result.bundleVersion === undefined
        ? {}
        : { bundleVersion: result.bundleVersion }),
    },
  });
}

export async function advanceCounter(
  context: RuntimeContext,
  credential: StoredAttestationCredential,
  result: AssertionVerificationResult,
): Promise<StoredAttestationCredential> {
  if (
    !Number.isSafeInteger(result.counter) ||
    result.counter <= credential.counter ||
    result.counter > UINT32_MAX
  ) {
    throw rejection("counter", "invalid_assertion_counter");
  }

  const exhausted = result.counter === UINT32_MAX;
  const updated =
    await context.adapter.incrementOne<StoredAttestationCredential>({
      model: CREDENTIAL_MODEL,
      where: [
        { field: "id", value: credential.id },
        { field: "counter", value: credential.counter },
        { field: "status", value: "active" },
      ],
      increment: { counter: result.counter - credential.counter },
      set: {
        lastUsedAt: new Date(),
        extensionsPresent: result.extensionsPresent,
        validationCategory: result.validationCategory ?? null,
        bundleVersion: result.bundleVersion ?? null,
        ...(exhausted
          ? {
              status: "revoked",
              revokedAt: new Date(),
              revocationReason: "counter_exhausted",
            }
          : {}),
      },
    });
  if (!updated) {
    throw rejection("counter", "assertion_counter_race");
  }
  return updated;
}

export async function retireCredentialsForUser(
  context: RuntimeContext,
  userId: string,
): Promise<void> {
  await context.adapter.updateMany({
    model: CREDENTIAL_MODEL,
    where: [
      { field: "userId", value: userId },
      { field: "status", value: "active" },
    ],
    update: {
      status: "revoked",
      revokedAt: new Date(),
      revocationReason: "user_deleted",
      publicKey: null,
      validationCategory: null,
      bundleVersion: null,
      unboundExpiresAt: null,
    },
  });
}

export async function maintainUnboundCredentials(
  context: RuntimeContext,
  provider: string,
  applicationId: string,
  retentionSeconds: number,
): Promise<void> {
  const now = new Date();
  await context.adapter.updateMany({
    model: CREDENTIAL_MODEL,
    where: [
      { field: "provider", value: provider },
      { field: "applicationId", value: applicationId },
      { field: "status", value: "active" },
      { field: "userId", value: null },
      { field: "externallyBound", value: false },
      { field: "unboundExpiresAt", value: now, operator: "lt" },
    ],
    update: {
      status: "expired",
      publicKey: null,
      validationCategory: null,
      bundleVersion: null,
      updatedAt: now,
    },
  });
  await context.adapter.deleteMany({
    model: CREDENTIAL_MODEL,
    where: [
      { field: "provider", value: provider },
      { field: "applicationId", value: applicationId },
      { field: "status", value: "expired" },
      { field: "userId", value: null },
      { field: "externallyBound", value: false },
      {
        field: "updatedAt",
        value: new Date(now.getTime() - retentionSeconds * 1000),
        operator: "lt",
      },
    ],
  });
}

export async function enforceUnboundCredentialQuota(
  context: RuntimeContext,
  provider: string,
  applicationId: string,
  maximum: number | undefined,
): Promise<void> {
  if (maximum === undefined) {
    return;
  }
  const count = await context.adapter.count({
    model: CREDENTIAL_MODEL,
    where: [
      { field: "provider", value: provider },
      { field: "applicationId", value: applicationId },
      { field: "status", value: "active" },
      { field: "userId", value: null },
      { field: "externallyBound", value: false },
    ],
  });
  if (count >= maximum) {
    throw new DeviceAttestationError({
      code: "DEVICE_ATTESTATION_RETRY",
      stage: "storage",
      reason: "unbound_credential_quota_reached",
      retryable: true,
    });
  }
}

export function requireUsableCredential<
  T extends Pick<
    StoredAttestationCredential,
    "status" | "publicKey" | "userId" | "externallyBound" | "unboundExpiresAt"
  >,
>(credential: T | null): asserts credential is T {
  if (!credential || credential.status !== "active" || !credential.publicKey) {
    throw new DeviceAttestationError({
      code: "DEVICE_ATTESTATION_CREDENTIAL_REQUIRED",
      stage: "credential-binding",
      reason: "credential_not_active",
    });
  }
  if (
    !credential.userId &&
    !credential.externallyBound &&
    (!credential.unboundExpiresAt ||
      credential.unboundExpiresAt.getTime() <= Date.now())
  ) {
    throw new DeviceAttestationError({
      code: "DEVICE_ATTESTATION_CREDENTIAL_REQUIRED",
      stage: "credential-binding",
      reason: "unbound_credential_expired",
    });
  }
}

/** Normalize bigint-backed UInt32 fields returned as decimal strings. */
export function normalizeCredentialIntegers(
  credential: StoredAttestationCredential,
): StoredAttestationCredential {
  const counter = normalizeUInt32(credential.counter, "invalid_stored_counter");
  const validationCategory =
    credential.validationCategory === undefined ||
    credential.validationCategory === null
      ? credential.validationCategory
      : normalizeUInt32(
          credential.validationCategory,
          "invalid_stored_validation_category",
        );
  if (validationCategory === undefined) {
    return counter === credential.counter
      ? credential
      : { ...credential, counter };
  }
  return { ...credential, counter, validationCategory };
}

function normalizeUInt32(value: unknown, reason: string): number {
  const normalized =
    typeof value === "number"
      ? value
      : typeof value === "string" && /^(0|[1-9][0-9]*)$/u.test(value)
        ? Number(value)
        : Number.NaN;
  if (
    !Number.isSafeInteger(normalized) ||
    normalized < 0 ||
    normalized > UINT32_MAX
  ) {
    throw rejection("storage", reason);
  }
  return normalized;
}
