import { defineErrorCodes } from "@better-auth/core/utils/error-codes";

const DEVICE_ATTESTATION_ERROR_MESSAGES = {
  DEVICE_ATTESTATION_INVALID_REQUEST: "The attestation request is invalid.",
  DEVICE_ATTESTATION_CHALLENGE_EXPIRED:
    "The attestation challenge is absent, expired, or already used.",
  DEVICE_ATTESTATION_CREDENTIAL_REQUIRED:
    "An active attestation credential is required.",
  DEVICE_ATTESTATION_REJECTED: "The attestation evidence was rejected.",
  DEVICE_ATTESTATION_GRANT_REQUIRED:
    "A valid device-attestation grant is required.",
  DEVICE_ATTESTATION_RETRY: "The attestation operation must be retried.",
} as const;

/** Stable generic Better Auth error codes exposed to clients. */
export const DEVICE_ATTESTATION_ERROR_CODES = defineErrorCodes(
  DEVICE_ATTESTATION_ERROR_MESSAGES,
);

/** Client-visible device-attestation error code. */
export type DeviceAttestationPublicErrorCode =
  keyof typeof DEVICE_ATTESTATION_ERROR_MESSAGES;

/** Return the intentionally generic client message for a public error code. */
export function deviceAttestationErrorMessage(
  code: DeviceAttestationPublicErrorCode,
): string {
  return DEVICE_ATTESTATION_ERROR_MESSAGES[code];
}

/** Safe server-side stage at which verification or state handling failed. */
export type DeviceAttestationFailureStage =
  | "request"
  | "challenge"
  | "cbor"
  | "authenticator-data"
  | "certificate-chain"
  | "nonce"
  | "app-identity"
  | "environment"
  | "platform-policy"
  | "distribution-metadata"
  | "signature"
  | "counter"
  | "credential-binding"
  | "grant-binding"
  | "storage"
  | "unexpected";

/**
 * Bounded structural measurements permitted in diagnostics.
 *
 * These fields describe sizes and flags only; they never contain evidence,
 * identifiers, keys, proofs, credentials, or request bodies.
 */
export interface DeviceAttestationDiagnosticMeasurements {
  /** Encoded evidence length when rejection happens before decoding. */
  encodedEvidenceCharacters?: number;
  /** Decoded provider evidence size. */
  evidenceBytes?: number;
  /** Authenticator-data size. */
  authenticatorDataBytes?: number;
  /** Authenticator flags byte represented as a number. */
  flags?: number;
  /** Encoded extension size. */
  extensionBytes?: number;
}

/** Redacted server-side rejection event supplied to the host reporter. */
export interface DeviceAttestationDiagnosticEvent {
  /** Provider ID, or `unknown` before a stored challenge is recovered. */
  provider: string;
  /** Plugin operation that observed the failure. */
  operation: "challenge" | "verify" | "register" | "assert" | "grant";
  /** Stable verification or state-machine stage. */
  stage: DeviceAttestationFailureStage;
  /** Stable, non-sensitive reason intended for server diagnosis. */
  reason: string;
  /** Whether a new attempt may succeed without changing client state. */
  retryable: boolean;
  /** Optional bounded structural measurements. */
  measurements?: DeviceAttestationDiagnosticMeasurements;
}

/**
 * Internal typed rejection that separates generic client errors from safe
 * server diagnostics.
 *
 * Provider implementations may throw this class. The Better Auth plugin maps
 * it to a generic `APIError` and reports only its redacted diagnostic fields.
 */
export class DeviceAttestationError extends Error {
  /** Generic client-visible Better Auth code. */
  readonly code: DeviceAttestationPublicErrorCode;
  /** Safe server diagnostic stage. */
  readonly stage: DeviceAttestationFailureStage;
  /** Safe server diagnostic reason. */
  readonly reason: string;
  /** Whether the plugin maps the failure to a retryable response. */
  readonly retryable: boolean;
  /** Optional bounded structural measurements. */
  readonly measurements: DeviceAttestationDiagnosticMeasurements | undefined;

  /** Create a typed device-attestation rejection. */
  constructor(input: {
    code: DeviceAttestationPublicErrorCode;
    stage: DeviceAttestationFailureStage;
    reason: string;
    retryable?: boolean;
    measurements?: DeviceAttestationDiagnosticMeasurements;
  }) {
    super(deviceAttestationErrorMessage(input.code));
    this.name = "DeviceAttestationError";
    this.code = input.code;
    this.stage = input.stage;
    this.reason = input.reason;
    this.retryable = input.retryable ?? false;
    this.measurements = input.measurements;
  }
}

/** Create a non-retryable evidence rejection with the generic public code. */
export function rejection(
  stage: DeviceAttestationFailureStage,
  reason: string,
  measurements?: DeviceAttestationDiagnosticMeasurements,
): DeviceAttestationError {
  return new DeviceAttestationError({
    code: "DEVICE_ATTESTATION_REJECTED",
    stage,
    reason,
    ...(measurements === undefined ? {} : { measurements }),
  });
}
