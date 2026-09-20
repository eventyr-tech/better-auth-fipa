const publicCodes = new Set([
  "DEVICE_ATTESTATION_INVALID_REQUEST",
  "DEVICE_ATTESTATION_CHALLENGE_EXPIRED",
  "DEVICE_ATTESTATION_CREDENTIAL_REQUIRED",
  "DEVICE_ATTESTATION_REJECTED",
  "DEVICE_ATTESTATION_GRANT_REQUIRED",
  "DEVICE_ATTESTATION_RETRY",
]);

/** A generic error which never includes native errors, server bodies, or evidence. */
export class DeviceAttestationClientError extends Error {
  override readonly name = "DeviceAttestationClientError";
  constructor(
    readonly code: string,
    readonly status?: number,
    readonly retryAfterSeconds?: number,
  ) {
    super("This app instance could not be verified.");
  }
}

export function serverError(response: Response, payload: unknown) {
  const candidate = isRecord(payload) ? payload.code : undefined;
  const code =
    typeof candidate === "string" && publicCodes.has(candidate)
      ? candidate
      : response.status === 429
        ? "DEVICE_ATTESTATION_RATE_LIMITED"
        : "DEVICE_ATTESTATION_REQUEST_FAILED";
  const retry =
    response.headers.get("Retry-After") ??
    response.headers.get("X-Retry-After");
  let retryAfterSeconds: number | undefined;
  if (retry !== null) {
    const numeric = Number(retry);
    const seconds = /^\d+(?:\.\d+)?$/u.test(retry.trim())
      ? numeric
      : (Date.parse(retry) - Date.now()) / 1000;
    if (Number.isFinite(seconds))
      retryAfterSeconds = Math.max(0, Math.ceil(seconds));
  }
  return new DeviceAttestationClientError(
    code,
    response.status,
    retryAfterSeconds,
  );
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
