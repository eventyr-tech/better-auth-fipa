import { APIError } from "better-auth/api";

import {
  DeviceAttestationError,
  deviceAttestationErrorMessage,
} from "./errors.js";
import type { DeviceAttestationOptions } from "./types.js";

export type DiagnosticOperation =
  "challenge" | "verify" | "register" | "assert" | "grant";

export async function withPublicError<T>(
  options: DeviceAttestationOptions,
  context: () => {
    provider: string;
    operation: DiagnosticOperation;
  },
  action: () => Promise<T>,
): Promise<T> {
  try {
    return await action();
  } catch (error) {
    const { provider, operation } = context();
    reportDiagnostic(options, error, provider, operation);
    throw toPublicApiError(error);
  }
}

export function reportDiagnostic(
  options: DeviceAttestationOptions,
  error: unknown,
  provider: string,
  operation: DiagnosticOperation,
): void {
  try {
    const report = options.diagnostics?.report;
    if (!report) {
      return;
    }
    const failure = normalizeFailure(error);
    void Promise.resolve(
      report({
        provider,
        operation,
        stage: failure.stage,
        reason: failure.reason,
        retryable: failure.retryable,
        ...(failure.measurements === undefined
          ? {}
          : { measurements: failure.measurements }),
      }),
    ).catch(() => undefined);
  } catch {
    // Diagnostic delivery must not replace the original authentication result.
  }
}

export function toPublicApiError(error: unknown): APIError {
  const failure = normalizeFailure(error);
  const status = failure.retryable ? "SERVICE_UNAVAILABLE" : "FORBIDDEN";
  return new APIError(status, {
    code: failure.code,
    message: deviceAttestationErrorMessage(failure.code),
  });
}

function normalizeFailure(error: unknown): DeviceAttestationError {
  return error instanceof DeviceAttestationError
    ? error
    : new DeviceAttestationError({
        code: "DEVICE_ATTESTATION_RETRY",
        stage: "unexpected",
        reason: "unexpected_failure",
        retryable: true,
      });
}
