export type FirstPartyErrorCode =
  | "cancelled"
  | "operation_failed"
  | "app_attest_unavailable"
  | "simulator_unavailable"
  | "key_unavailable"
  | "key_locked"
  | "key_invalid_input"
  | "invalid_configuration"
  | "invalid_state"
  | "invalid_request"
  | "invalid_response"
  | "account_limit_reached"
  | "unsupported_platform"
  | "native_unavailable"
  | "request_failed"
  | "reauthentication_required"
  | "unsupported_step"
  | "registration_recovery_required"
  | "browser_unavailable"
  | "browser_busy"
  | "browser_failed"
  | "vault_invalid_input"
  | "vault_busy"
  | "vault_lost_lease"
  | "vault_corrupt"
  | "vault_locked"
  | "vault_unavailable"
  | "vault_key_lost"
  | "vault_recovery_pending"
  | "vault_recovery_changed"
  | "vault_storage_failed"
  | "vault_policy_mismatch";

/** No original exception, response, capability, or native message is retained. */
export class FirstPartyClientError extends Error {
  override readonly name = "FirstPartyClientError";
  constructor(
    readonly code: FirstPartyErrorCode,
    readonly cleanup?: "complete" | "not-owned" | "uncertain",
    readonly remoteCleanup?: "confirmed" | "unconfirmed",
  ) {
    super(
      code === "app_attest_unavailable"
        ? "App Attest is unavailable on this runtime. For iOS Simulator, explicitly configure the development simulator provider on both client and server."
        : code === "simulator_unavailable"
          ? "The development simulator provider requires an iOS Simulator runtime."
          : code === "key_unavailable"
            ? "Native signing keys are unavailable. On iOS Simulator, explicitly select the development simulator provider on both client and server."
            : code === "invalid_configuration"
              ? "Check the provider, environment and transport configuration. Simulator mode requires development; local HTTP requires allowInsecureLoopback."
              : "The authentication operation could not be completed.",
    );
  }
}

const nativeCodes = new Set<FirstPartyErrorCode>([
  "vault_invalid_input",
  "vault_busy",
  "vault_lost_lease",
  "vault_corrupt",
  "vault_locked",
  "vault_unavailable",
  "vault_key_lost",
  "vault_recovery_pending",
  "vault_recovery_changed",
  "vault_storage_failed",
  "vault_policy_mismatch",
]);

export function vaultError(error: unknown): FirstPartyClientError {
  const code =
    error !== null && typeof error === "object" && "code" in error
      ? error.code
      : undefined;
  return new FirstPartyClientError(
    typeof code === "string" && nativeCodes.has(code as FirstPartyErrorCode)
      ? (code as FirstPartyErrorCode)
      : "vault_storage_failed",
  );
}
