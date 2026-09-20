import type { Spec as Recovery } from "../NativeAndroidVaultRecovery.ts";
import { FirstPartyClientError, vaultError } from "./errors.ts";

const tokenPattern = /^[A-Za-z0-9_-]{43}$/;

/** Destruction is global to this app's Android vault, across SDK namespaces.
 * No automatic fallback, key deletion, session migration or remote revocation. */
export function createAndroidStorageRecovery(native: Recovery) {
  return {
    async prepareRecovery() {
      let value: Awaited<ReturnType<Recovery["prepare"]>>;
      try {
        value = await native.prepare();
      } catch (error) {
        throw vaultError(error);
      }
      if (value === null) return null;
      if (
        !value ||
        typeof value.token !== "string" ||
        !tokenPattern.test(value.token) ||
        typeof value.inProgress !== "boolean"
      )
        throw new FirstPartyClientError("vault_storage_failed");
      return {
        confirmationToken: value.token,
        scope: "all-local-native-accounts" as const,
        kind: value.inProgress
          ? ("recovery-in-progress" as const)
          : ("vault-key-lost" as const),
      };
    },
    async recover(input: {
      confirmationToken: string;
      discardAllLocalAccounts: true;
    }) {
      if (
        !input ||
        input.discardAllLocalAccounts !== true ||
        typeof input.confirmationToken !== "string" ||
        !tokenPattern.test(input.confirmationToken)
      )
        throw new FirstPartyClientError("invalid_request");
      let alreadyCompleted: boolean;
      try {
        alreadyCompleted = await native.recover(input.confirmationToken);
      } catch (error) {
        throw vaultError(error);
      }
      if (typeof alreadyCompleted !== "boolean")
        throw new FirstPartyClientError("vault_storage_failed");
      return {
        kind: "fresh-login-required" as const,
        scope: "all-local-native-accounts" as const,
        signingKeys: "retained" as const,
        remoteRevocation: "unconfirmed" as const,
        alreadyCompleted,
      };
    },
  };
}
