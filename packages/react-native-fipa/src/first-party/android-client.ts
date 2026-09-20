import type { Spec as Recovery } from "../NativeAndroidVaultRecovery.ts";
import { createAndroidStorageRecovery } from "./android-storage-recovery.ts";
import type { Spec as Integrity } from "../NativeAndroidIntegrity.ts";
import type { Spec as Transport } from "../NativeFirstPartyTransport.ts";
import type { SessionVaultNative } from "./session-coordinator.ts";
import { createAndroidKeyPorts } from "./android-keys.ts";
import {
  createNativeLifecycle,
  type NativeFirstPartyConfiguration,
} from "./native-lifecycle.ts";

export type AndroidFirstPartyConfiguration = Omit<
  NativeFirstPartyConfiguration,
  "environment"
> & {
  environment: "production";
  android: {
    cloudProjectNumber: string;
    securityLevel: "tee" | "strongbox";
  };
};

/** Android composition through installed native modules. Hardware and release
 * acceptance must still be established on the signed application. */
export function createAndroidFirstPartyClient(
  configuration: AndroidFirstPartyConfiguration,
  native: {
    integrity: Integrity;
    transport: Transport;
    vault: SessionVaultNative;
    recovery: Recovery;
  },
) {
  const config = {
    ...configuration,
    provider: "android-hardware",
    storageNamespace:
      configuration.storageNamespace ?? "device-attestation.first-party.v1",
    accessibility: "when-unlocked" as const,
  };
  const lifecycle = createNativeLifecycle(config, native, ({ aliases, send }) =>
    createAndroidKeyPorts(
      {
        ...config,
        cloudProjectNumber: configuration.android?.cloudProjectNumber,
        securityLevel: configuration.android?.securityLevel,
        aliases,
      },
      { integrity: native.integrity, send },
    ),
  );
  return {
    ...lifecycle.client,
    storage: createAndroidStorageRecovery(native.recovery),
  };
}
