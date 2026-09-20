import type { Spec as AppAttest } from "../NativeDeviceAttestation.ts";
import type { Spec as Transport } from "../NativeFirstPartyTransport.ts";
import type { SessionVaultNative } from "./session-coordinator.ts";
import type { FirstPartyClientConfiguration } from "./client.ts";
import { createIOSKeyPorts } from "./ios-keys.ts";
import {
  createNativeLifecycle,
  type NativeFirstPartyConfiguration,
} from "./native-lifecycle.ts";
import {
  readRetainedIOSKeys,
  type RetainedIOSKeyReference,
} from "./ios-retained-keys.ts";

const keyIdStoragePrefix = "DeviceAttestation.FirstParty.AppAttest.v1.";

/** Complete iOS composition. Native modules are injected only at this internal
 * seam for testing, never exposed as consumer storage/crypto overrides. */
export function createIOSFirstPartyClient(
  configuration: NativeFirstPartyConfiguration,
  native: {
    appAttest: AppAttest;
    transport: Transport;
    vault: SessionVaultNative;
  },
) {
  const config: FirstPartyClientConfiguration = {
    ...configuration,
    provider: "app-attest",
    storageNamespace:
      configuration.storageNamespace ?? "device-attestation.first-party.v1",
    accessibility: "when-unlocked",
  };
  const { client, catalog } = createNativeLifecycle(
    config,
    native,
    ({ aliases, send }) =>
      createIOSKeyPorts(
        { ...config, keyIdStoragePrefix, aliases },
        {
          appAttest: native.appAttest,
          dpop: native.transport,
          send,
        },
      ),
    { keyIdStoragePrefix },
  );
  return {
    ...client,
    accounts: {
      ...client.accounts,
      importIOSKeys: async (reference: RetainedIOSKeyReference) =>
        catalog.importRetained(
          await readRetainedIOSKeys(reference, {
            appAttest: native.appAttest,
            dpop: native.transport,
          }),
        ),
      resumeImport: () => catalog.resumeImport(),
    },
  };
}
