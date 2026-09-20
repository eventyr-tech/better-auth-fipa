import { DPoP } from "react-native-dpop";
import NativeDeviceAttestation from "./NativeDeviceAttestation.ts";
import { createAppAttestClient } from "./client.ts";
import { createDpopClient } from "./dpop.ts";
import { DeviceAttestationClientError } from "./errors.ts";
import type { AppAttestClientOptions } from "./types.ts";

export { DeviceAttestationClientError } from "./errors.ts";
export type * from "./types.ts";

/** Native App Attest orchestration. Android attestation is not implemented yet. */
export function createReactNativeDeviceAttestation(
  options: AppAttestClientOptions,
) {
  if (!NativeDeviceAttestation)
    throw new DeviceAttestationClientError("DEVICE_ATTESTATION_UNAVAILABLE");
  return createAppAttestClient(options, NativeDeviceAttestation);
}

/** Hardware-backed DPoP operations using react-native-dpop; private keys stay native. */
export function createNativeDpopClient(keyAlias: string) {
  return createDpopClient(keyAlias, DPoP);
}
