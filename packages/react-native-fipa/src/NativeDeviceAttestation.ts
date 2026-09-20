import type { TurboModule } from "react-native";
import { TurboModuleRegistry } from "react-native";

export interface Spec extends TurboModule {
  getKey(
    storagePrefix: string,
    credentialScope: string,
  ): Promise<string | null>;
  getOrCreateKey(
    storagePrefix: string,
    credentialScope: string,
  ): Promise<{ created: boolean; keyId: string }>;
  generateEvidence(
    keyId: string,
    clientData: string,
    operation: string,
  ): Promise<string>;
  resetKey(storagePrefix: string, credentialScope: string): Promise<void>;
  removeKey(
    storagePrefix: string,
    credentialScope: string,
    expectedKeyId: string,
  ): Promise<void>;
}

export default TurboModuleRegistry.get<Spec>("DeviceAttestationAppAttest");
