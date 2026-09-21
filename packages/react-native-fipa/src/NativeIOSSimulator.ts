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

  removeKey(
    storagePrefix: string,
    credentialScope: string,
    expectedKeyId: string,
  ): Promise<void>;
  prepareDpop(alias: string): Promise<string>;
  inspectDpop(alias: string): Promise<string>;
  removeDpop(alias: string, expectedThumbprint: string): Promise<void>;
  signDpop(
    alias: string,
    expectedThumbprint: string,
    url: string,
    method: string,
    accessToken: string | null,
    nonce: string | null,
  ): Promise<string>;
}

export default TurboModuleRegistry.get<Spec>("DeviceAttestationIOSSimulator");
