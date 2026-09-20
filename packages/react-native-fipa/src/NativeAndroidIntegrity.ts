import type { TurboModule } from "react-native";
import { TurboModuleRegistry } from "react-native";

/** Internal Android key/standard-integrity bridge. Never exports a private key. */
export interface Spec extends TurboModule {
  inspectKey(alias: string): Promise<string | null>;
  /** Must reject an occupied alias, including software keys. No replacement. */
  createKey(
    alias: string,
    attestationChallenge: string,
    securityLevel: string,
  ): Promise<string>;
  certificateChain(
    alias: string,
    expectedThumbprint: string,
  ): Promise<Array<string>>;
  removeKey(alias: string, expectedThumbprint: string): Promise<void>;
  signDpop(
    alias: string,
    expectedThumbprint: string,
    url: string,
    method: string,
    accessToken: string | null,
    nonce: string | null,
  ): Promise<string>;
  sha256Utf8(value: string): Promise<string>;
  /** Native implementation owns warm-up/single-flight and bounded deadlines. */
  standardIntegrity(
    cloudProjectNumber: string,
    requestHash: string,
  ): Promise<string>;
}

export default TurboModuleRegistry.get<Spec>(
  "DeviceAttestationAndroidIntegrity",
);
