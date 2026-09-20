import type { TurboModule } from "react-native";
import { TurboModuleRegistry } from "react-native";

/** Android-only recovery for loss of the shared vault encryption key. */
export interface Spec extends TurboModule {
  prepare(): Promise<{ token: string; inProgress: boolean } | null>;
  /** Requires the exact prepared ticket. True means already completed. */
  recover(token: string): Promise<boolean>;
}

export default TurboModuleRegistry.get<Spec>(
  "DeviceAttestationAndroidVaultRecovery",
);
