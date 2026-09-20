import type { TurboModule } from "react-native";
import { TurboModuleRegistry } from "react-native";

/** Internal first-party vault bridge. Session payloads never contain private keys. */
export interface Spec extends TurboModule {
  acquire(
    storageNamespace: string,
    slotId: string,
    accessibility: string,
    leaseMilliseconds: number,
    preserveSession: boolean,
  ): Promise<{
    leaseId: string;
    generation: number;
    identityJSON: string | null;
    sessionJSON: string | null;
    recoveryRequired: boolean;
  }>;
  commit(
    storageNamespace: string,
    slotId: string,
    leaseId: string,
    generation: number,
    identityJSON: string | null,
    sessionJSON: string | null,
    recoverySessionJSON: string | null,
    hasInteraction: boolean,
  ): Promise<number>;
  renew(
    storageNamespace: string,
    slotId: string,
    leaseId: string,
    generation: number,
    leaseMilliseconds: number,
  ): Promise<void>;
  abandon(
    storageNamespace: string,
    slotId: string,
    leaseId: string,
    generation: number,
  ): Promise<number>;
  invalidate(
    storageNamespace: string,
    slotId: string,
    accessibility: string,
  ): Promise<number>;
  discard(
    storageNamespace: string,
    slotId: string,
    generation: number,
  ): Promise<boolean>;
  saveIdentity(
    storageNamespace: string,
    slotId: string,
    leaseId: string,
    generation: number,
    identityJSON: string,
  ): Promise<void>;
  clearSession(
    storageNamespace: string,
    slotId: string,
    leaseId: string,
    generation: number,
  ): Promise<void>;
  release(
    storageNamespace: string,
    slotId: string,
    leaseId: string,
    generation: number,
  ): Promise<void>;
  cancelInteraction(
    storageNamespace: string,
    slotId: string,
    accessibility: string,
  ): Promise<{ sessionJSON: string | null; cancelled: boolean }>;
}

export default TurboModuleRegistry.get<Spec>("DeviceAttestationSessionVault");
