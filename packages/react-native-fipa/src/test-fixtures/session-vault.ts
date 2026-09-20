import { randomBytes } from "node:crypto";
import { FirstPartyClientError } from "../first-party/errors.ts";
import type { SessionVaultNative } from "../first-party/session-coordinator.ts";
const random = () => randomBytes(32).toString("base64url");
// In-memory native contract double. Native atomicity, leases and crash recovery
// have separate Swift and Kotlin tests. Platform evidence is synthetic; HTTP/DPoP/PKCE,
// password verification, continuations and OAuth token issuance are real here.
export function createMemorySessionVault() {
  const record = {
    generation: 0,
    lease: null as string | null,
    identityJSON: null as string | null,
    sessionJSON: null as string | null,
    recoverySessionJSON: null as string | null,
    rollbackSessionJSON: null as string | null,
    hasInteraction: false,
    preserveSession: false,
  };
  const faults = { rejectTokenCommit: false };
  const owned = (id: string, generation: number) => {
    if (record.lease !== id || record.generation !== generation)
      throw new FirstPartyClientError("vault_lost_lease");
  };
  const invalidate = (recover = false) => {
    record.sessionJSON = recover ? record.recoverySessionJSON : null;
    record.recoverySessionJSON = record.sessionJSON;
    record.rollbackSessionJSON = null;
    record.hasInteraction = false;
    record.lease = null;
    return ++record.generation;
  };
  const native: SessionVaultNative = {
    release: (_namespace, _slot, id, generation) => {
      owned(id, generation);
      record.lease = null;
      record.generation++;
      return Promise.resolve();
    },
    clearSession: (_namespace, _slot, id, generation) => {
      owned(id, generation);
      record.sessionJSON = null;
      record.recoverySessionJSON = null;
      record.rollbackSessionJSON = null;
      record.hasInteraction = false;
      return Promise.resolve();
    },
    saveIdentity: (_namespace, _slot, id, generation, identityJSON) => {
      owned(id, generation);
      record.identityJSON = identityJSON;
      return Promise.resolve();
    },
    acquire: (
      _namespace,
      _slot,
      _accessibility,
      _duration,
      preserveSession,
    ) => {
      if (record.lease)
        return Promise.reject(new FirstPartyClientError("vault_busy"));
      record.lease = random();
      record.preserveSession = preserveSession;
      return Promise.resolve({
        ...record,
        leaseId: record.lease,
        recoveryRequired: false,
      });
    },
    commit: (
      _namespace,
      _slot,
      id,
      generation,
      identityJSON,
      sessionJSON,
      recoverySessionJSON,
      hasInteraction,
    ) => {
      owned(id, generation);
      if (faults.rejectTokenCommit && sessionJSON?.includes('"phase":"active"'))
        return Promise.reject(
          new FirstPartyClientError("vault_storage_failed"),
        );
      Object.assign(record, {
        rollbackSessionJSON: record.preserveSession
          ? record.recoverySessionJSON
          : null,
        recoverySessionJSON,
        hasInteraction,
        identityJSON,
        sessionJSON,
        lease: null,
        generation: generation + 1,
      });
      return Promise.resolve(record.generation);
    },
    renew: (_namespace, _slot, id, generation) => {
      owned(id, generation);
      return Promise.resolve();
    },
    abandon: (_namespace, _slot, id, generation) => {
      owned(id, generation);
      return Promise.resolve(invalidate(record.preserveSession));
    },
    invalidate: () => Promise.resolve(invalidate()),
    cancelInteraction: () => {
      if (record.lease && !record.preserveSession)
        return Promise.reject(new FirstPartyClientError("vault_busy"));
      if (!record.lease && !record.hasInteraction)
        return Promise.resolve({ sessionJSON: null, cancelled: false });
      const sessionJSON = record.sessionJSON;
      invalidate(true);
      return Promise.resolve({ sessionJSON, cancelled: true });
    },
    discard: (_namespace, _slot, generation) => {
      if (generation !== record.generation) return Promise.resolve(false);
      record.recoverySessionJSON = record.rollbackSessionJSON;
      invalidate(true);
      return Promise.resolve(true);
    },
  };
  return { native, record, faults };
}

/** Route the bridge contract by namespace and slot. Each record retains the
 * existing fault-injectable lifecycle double; production uses native storage. */
export function createMemorySessionVaultCollection() {
  const records = new Map<
    string,
    ReturnType<typeof createMemorySessionVault>
  >();
  const record = (namespace: string, slot: string) => {
    const key = JSON.stringify([namespace, slot]);
    let stored = records.get(key);
    if (!stored) {
      stored = createMemorySessionVault();
      records.set(key, stored);
    }
    return stored;
  };
  const native = new Proxy({} as SessionVaultNative, {
    get(_target, name: keyof SessionVaultNative) {
      return (...args: unknown[]) => {
        const source = record(String(args[0]), String(args[1])).native;
        return Reflect.apply(source[name], source, args) as unknown;
      };
    },
  });
  return { native, records, record };
}
