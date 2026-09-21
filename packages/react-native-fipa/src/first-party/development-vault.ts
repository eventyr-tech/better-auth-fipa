import type { AsyncStorageStatic } from "@react-native-async-storage/async-storage";
import { z } from "zod";
import { FirstPartyClientError } from "./errors.ts";
import type { SessionVaultNative } from "./session-coordinator.ts";

const schema = z.strictObject({
  generation: z
    .number()
    .int()
    .nonnegative()
    .max(Number.MAX_SAFE_INTEGER - 1),
  lease: z.string().nullable(),
  expiresAt: z.number().finite(),
  identityJSON: z.string().nullable(),
  sessionJSON: z.string().nullable(),
  recoverySessionJSON: z.string().nullable(),
  rollbackSessionJSON: z.string().nullable(),
  hasInteraction: z.boolean(),
  preserveSession: z.boolean(),
  recoveryRequired: z.boolean(),
});
type RecordValue = z.infer<typeof schema>;
// All SDK clients in one JS runtime serialize mutations. Development AsyncStorage
// is not a cross-process transaction store; simultaneous JS runtimes are unsupported.
const queues = new Map<string, Promise<unknown>>();
const empty = (): RecordValue => ({
  generation: 0,
  lease: null,
  expiresAt: 0,
  identityJSON: null,
  sessionJSON: null,
  recoverySessionJSON: null,
  rollbackSessionJSON: null,
  hasInteraction: false,
  preserveSession: false,
  recoveryRequired: false,
});

/** Internal development-only persistence. Never used by hardware clients. */
export function createDevelopmentVault(
  randomToken: () => Promise<string>,
): SessionVaultNative {
  async function mutate<T>(
    namespace: string,
    slot: string,
    operation: (record: RecordValue) => T | Promise<T>,
  ): Promise<T> {
    const key = `fipa:development-storage:v1:${JSON.stringify([namespace, slot])}`;
    const previous = queues.get(key) ?? Promise.resolve();
    const current = previous
      .catch(() => undefined)
      .then(async () => {
        const module =
          await import("@react-native-async-storage/async-storage").catch(
            () => {
              throw new FirstPartyClientError("vault_unavailable");
            },
          );
        const candidate = module.default as unknown as AsyncStorageStatic & {
          default?: AsyncStorageStatic;
        };
        const storage =
          typeof candidate.getItem === "function"
            ? candidate
            : candidate.default;
        if (!storage) throw new FirstPartyClientError("vault_unavailable");
        const value = await storage.getItem(key);
        let record: RecordValue;
        try {
          record = value === null ? empty() : schema.parse(JSON.parse(value));
        } catch {
          throw new FirstPartyClientError("vault_corrupt");
        }
        const result = await operation(record);
        await storage.setItem(key, JSON.stringify(record));
        return result;
      });
    queues.set(key, current);
    try {
      return await current;
    } finally {
      if (queues.get(key) === current) queues.delete(key);
    }
  }
  const owned = (r: RecordValue, lease: string, generation: number) => {
    if (
      r.lease !== lease ||
      r.generation !== generation ||
      r.expiresAt <= Date.now()
    )
      throw new FirstPartyClientError("vault_lost_lease");
  };
  const invalidate = (r: RecordValue, recover = false) => {
    r.sessionJSON = recover ? r.recoverySessionJSON : null;
    r.recoverySessionJSON = r.sessionJSON;
    r.rollbackSessionJSON = null;
    r.hasInteraction = false;
    r.lease = null;
    r.recoveryRequired = true;
    return ++r.generation;
  };
  return {
    acquire: (ns, slot, _access, duration, preserveSession) =>
      mutate(ns, slot, async (r) => {
        if (r.lease) {
          if (r.expiresAt > Date.now())
            throw new FirstPartyClientError("vault_busy");
          invalidate(r, r.preserveSession);
        }
        r.lease = await randomToken();
        r.expiresAt = Date.now() + duration;
        r.preserveSession = preserveSession;
        return {
          leaseId: r.lease,
          generation: r.generation,
          identityJSON: r.identityJSON,
          sessionJSON: r.sessionJSON,
          recoveryRequired: r.recoveryRequired,
        };
      }),
    commit: (
      ns,
      slot,
      lease,
      generation,
      identityJSON,
      sessionJSON,
      recoverySessionJSON,
      hasInteraction,
    ) =>
      mutate(ns, slot, (r) => {
        owned(r, lease, generation);
        r.rollbackSessionJSON = r.preserveSession
          ? r.recoverySessionJSON
          : null;
        Object.assign(r, {
          identityJSON,
          sessionJSON,
          recoverySessionJSON,
          hasInteraction,
          recoveryRequired: false,
          lease: null,
        });
        return ++r.generation;
      }),
    renew: (ns, slot, lease, generation, duration) =>
      mutate(ns, slot, (r) => {
        owned(r, lease, generation);
        r.expiresAt = Date.now() + duration;
      }),
    release: (ns, slot, lease, generation) =>
      mutate(ns, slot, (r) => {
        owned(r, lease, generation);
        r.lease = null;
        r.generation++;
      }),
    saveIdentity: (ns, slot, lease, generation, identityJSON) =>
      mutate(ns, slot, (r) => {
        owned(r, lease, generation);
        r.identityJSON = identityJSON;
      }),
    clearSession: (ns, slot, lease, generation) =>
      mutate(ns, slot, (r) => {
        owned(r, lease, generation);
        r.sessionJSON = null;
        r.recoverySessionJSON = null;
        r.rollbackSessionJSON = null;
        r.hasInteraction = false;
      }),
    abandon: (ns, slot, lease, generation) =>
      mutate(ns, slot, (r) => {
        owned(r, lease, generation);
        return invalidate(r, r.preserveSession);
      }),
    invalidate: (ns, slot) => mutate(ns, slot, (r) => invalidate(r)),
    discard: (ns, slot, generation) =>
      mutate(ns, slot, (r) => {
        if (r.generation !== generation) return false;
        r.recoverySessionJSON = r.rollbackSessionJSON;
        invalidate(r, true);
        return true;
      }),
    cancelInteraction: (ns, slot) =>
      mutate(ns, slot, (r) => {
        if (r.lease && r.expiresAt > Date.now() && !r.preserveSession)
          throw new FirstPartyClientError("vault_busy");
        if (!r.lease && !r.hasInteraction)
          return { sessionJSON: null, cancelled: false };
        const sessionJSON = r.sessionJSON;
        invalidate(r, !r.lease || r.preserveSession);
        return { sessionJSON, cancelled: true };
      }),
  };
}
