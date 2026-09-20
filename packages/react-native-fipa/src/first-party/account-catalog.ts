import { z } from "zod";
import type { AccountSlot, NativeIdentity } from "./client.ts";
import {
  retainedIOSIdentitySchema,
  type RetainedIOSIdentity,
} from "./ios-retained-keys.ts";
import { FirstPartyClientError } from "./errors.ts";
import {
  createSessionCoordinator,
  type SessionVaultNative,
} from "./session-coordinator.ts";

const id = z.string().regex(/^[A-Za-z0-9_-]{43}$/);
const catalogSchema = z.strictObject({
  version: z.literal(1),
  id,
  slots: z
    .array(id)
    .max(32)
    .refine((slots) => new Set(slots).size === slots.length),
  replacements: z
    .array(z.strictObject({ from: id, to: id }))
    .max(31)
    .optional(),
  importing: z
    .strictObject({ slot: id, identity: retainedIOSIdentitySchema })
    .optional(),
  importedSlots: z.array(id).max(32).optional(),
});
type Catalog = z.infer<typeof catalogSchema>;

/** An index of opaque slots, never a second authority for subject or tokens.
 * Account bindings remain inside each slot's atomic identity/session record. */
export function createAccountCatalog(options: {
  namespace: string;
  vault: SessionVaultNative;
  randomToken(): Promise<string>;
  inspect(slot: string): Promise<AccountSlot>;
  beginRecovery(slot: string, allowEmptyImport: boolean): Promise<void>;
  readIdentity(slot: string): Promise<NativeIdentity | null>;
  installRetainedIdentity(
    slot: string,
    identity: RetainedIOSIdentity,
  ): Promise<void>;
}) {
  const coordinator = createSessionCoordinator(options.vault, {
    namespace: JSON.stringify([
      "device-attestation-catalog/v1",
      options.namespace,
    ]),
  });
  async function run<T>(
    change: boolean,
    operation: (
      record: Catalog | null,
      save: (record: Catalog) => Promise<void>,
    ) => Promise<{ record: Catalog | null; result: T }>,
  ) {
    return coordinator.run("catalog", async (tx) => {
      if (!change) tx.readOnly();
      if (tx.session !== null) throw new FirstPartyClientError("vault_corrupt");
      const parsed = catalogSchema.nullable().safeParse(tx.identity);
      if (!parsed.success) throw new FirstPartyClientError("vault_corrupt");
      const replacements = parsed.data?.replacements ?? [];
      if (
        new Set(replacements.map((edge) => edge.from)).size !==
          replacements.length ||
        replacements.some(
          (edge) =>
            edge.from === edge.to ||
            !parsed.data?.slots.includes(edge.from) ||
            !parsed.data.slots.includes(edge.to),
        )
      )
        throw new FirstPartyClientError("vault_corrupt");
      if (
        parsed.data?.importing &&
        !parsed.data.slots.includes(parsed.data.importing.slot)
      )
        throw new FirstPartyClientError("vault_corrupt");
      if (
        parsed.data?.importedSlots &&
        (new Set(parsed.data.importedSlots).size !==
          parsed.data.importedSlots.length ||
          parsed.data.importedSlots.some(
            (slot) => !parsed.data?.slots.includes(slot),
          ))
      )
        throw new FirstPartyClientError("vault_corrupt");
      for (const edge of replacements) {
        const seen = new Set<string>();
        let current: typeof edge | undefined = edge;
        while (current) {
          if (seen.has(current.from))
            throw new FirstPartyClientError("vault_corrupt");
          seen.add(current.from);
          const target: string = current.to;
          current = replacements.find((value) => value.from === target);
        }
      }
      const update = await operation(parsed.data, (record) =>
        tx.saveIdentity(record),
      );
      return { identity: update.record, session: null, result: update.result };
    });
  }
  async function randomId() {
    try {
      return id.parse(await options.randomToken());
    } catch {
      throw new FirstPartyClientError("operation_failed");
    }
  }
  function member(
    record: Catalog | null,
    slot: string,
  ): asserts record is Catalog {
    if (!id.safeParse(slot).success || !record?.slots.includes(slot))
      throw new FirstPartyClientError("invalid_request");
  }
  async function describeSlot(
    record: Catalog,
    slot: string,
  ): Promise<AccountSlot> {
    const account = await options.inspect(slot);
    if (record.importing?.slot === slot)
      return { ...account, status: "import-required" };
    if (
      record.replacements?.some((edge) => edge.from === slot) ||
      (record.importedSlots?.includes(slot) &&
        !(await options.readIdentity(slot)))
    )
      return { ...account, status: "recovery-required" };
    return account;
  }
  async function finishImport(
    record: Catalog,
  ): Promise<{ record: Catalog; result: AccountSlot }> {
    if (!record.importing) throw new FirstPartyClientError("invalid_state");
    const { slot, identity } = record.importing;
    await options.installRetainedIdentity(slot, identity);
    const result = await options.inspect(slot);
    const cleaned = {
      ...record,
      importedSlots: [...new Set([...(record.importedSlots ?? []), slot])],
    };
    delete cleaned.importing;
    return { record: cleaned, result };
  }
  return {
    importRetained(input: RetainedIOSIdentity): Promise<AccountSlot> {
      const parsed = retainedIOSIdentitySchema.safeParse(input);
      if (!parsed.success) throw new FirstPartyClientError("invalid_request");
      return run(true, async (stored, save) => {
        const record: Catalog = stored ?? {
          version: 1,
          id: await randomId(),
          slots: [],
        };
        if (record.importing) {
          if (
            JSON.stringify(record.importing.identity) !==
            JSON.stringify(parsed.data)
          )
            throw new FirstPartyClientError("invalid_state");
          return finishImport(record);
        }
        for (const slot of record.slots) {
          const existing = await options.readIdentity(slot);
          if (!existing) continue;
          const requested = parsed.data;
          const sameReference =
            existing.dpopAlias === requested.dpopAlias &&
            existing.providerScope === requested.providerScope &&
            existing.providerStoragePrefix === requested.providerStoragePrefix;
          const sameKeys =
            existing.providerKeyId === requested.providerKeyId &&
            existing.dpopJkt === requested.dpopJkt;
          if (
            sameReference &&
            sameKeys &&
            !existing.retired &&
            !existing.superseded
          )
            return { record, result: await describeSlot(record, slot) };
          if (
            sameReference ||
            existing.dpopAlias === requested.dpopAlias ||
            existing.dpopJkt === requested.dpopJkt ||
            existing.providerKeyId === requested.providerKeyId ||
            (existing.providerScope === requested.providerScope &&
              existing.providerStoragePrefix ===
                requested.providerStoragePrefix)
          )
            throw new FirstPartyClientError("invalid_state");
        }
        if (record.slots.length >= 32)
          throw new FirstPartyClientError("account_limit_reached");
        const slot = await randomId();
        if (record.slots.includes(slot))
          throw new FirstPartyClientError("operation_failed");
        const reserved: Catalog = {
          ...record,
          slots: [...record.slots, slot],
          importing: { slot, identity: parsed.data },
        };
        // Commit the reservation before writing a second record. Interrupted
        // imports resume this exact identity and can never become default key creation.
        await save(reserved);
        return finishImport(reserved);
      });
    },
    resumeImport(): Promise<AccountSlot> {
      return run(true, (record) => {
        if (!record) throw new FirstPartyClientError("invalid_state");
        return finishImport(record);
      });
    },
    /** Reuse unfinished default preparation. Imported credentials remain reserved
     * for an explicit returning-account login, never a new-account request. */
    create(): Promise<AccountSlot> {
      return run(true, async (stored) => {
        const record = stored ?? {
          version: 1,
          id: await randomId(),
          slots: [],
        };
        for (const slot of record.slots) {
          if (
            record.importing?.slot === slot ||
            record.importedSlots?.includes(slot)
          )
            continue;
          const account = await describeSlot(record, slot);
          if (account.status === "pending") return { record, result: account };
        }
        if (record.slots.length >= 32)
          throw new FirstPartyClientError("account_limit_reached");
        const slot = await randomId();
        if (record.slots.includes(slot))
          throw new FirstPartyClientError("operation_failed");
        return {
          record: { ...record, slots: [...record.slots, slot] },
          result: {
            slotId: slot,
            status: "pending",
            hasSession: false,
            hasInteraction: false,
            keysRemoved: false,
          } satisfies AccountSlot,
        };
      });
    },
    list(): Promise<AccountSlot[]> {
      return run(false, async (record) => {
        const result: AccountSlot[] = [];
        for (const slot of record?.slots ?? [])
          result.push(await describeSlot(record!, slot));
        return { record, result };
      });
    },
    require(slot: string): Promise<void> {
      return run(false, async (record) => {
        member(record, slot);
        if (record.importing?.slot === slot)
          throw new FirstPartyClientError("invalid_state");
        if (
          record.importedSlots?.includes(slot) &&
          !(await options.readIdentity(slot))
        )
          throw new FirstPartyClientError("registration_recovery_required");
        if (record.replacements?.some((edge) => edge.from === slot))
          throw new FirstPartyClientError("reauthentication_required");
        return Promise.resolve({ record, result: undefined });
      });
    },
    /** Journal the old slot's tombstone before exposing any replacement. A
     * retry after either write fails resumes without regenerating old keys. */
    recover(slot: string): Promise<AccountSlot> {
      return run(true, async (record) => {
        member(record, slot);
        const visited = new Set<string>();
        let target = slot;
        let next: { from: string; to: string } | undefined;
        while (
          (next = record.replacements?.find((edge) => edge.from === target))
        ) {
          if (visited.has(target))
            throw new FirstPartyClientError("vault_corrupt");
          visited.add(target);
          target = next.to;
        }
        if (target !== slot) {
          const current = await describeSlot(record, target);
          if (current.status !== "recovery-required")
            return { record, result: current };
          // Its previous replacement was explicitly retired and forgotten.
          // Continue the chain without reopening a superseded identity.
        }
        if (record.slots.length >= 32)
          throw new FirstPartyClientError("account_limit_reached");
        const replacement = await randomId();
        if (record.slots.includes(replacement))
          throw new FirstPartyClientError("operation_failed");
        await options.beginRecovery(
          target,
          record.importing?.slot === target ||
            record.importedSlots?.includes(target) === true,
        );
        const cleaned = { ...record };
        if (cleaned.importing?.slot === target) delete cleaned.importing;
        return {
          record: {
            ...cleaned,
            slots: [...record.slots, replacement],
            replacements: [
              ...(record.replacements ?? []),
              { from: target, to: replacement },
            ],
          },
          result: {
            slotId: replacement,
            status: "pending",
            hasSession: false,
            hasInteraction: false,
            keysRemoved: false,
          } satisfies AccountSlot,
        };
      });
    },
    aliases(
      slot: string,
    ): Promise<{ dpopAlias: string; providerScope: string }> {
      return run(false, (record) => {
        member(record, slot);
        const scope = `fipa.v1.${record.id}.${slot}`;
        return Promise.resolve({
          record,
          result: { dpopAlias: scope, providerScope: scope },
        });
      });
    },
    /** The retired slot tombstone remains in the vault, fencing old callers. */
    forget(slot: string): Promise<void> {
      return run(true, async (record) => {
        member(record, slot);
        const account = await options.inspect(slot);
        if (account.status !== "retired" || !account.keysRemoved)
          throw new FirstPartyClientError("invalid_state");
        return {
          record: {
            ...record,
            slots: record.slots.filter((value) => value !== slot),
            ...(record.replacements
              ? {
                  replacements: record.replacements.filter(
                    (edge) => edge.from !== slot && edge.to !== slot,
                  ),
                }
              : {}),
            ...(record.importedSlots
              ? {
                  importedSlots: record.importedSlots.filter(
                    (value) => value !== slot,
                  ),
                }
              : {}),
          },
          result: undefined,
        };
      });
    },
  };
}
