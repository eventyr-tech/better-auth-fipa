import { randomBytes } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { createAccountCatalog } from "./account-catalog.ts";
import type { RetainedIOSIdentity } from "./ios-retained-keys.ts";
import type { AccountSlot } from "./client.ts";
import { FirstPartyClientError } from "./errors.ts";
import type { SessionVaultNative } from "./session-coordinator.ts";

const random = () => randomBytes(32).toString("base64url");
// Native storage atomicity has Swift coverage. This double exercises catalog
// policy and bridge failures, not Keychain security or platform cryptography.
function fixture() {
  const records = new Map<
    string,
    {
      identityJSON: string | null;
      sessionJSON: string | null;
      generation: number;
      lease: string | null;
    }
  >();
  const accounts = new Map<string, AccountSlot>();
  const identities = new Map<string, RetainedIOSIdentity>();
  const faults = {
    read: false,
    commit: false,
    lostCommit: false,
    recovery: false,
    install: false,
    journal: false,
  };
  const record = (namespace: string) => {
    if (faults.read) throw new FirstPartyClientError("vault_locked");
    let value = records.get(namespace);
    if (!value) {
      value = {
        identityJSON: null,
        sessionJSON: null,
        generation: 0,
        lease: null,
      };
      records.set(namespace, value);
    }
    return value;
  };
  const owned = (namespace: string, id: string, generation: number) => {
    const value = record(namespace);
    if (value.lease !== id || value.generation !== generation)
      throw new FirstPartyClientError("vault_lost_lease");
    return value;
  };
  const native: SessionVaultNative = {
    acquire: (namespace) => {
      const value = record(namespace);
      if (value.lease)
        return Promise.reject(new FirstPartyClientError("vault_busy"));
      value.lease = random();
      return Promise.resolve({
        ...value,
        leaseId: value.lease,
        recoveryRequired: false,
      });
    },
    commit: (namespace, _slot, id, generation, identityJSON, sessionJSON) => {
      const value = owned(namespace, id, generation);
      if (faults.commit)
        return Promise.reject(
          new FirstPartyClientError("vault_storage_failed"),
        );
      Object.assign(value, {
        identityJSON,
        sessionJSON,
        generation: generation + 1,
        lease: null,
      });
      if (faults.lostCommit)
        return Promise.reject(
          new FirstPartyClientError("vault_storage_failed"),
        );
      return Promise.resolve(value.generation);
    },
    renew: (namespace, _slot, id, generation) => {
      owned(namespace, id, generation);
      return Promise.resolve();
    },
    abandon: (namespace, _slot, id, generation) => {
      const value = owned(namespace, id, generation);
      value.lease = null;
      value.sessionJSON = null;
      return Promise.resolve(++value.generation);
    },
    release: (namespace, _slot, id, generation) => {
      const value = owned(namespace, id, generation);
      value.lease = null;
      value.generation++;
      return Promise.resolve();
    },
    discard: (namespace, _slot, generation) => {
      const value = record(namespace);
      if (value.generation !== generation) return Promise.resolve(false);
      value.sessionJSON = null;
      value.lease = null;
      value.generation++;
      return Promise.resolve(true);
    },
    invalidate: vi.fn(),
    saveIdentity: (namespace, _slot, id, generation, identityJSON) => {
      if (faults.journal)
        return Promise.reject(
          new FirstPartyClientError("vault_storage_failed"),
        );
      owned(namespace, id, generation).identityJSON = identityJSON;
      return Promise.resolve();
    },
    clearSession: vi.fn(),
    cancelInteraction: vi.fn(),
  };
  const inspect = vi.fn((slot: string): Promise<AccountSlot> =>
    Promise.resolve(
      accounts.get(slot) ?? {
        slotId: slot,
        status: "pending",
        hasSession: false,
        hasInteraction: false,
        keysRemoved: false,
      },
    ),
  );
  const beginRecovery = vi.fn(async (slot: string) => {
    if (faults.recovery)
      throw new FirstPartyClientError("vault_storage_failed");
    const original = await inspect(slot);
    accounts.set(slot, {
      ...original,
      status: "recovery-required",
      hasSession: false,
      hasInteraction: false,
    });
  });
  const installRetainedIdentity = vi.fn(
    (slot: string, identity: RetainedIOSIdentity) => {
      if (faults.install)
        return Promise.reject(new FirstPartyClientError("vault_locked"));
      identities.set(slot, identity);
      return Promise.resolve();
    },
  );
  const randomToken = vi.fn(() => Promise.resolve(random()));
  const make = (namespace = "issuer/client/app") =>
    createAccountCatalog({
      namespace,
      vault: native,
      inspect,
      randomToken,
      beginRecovery,
      readIdentity: (slot) => Promise.resolve(identities.get(slot) ?? null),
      installRetainedIdentity,
    });
  const save = (slot: AccountSlot, overrides: Partial<AccountSlot> = {}) =>
    accounts.set(slot.slotId, {
      ...slot,
      status: "saved",
      account: { subject: "server-user", credentialId: random() },
      ...overrides,
    });
  return {
    make,
    native,
    records,
    accounts,
    faults,
    inspect,
    randomToken,
    beginRecovery,
    identities,
    installRetainedIdentity,
    save,
  };
}

function retained(): RetainedIOSIdentity {
  return {
    version: 1,
    dpopAlias: random(),
    dpopJkt: random(),
    providerScope: random(),
    providerStoragePrefix: "legacy.prefix.",
    providerKeyId: random(),
    providerRegistration: "unknown",
  };
}

describe("opaque native account catalog", () => {
  it("imports exact references once and leaves authentication pending", async () => {
    const f = fixture();
    const identity = retained();
    const imported = await f.make().importRetained(identity);
    expect(imported).toMatchObject({ status: "pending", hasSession: false });
    expect(await f.make().importRetained(identity)).toEqual(imported);
    expect(f.identities.get(imported.slotId)).toEqual(identity);
    expect(f.installRetainedIdentity).toHaveBeenCalledTimes(1);
    expect(await f.make().list()).toHaveLength(1);
  });

  it("keeps a pending imported credential separate from new-account preparation", async () => {
    const f = fixture();
    const identity = retained();
    const imported = await f.make().importRetained(identity);
    const fresh = await f.make().create();
    expect(fresh.slotId).not.toBe(imported.slotId);
    expect(await f.make().create()).toEqual(fresh);
    expect(await f.make().importRetained(identity)).toEqual(imported);
  });

  it("keeps interrupted imports reserved and resumes the same native identity", async () => {
    const f = fixture();
    const identity = retained();
    f.faults.install = true;
    await expect(f.make().importRetained(identity)).rejects.toMatchObject({
      code: "vault_locked",
    });
    const [reserved] = await f.make().list();
    expect(reserved?.status).toBe("import-required");
    await expect(f.make().require(reserved!.slotId)).rejects.toMatchObject({
      code: "invalid_state",
    });
    await expect(f.make().importRetained(retained())).rejects.toMatchObject({
      code: "invalid_state",
    });
    f.faults.install = false;
    const completed = await f.make().resumeImport();
    expect(completed.slotId).toBe(reserved!.slotId);
    expect(f.identities.get(completed.slotId)).toEqual(identity);
    await expect(f.make().require(completed.slotId)).resolves.toBeUndefined();
  });

  it("does not install references before the reservation is durable", async () => {
    const f = fixture();
    f.faults.journal = true;
    await expect(f.make().importRetained(retained())).rejects.toMatchObject({
      code: "vault_storage_failed",
    });
    expect(f.installRetainedIdentity).not.toHaveBeenCalled();
    expect(await f.make().list()).toEqual([]);
  });

  it.each([false, true])(
    "recovers final import write failure without duplicating the slot (ambiguous: %s)",
    async (ambiguous) => {
      const f = fixture();
      const identity = retained();
      f.faults.commit = !ambiguous;
      f.faults.lostCommit = ambiguous;
      await expect(f.make().importRetained(identity)).rejects.toMatchObject({
        code: "vault_storage_failed",
      });
      f.faults.commit = false;
      f.faults.lostCommit = false;
      const result = await f.make().importRetained(identity);
      expect(await f.make().list()).toHaveLength(1);
      expect(f.identities.get(result.slotId)).toEqual(identity);
    },
  );

  it("does not fall back to default key generation when an imported identity record disappears", async () => {
    const f = fixture();
    const imported = await f.make().importRetained(retained());
    f.identities.delete(imported.slotId);
    await expect(f.make().require(imported.slotId)).rejects.toMatchObject({
      code: "registration_recovery_required",
    });
    expect((await f.make().list())[0]?.status).toBe("recovery-required");
    const replacement = await f.make().recover(imported.slotId);
    expect(replacement.slotId).not.toBe(imported.slotId);
    expect(f.beginRecovery).toHaveBeenCalledWith(imported.slotId, true);
  });

  it("allows explicit recovery from an import whose keys are no longer available", async () => {
    const f = fixture();
    f.faults.install = true;
    await expect(f.make().importRetained(retained())).rejects.toBeDefined();
    const [reserved] = await f.make().list();
    const replacement = await f.make().recover(reserved!.slotId);
    expect(replacement.slotId).not.toBe(reserved!.slotId);
    await expect(f.make().resumeImport()).rejects.toMatchObject({
      code: "invalid_state",
    });
    await expect(f.make().require(reserved!.slotId)).rejects.toMatchObject({
      code: "reauthentication_required",
    });
  });

  it.each(["dpopAlias", "dpopJkt", "providerKeyId"] as const)(
    "rejects a conflicting import that shares %s with another slot",
    async (field) => {
      const f = fixture();
      const original = retained();
      await f.make().importRetained(original);
      const conflicting = { ...retained(), [field]: original[field] };
      await expect(f.make().importRetained(conflicting)).rejects.toMatchObject({
        code: "invalid_state",
      });
      expect(await f.make().list()).toHaveLength(1);
    },
  );

  it("recovers into a new slot while retaining the old binding and aliases", async () => {
    const f = fixture();
    const old = await f.make().create();
    f.save(old, { hasSession: true });
    const aliases = await f.make().aliases(old.slotId);
    const replacement = await f.make().recover(old.slotId);
    expect(replacement.slotId).not.toBe(old.slotId);
    expect(await f.make().aliases(replacement.slotId)).not.toEqual(aliases);
    expect(await f.make().aliases(old.slotId)).toEqual(aliases);
    expect(await f.make().list()).toMatchObject([
      {
        slotId: old.slotId,
        status: "recovery-required",
        hasSession: false,
        account: { subject: "server-user" },
      },
      { slotId: replacement.slotId, status: "pending", hasSession: false },
    ]);
    await expect(f.make().require(old.slotId)).rejects.toMatchObject({
      code: "reauthentication_required",
    });
    expect(await f.make().create()).toEqual(replacement);
    expect(await f.make().recover(old.slotId)).toEqual(replacement);
    expect(f.beginRecovery).toHaveBeenCalledTimes(1);
  });

  it("does not allocate a replacement if the old slot cannot be durably fenced", async () => {
    const f = fixture();
    const old = await f.make().create();
    f.save(old, { hasSession: true });
    f.faults.recovery = true;
    await expect(f.make().recover(old.slotId)).rejects.toMatchObject({
      code: "vault_storage_failed",
    });
    expect(await f.make().list()).toMatchObject([
      { slotId: old.slotId, hasSession: true },
    ]);
  });

  it.each([false, true])(
    "resumes recovery after catalog write failure (ambiguous: %s)",
    async (ambiguous) => {
      const f = fixture();
      const old = await f.make().create();
      f.save(old);
      f.faults.commit = !ambiguous;
      f.faults.lostCommit = ambiguous;
      await expect(f.make().recover(old.slotId)).rejects.toMatchObject({
        code: "vault_storage_failed",
      });
      f.faults.commit = false;
      f.faults.lostCommit = false;
      const resumed = await f.make().recover(old.slotId);
      expect(resumed.slotId).not.toBe(old.slotId);
      expect(await f.make().list()).toHaveLength(2);
      expect(await f.make().recover(old.slotId)).toEqual(resumed);
    },
  );

  it("resolves repeated recovery to the latest independent replacement", async () => {
    const f = fixture();
    const old = await f.make().create();
    f.save(old);
    const first = await f.make().recover(old.slotId);
    f.save(first);
    const latest = await f.make().recover(first.slotId);
    expect(await f.make().recover(old.slotId)).toEqual(latest);
    expect(await f.make().list()).toHaveLength(3);
  });

  it("continues recovery when a later replacement was retired and forgotten", async () => {
    const f = fixture();
    const old = await f.make().create();
    f.save(old);
    const first = await f.make().recover(old.slotId);
    f.save(first);
    const second = await f.make().recover(first.slotId);
    f.save(second, { status: "retired", keysRemoved: true });
    await f.make().forget(second.slotId);
    const replacement = await f.make().recover(old.slotId);
    expect(replacement.status).toBe("pending");
    expect([old.slotId, first.slotId, second.slotId]).not.toContain(
      replacement.slotId,
    );
    expect(await f.make().recover(old.slotId)).toEqual(replacement);
  });

  it("reuses an unfinished slot across restarts and assigns stable non-user aliases", async () => {
    const f = fixture();
    expect(await f.make().list()).toEqual([]);
    const first = await f.make().create();
    expect(first.slotId).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(await f.make().create()).toEqual(first);
    expect(f.randomToken).toHaveBeenCalledTimes(2);
    const aliases = await f.make().aliases(first.slotId);
    expect(await f.make().aliases(first.slotId)).toEqual(aliases);
    expect(aliases.dpopAlias).toBe(aliases.providerScope);
    expect(await f.make().list()).toEqual([first]);
  });

  it("allocates a separate credential for another sign-in even when the subject matches", async () => {
    const f = fixture();
    const first = await f.make().create();
    f.save(first);
    const second = await f.make().create();
    f.save(second);
    expect(second.slotId).not.toBe(first.slotId);
    expect(await f.make().aliases(second.slotId)).not.toEqual(
      await f.make().aliases(first.slotId),
    );
    const saved = await f.make().list();
    expect(saved).toHaveLength(2);
    expect(saved.map((item) => item.account?.subject)).toEqual([
      "server-user",
      "server-user",
    ]);
    // Binding metadata is authoritative only in each slot, never copied into the index.
    expect(JSON.stringify([...f.records.values()])).not.toContain(
      "server-user",
    );
  });

  it("isolates catalogs and rejects an unknown slot before identity preparation", async () => {
    const f = fixture();
    const first = await f.make("first").create();
    expect(await f.make("second").list()).toEqual([]);
    await expect(f.make("second").require(first.slotId)).rejects.toMatchObject({
      code: "invalid_request",
    });
    await expect(f.make().aliases("email@example.com")).rejects.toMatchObject({
      code: "invalid_request",
    });
  });

  it("bounds saved slots and still allows reuse of an unfinished slot at the limit", async () => {
    const f = fixture();
    for (let i = 0; i < 31; i++) f.save(await f.make().create());
    const last = await f.make().create();
    expect(await f.make().create()).toEqual(last);
    f.save(last);
    await expect(f.make().create()).rejects.toMatchObject({
      code: "account_limit_reached",
    });
    expect(await f.make().list()).toHaveLength(32);
  });

  it("forgets only a durably retired slot whose keys were removed", async () => {
    const f = fixture();
    const first = await f.make().create();
    await expect(f.make().forget(first.slotId)).rejects.toMatchObject({
      code: "invalid_state",
    });
    f.save(first, { status: "retired" });
    await expect(f.make().forget(first.slotId)).rejects.toMatchObject({
      code: "invalid_state",
    });
    f.save(first, { status: "retired", keysRemoved: true });
    await f.make().forget(first.slotId);
    expect(await f.make().list()).toEqual([]);
    expect(f.accounts.get(first.slotId)?.status).toBe("retired");
    await expect(f.make().require(first.slotId)).rejects.toMatchObject({
      code: "invalid_request",
    });
    expect((await f.make().create()).slotId).not.toBe(first.slotId);
  });

  it("never exposes a new slot before its durable catalog write", async () => {
    const f = fixture();
    f.faults.commit = true;
    await expect(f.make().create()).rejects.toMatchObject({
      code: "vault_storage_failed",
    });
    f.faults.commit = false;
    expect(await f.make().list()).toEqual([]);
  });

  it("recovers a lost creation response by listing the committed pending slot", async () => {
    const f = fixture();
    f.faults.lostCommit = true;
    await expect(f.make().create()).rejects.toMatchObject({
      code: "vault_storage_failed",
    });
    f.faults.lostCommit = false;
    const saved = await f.make().list();
    expect(saved).toHaveLength(1);
    expect(await f.make().create()).toEqual(saved[0]);
  });

  it("does not treat inaccessible or corrupt storage as an empty catalog", async () => {
    const f = fixture();
    const first = await f.make().create();
    f.faults.read = true;
    await expect(f.make().list()).rejects.toMatchObject({
      code: "vault_locked",
    });
    f.faults.read = false;
    const value = [...f.records.values()][0]!;
    const valid = value.identityJSON;
    value.identityJSON = '{"version":999}';
    await expect(f.make().create()).rejects.toMatchObject({
      code: "vault_corrupt",
    });
    expect(value.identityJSON).toBe('{"version":999}');
    value.identityJSON = valid;
    expect(await f.make().create()).toEqual(first);
  });

  it("serializes competing runtimes without creating duplicate pending slots", async () => {
    const f = fixture();
    const results = await Promise.allSettled([
      f.make().create(),
      f.make().create(),
    ]);
    expect(
      results.filter((result) => result.status === "fulfilled"),
    ).toHaveLength(1);
    expect(await f.make().list()).toHaveLength(1);
  });
});
