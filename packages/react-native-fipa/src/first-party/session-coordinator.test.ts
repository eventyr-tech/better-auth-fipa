import { afterEach, describe, expect, it, vi } from "vitest";
import { FirstPartyClientError } from "./errors.ts";
import {
  createSessionCoordinator,
  type SlotTransaction,
} from "./session-coordinator.ts";

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}
function fixture() {
  const snapshot = {
    leaseId: "a".repeat(43),
    generation: 5,
    identityJSON: JSON.stringify({ keyAlias: "retained-key" }),
    sessionJSON: JSON.stringify({ refreshToken: "old-secret" }),
    recoveryRequired: false,
  };
  const native = {
    acquire: vi.fn().mockResolvedValue(snapshot),
    commit: vi.fn().mockResolvedValue(6),
    renew: vi.fn().mockResolvedValue(undefined),
    abandon: vi.fn().mockResolvedValue(6),
    invalidate: vi.fn().mockResolvedValue(6),
    discard: vi.fn().mockResolvedValue(true),
    saveIdentity: vi.fn().mockResolvedValue(undefined),
    clearSession: vi.fn().mockResolvedValue(undefined),
    release: vi.fn().mockResolvedValue(undefined),
    cancelInteraction: vi
      .fn()
      .mockResolvedValue({ sessionJSON: null, cancelled: false }),
  };
  const coordinator = createSessionCoordinator(native, {
    namespace: "issuer/client/app",
  });
  const update = {
    identity: { keyAlias: "retained-key" },
    session: { refreshToken: "new-secret" },
    result: { kind: "authenticated" },
  };
  return { native, coordinator, update, snapshot };
}
afterEach(() => {
  vi.useRealTimers();
});

describe("native session coordination", () => {
  it("passes interaction recovery policy and independent recovery material to native storage", async () => {
    const { coordinator, native, update } = fixture();
    const recoverySession = { refreshToken: "independent-family" };
    await coordinator.run(
      "slot",
      () =>
        Promise.resolve({ ...update, recoverySession, hasInteraction: true }),
      undefined,
      { preserveSession: true },
    );
    expect(native.acquire).toHaveBeenCalledWith(
      "issuer/client/app",
      "slot",
      "when-unlocked",
      30000,
      true,
    );
    expect(native.commit.mock.calls[0]?.slice(6)).toEqual([
      JSON.stringify(recoverySession),
      true,
    ]);
  });

  it("waits for aborted interaction cleanup before returning its native cancellation snapshot", async () => {
    const { coordinator, native } = fixture();
    const entered = deferred<void>();
    const cleanup = deferred<number>();
    native.abandon.mockReturnValue(cleanup.promise);
    native.cancelInteraction.mockResolvedValue({
      sessionJSON: '{"step":"old"}',
      cancelled: true,
    });
    const operation = coordinator
      .run(
        "slot",
        () => {
          entered.resolve();
          return new Promise<never>(() => {});
        },
        undefined,
        { preserveSession: true },
      )
      .catch((error: unknown) => error);
    await entered.promise;
    let returned = false;
    const cancelled = coordinator.cancelInteraction("slot").then((value) => {
      returned = true;
      return value;
    });
    await vi.waitFor(() => expect(native.abandon).toHaveBeenCalledOnce());
    expect(returned).toBe(false);
    cleanup.resolve(6);
    await expect(cancelled).resolves.toEqual({
      session: { step: "old" },
      cancelled: true,
    });
    await expect(operation).resolves.toMatchObject({ code: "cancelled" });
  });

  it("surfaces a busy refresh lease without aborting or recovering its token", async () => {
    const { coordinator, native, update } = fixture();
    const entered = deferred<void>();
    const completed = deferred<typeof update>();
    const operation = coordinator.run("slot", () => {
      entered.resolve();
      return completed.promise;
    });
    await entered.promise;
    native.cancelInteraction.mockRejectedValue(
      new FirstPartyClientError("vault_busy"),
    );
    await expect(coordinator.cancelInteraction("slot")).rejects.toMatchObject({
      code: "vault_busy",
    });
    expect(native.abandon).not.toHaveBeenCalled();
    completed.resolve(update);
    await expect(operation).resolves.toEqual(update.result);
  });

  it("compares read-only JSON records independently of object property order", async () => {
    const { coordinator, native } = fixture();
    native.acquire.mockResolvedValue({
      leaseId: "a".repeat(43),
      generation: 5,
      identityJSON: null,
      sessionJSON: '{"nested":{"b":2,"a":1},"values":[1,2]}',
      recoveryRequired: false,
    });
    await expect(
      coordinator.run("slot", (tx) => {
        tx.readOnly();
        return Promise.resolve({
          identity: null,
          session: { values: [1, 2], nested: { a: 1, b: 2 } },
          result: "ok",
        });
      }),
    ).resolves.toBe("ok");
  });

  it("keeps a read-only session when cancellation races its completed commit", async () => {
    const { native, coordinator } = fixture();
    const controller = new AbortController();
    native.commit.mockImplementation(() => {
      controller.abort();
      return Promise.resolve(6);
    });
    await expect(
      coordinator.run(
        "slot",
        (tx) => {
          tx.readOnly();
          return Promise.resolve({
            identity: tx.identity,
            session: tx.session,
            result: undefined,
          });
        },
        controller.signal,
      ),
    ).rejects.toMatchObject({ code: "cancelled", cleanup: "complete" });
    expect(native.commit).toHaveBeenCalledOnce();
    expect(native.abandon).not.toHaveBeenCalled();
    expect(native.discard).not.toHaveBeenCalled();
  });
  it("releases a cancelled read-only lease without abandoning its session", async () => {
    const { native, coordinator, update, snapshot } = fixture();
    const controller = new AbortController();
    await expect(
      coordinator.run(
        "slot",
        (tx) => {
          tx.readOnly();
          controller.abort();
          return Promise.resolve({
            ...update,
            session: JSON.parse(snapshot.sessionJSON) as Record<
              string,
              unknown
            >,
          });
        },
        controller.signal,
      ),
    ).rejects.toMatchObject({ code: "cancelled", cleanup: "complete" });
    expect(native.release).toHaveBeenCalledOnce();
    expect(native.abandon).not.toHaveBeenCalled();
    expect(native.discard).not.toHaveBeenCalled();
  });

  it("rejects mutation under a read-only lease and cannot switch after journaling", async () => {
    const { native, coordinator, update } = fixture();
    await expect(
      coordinator.run("slot", async (tx) => {
        tx.readOnly();
        await tx.clearSession();
        return update;
      }),
    ).rejects.toMatchObject({ code: "invalid_state" });
    expect(native.clearSession).not.toHaveBeenCalled();
    await expect(
      coordinator.run("slot", (tx) => {
        tx.readOnly();
        return Promise.resolve(update);
      }),
    ).rejects.toMatchObject({ code: "invalid_state" });
    expect(native.commit).not.toHaveBeenCalled();
    await expect(
      coordinator.run("slot", async (tx) => {
        await tx.clearSession();
        tx.readOnly();
        return update;
      }),
    ).rejects.toMatchObject({ code: "invalid_state" });
    expect(native.abandon).toHaveBeenCalledOnce();
  });

  it("durably clears session capabilities before remote work and rejects late clears", async () => {
    const { native, coordinator, update } = fixture();
    const cleared = deferred<void>();
    native.clearSession.mockReturnValue(cleared.promise);
    const remote = vi.fn();
    let held!: SlotTransaction;
    const run = coordinator.run("slot", async (tx) => {
      held = tx;
      await tx.clearSession();
      remote();
      return { ...update, session: null };
    });
    await vi.waitFor(() => expect(native.clearSession).toHaveBeenCalledOnce());
    expect(remote).not.toHaveBeenCalled();
    cleared.resolve();
    await run;
    expect(remote).toHaveBeenCalledOnce();
    expect(native.commit.mock.calls[0]?.[5]).toBeNull();
    await expect(held.clearSession()).rejects.toMatchObject({
      code: "cancelled",
    });
  });
  it("journals registration before external work and final commit", async () => {
    const { native, coordinator, update } = fixture();
    const persisted = deferred<void>();
    native.saveIdentity.mockReturnValue(persisted.promise);
    const external = vi.fn();
    const identity = { ...update.identity, registration: "attesting" };
    const result = coordinator.run("slot", async (tx) => {
      await tx.saveIdentity(identity);
      external();
      return { ...update, identity };
    });
    await vi.waitFor(() => expect(native.saveIdentity).toHaveBeenCalledOnce());
    expect(external).not.toHaveBeenCalled();
    expect(native.commit).not.toHaveBeenCalled();
    persisted.resolve();
    await result;
    expect(external).toHaveBeenCalledOnce();
    expect(native.saveIdentity).toHaveBeenCalledWith(
      "issuer/client/app",
      "slot",
      "a".repeat(43),
      5,
      JSON.stringify(identity),
    );
    expect(native.commit.mock.calls[0]?.[4]).toBe(JSON.stringify(identity));
  });

  it("aborts before external work on a failed registration journal", async () => {
    const { native, coordinator, update } = fixture();
    native.saveIdentity.mockRejectedValue({ code: "vault_locked" });
    const external = vi.fn();
    await expect(
      coordinator.run("slot", async (tx) => {
        await tx.saveIdentity(update.identity);
        external();
        return update;
      }),
    ).rejects.toMatchObject({ code: "vault_locked", cleanup: "complete" });
    expect(external).not.toHaveBeenCalled();
    expect(native.commit).not.toHaveBeenCalled();
    expect(native.abandon).toHaveBeenCalledOnce();
  });

  it("rejects late registration writes after cancellation and after commit", async () => {
    const { native, coordinator, update } = fixture();
    let transaction!: SlotTransaction;
    await coordinator.run("slot", (tx) => {
      transaction = tx;
      return Promise.resolve(update);
    });
    await expect(
      transaction.saveIdentity(update.identity),
    ).rejects.toMatchObject({ code: "cancelled" });
    const started = deferred<void>();
    const running = deferred<typeof update>();
    const cancelled = coordinator.run("slot", (tx) => {
      transaction = tx;
      started.resolve();
      return running.promise;
    });
    await started.promise;
    const outcome = cancelled.catch((error: unknown) => error);
    await coordinator.invalidate("slot");
    await expect(outcome).resolves.toMatchObject({ code: "cancelled" });
    await expect(
      transaction.saveIdentity(update.identity),
    ).rejects.toMatchObject({ code: "cancelled" });
    running.resolve(update);
    expect(native.saveIdentity).not.toHaveBeenCalled();
  });

  it("returns success only after the atomic commit and passes recovery state internally", async () => {
    const { native, coordinator, update, snapshot } = fixture();
    snapshot.recoveryRequired = true;
    snapshot.sessionJSON = "null";
    native.acquire.mockResolvedValue({ ...snapshot, sessionJSON: null });
    const committed = deferred<number>();
    native.commit.mockReturnValue(committed.promise);
    let exposed = false;
    const result = coordinator
      .run("slot", async (tx) => {
        expect(tx.identity).toEqual(update.identity);
        expect(tx.session).toBeNull();
        expect(tx.recoveryRequired).toBe(true);
        await tx.checkpoint();
        return update;
      })
      .then((value) => {
        exposed = true;
        return value;
      });
    await vi.waitFor(() => expect(native.commit).toHaveBeenCalledOnce());
    expect(exposed).toBe(false);
    expect(native.commit).toHaveBeenCalledWith(
      "issuer/client/app",
      "slot",
      snapshot.leaseId,
      5,
      JSON.stringify(update.identity),
      JSON.stringify(update.session),
      null,
      false,
    );
    committed.resolve(6);
    await expect(result).resolves.toEqual({ kind: "authenticated" });
    expect(native.abandon).not.toHaveBeenCalled();
  });

  it("renews an active operation and stops heartbeats after commit", async () => {
    vi.useFakeTimers();
    const { native, coordinator, update } = fixture();
    const work = deferred<typeof update>();
    const result = coordinator.run("slot", async () => work.promise);
    await vi.advanceTimersByTimeAsync(20_000);
    expect(native.renew).toHaveBeenCalledTimes(2);
    work.resolve(update);
    await result;
    await vi.advanceTimersByTimeAsync(120_000);
    expect(native.renew).toHaveBeenCalledTimes(2);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("aborts network work on lease loss and never commits its late response", async () => {
    vi.useFakeTimers();
    const { native, coordinator, update } = fixture();
    native.renew.mockRejectedValue({
      code: "vault_lost_lease",
      message: "secret native details",
    });
    native.abandon.mockRejectedValue({ code: "vault_lost_lease" });
    const work = deferred<typeof update>();
    let signal: AbortSignal | undefined;
    const result = coordinator.run("slot", async (tx) => {
      signal = tx.signal;
      return work.promise;
    });
    const outcome = result.catch((error: unknown) => error);
    await vi.advanceTimersByTimeAsync(10_000);
    expect(signal?.aborted).toBe(true);
    work.resolve(update);
    await expect(outcome).resolves.toMatchObject({
      code: "vault_lost_lease",
      cleanup: "not-owned",
    });
    expect(native.commit).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("releases a cancelled operation even if transport ignores abort, and discards its late success", async () => {
    const { native, coordinator, update } = fixture();
    const network = deferred<typeof update>();
    const started = deferred<void>();
    const abort = new AbortController();
    const result = coordinator.run(
      "slot",
      () => {
        started.resolve();
        return network.promise;
      },
      abort.signal,
    );
    await started.promise;
    abort.abort();
    await expect(result).rejects.toMatchObject({
      code: "cancelled",
      cleanup: "complete",
    });
    expect(native.abandon).toHaveBeenCalledOnce();
    network.resolve(update);
    await network.promise;
    expect(native.commit).not.toHaveBeenCalled();
  });

  it("waits for an in-flight renewal before commit", async () => {
    vi.useFakeTimers();
    const { native, coordinator, update } = fixture();
    const renewal = deferred<void>();
    native.renew.mockReturnValue(renewal.promise);
    const work = deferred<typeof update>();
    const result = coordinator.run("slot", async () => work.promise);
    await vi.advanceTimersByTimeAsync(10_000);
    work.resolve(update);
    await vi.advanceTimersByTimeAsync(0);
    expect(native.commit).not.toHaveBeenCalled();
    renewal.resolve();
    await result;
    expect(native.commit).toHaveBeenCalledOnce();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("serializes explicit checkpoints and sanitizes operation failures", async () => {
    const { native, coordinator } = fixture();
    const first = deferred<void>();
    native.renew.mockReturnValueOnce(first.promise);
    const running = deferred<void>();
    const result = coordinator.run("slot", async (tx) => {
      const checks = [tx.checkpoint(), tx.checkpoint()];
      running.resolve();
      await Promise.all(checks);
      throw new Error("password=secret server response");
    });
    await running.promise;
    expect(native.renew).toHaveBeenCalledTimes(1);
    first.resolve();
    const error: unknown = await result.catch((value: unknown) => value);
    expect(error).toMatchObject({
      code: "operation_failed",
      cleanup: "complete",
    });
    expect(JSON.stringify(error)).not.toContain("secret");
    expect(String(error)).not.toContain("secret");
    expect(native.renew).toHaveBeenCalledTimes(2);
    expect(native.commit).not.toHaveBeenCalled();
  });

  it("does not acquire when already cancelled and releases acquisition cancelled in flight", async () => {
    const { native, coordinator, update, snapshot } = fixture();
    const abort = new AbortController();
    abort.abort();
    const operation = vi.fn(() => Promise.resolve(update));
    await expect(
      coordinator.run("slot", operation, abort.signal),
    ).rejects.toMatchObject({ code: "cancelled" });
    expect(native.acquire).not.toHaveBeenCalled();
    const acquired = deferred<typeof snapshot>();
    native.acquire.mockReturnValue(acquired.promise);
    const other = new AbortController();
    const result = coordinator.run("slot", operation, other.signal);
    other.abort();
    acquired.resolve(snapshot);
    await expect(result).rejects.toMatchObject({
      code: "cancelled",
      cleanup: "complete",
    });
    expect(operation).not.toHaveBeenCalled();
    expect(native.abandon).toHaveBeenCalledOnce();
  });

  it.each([true, false])(
    "cleans up a cancelled commit by its generation (still current: %s)",
    async (current) => {
      const { native, coordinator, update } = fixture();
      const committed = deferred<number>();
      native.commit.mockReturnValue(committed.promise);
      native.discard.mockResolvedValue(current);
      const abort = new AbortController();
      const result = coordinator.run(
        "slot",
        () => Promise.resolve(update),
        abort.signal,
      );
      await vi.waitFor(() => expect(native.commit).toHaveBeenCalledOnce());
      abort.abort();
      committed.resolve(6);
      await expect(result).rejects.toMatchObject({
        code: "cancelled",
        cleanup: current ? "complete" : "not-owned",
      });
      expect(native.discard).toHaveBeenCalledWith(
        "issuer/client/app",
        "slot",
        6,
      );
      expect(native.invalidate).not.toHaveBeenCalled();
      expect(native.abandon).not.toHaveBeenCalled();
    },
  );

  it("reports failed compensation without retaining newly received tokens", async () => {
    const { native, coordinator, update } = fixture();
    native.commit.mockResolvedValue(99);
    native.discard.mockRejectedValue({
      code: "vault_locked",
      message: "new-secret",
    });
    await expect(
      coordinator.run("slot", () => Promise.resolve(update)),
    ).rejects.toMatchObject({ code: "vault_corrupt", cleanup: "uncertain" });
  });

  it("clears a commit whose native success response was lost without clearing a newer generation", async () => {
    const { native, coordinator, update } = fixture();
    native.commit.mockRejectedValue(
      new Error("bridge disconnected after write"),
    );
    native.abandon.mockRejectedValue({ code: "vault_lost_lease" });
    native.discard.mockResolvedValue(false);
    await expect(
      coordinator.run("slot", () => Promise.resolve(update)),
    ).rejects.toMatchObject({
      code: "vault_storage_failed",
      cleanup: "not-owned",
    });
    expect(native.discard).toHaveBeenCalledWith("issuer/client/app", "slot", 6);
  });

  it("preserves cancellation classification when aborting fetch rejects with an untrusted error", async () => {
    const { coordinator } = fixture();
    const abort = new AbortController();
    const started = deferred<void>();
    const result = coordinator.run(
      "slot",
      (tx) =>
        new Promise<never>((_, reject) => {
          tx.signal.addEventListener(
            "abort",
            () => reject(new Error("raw network details")),
            { once: true },
          );
          started.resolve();
        }),
      abort.signal,
    );
    await started.promise;
    abort.abort();
    await expect(result).rejects.toMatchObject({
      code: "cancelled",
      cleanup: "complete",
    });
  });

  it.each([undefined, "vault_locked"])(
    "reports commit failure and cleanup outcome (%s)",
    async (cleanupFailure) => {
      const { native, coordinator, update } = fixture();
      native.commit.mockRejectedValue({
        code: "vault_storage_failed",
        message: "refresh=new-secret",
      });
      if (cleanupFailure)
        native.abandon.mockRejectedValue({ code: cleanupFailure });
      await expect(
        coordinator.run("slot", () => Promise.resolve(update)),
      ).rejects.toMatchObject({
        code: "vault_storage_failed",
        cleanup: cleanupFailure ? "uncertain" : "complete",
      });
      expect(native.discard).not.toHaveBeenCalled();
    },
  );

  it.each([
    "vault_busy",
    "vault_locked",
    "vault_unavailable",
    "untrusted-code",
  ])(
    "does not reinterpret native acquisition failure %s as missing state",
    async (code) => {
      const { native, coordinator, update } = fixture();
      native.acquire.mockRejectedValue({ code, message: "secret" });
      const operation = vi.fn(() => Promise.resolve(update));
      await expect(coordinator.run("slot", operation)).rejects.toMatchObject({
        code: code === "untrusted-code" ? "vault_storage_failed" : code,
      });
      expect(operation).not.toHaveBeenCalled();
      expect(native.abandon).not.toHaveBeenCalled();
    },
  );

  it("invalidates only the requested local slot and does not claim a failed logout succeeded", async () => {
    const { native, coordinator, update } = fixture();
    const a = deferred<typeof update>();
    const b = deferred<typeof update>();
    let txA: SlotTransaction | undefined;
    let txB: SlotTransaction | undefined;
    const first = coordinator.run("a", async (tx) => {
      txA = tx;
      return a.promise;
    });
    const second = coordinator.run("b", async (tx) => {
      txB = tx;
      return b.promise;
    });
    await vi.waitFor(() => expect(txB).toBeDefined());
    native.invalidate.mockRejectedValue({ code: "vault_locked" });
    await expect(coordinator.invalidate("a")).rejects.toMatchObject({
      code: "vault_locked",
    });
    expect(txA?.signal.aborted).toBe(true);
    expect(txB?.signal.aborted).toBe(false);
    a.resolve(update);
    b.resolve(update);
    await expect(first).rejects.toMatchObject({ code: "cancelled" });
    await expect(second).resolves.toEqual(update.result);
  });

  it.each(["[]", "null", "broken-json"])(
    "rejects corrupt stored payload %s before external work",
    async (sessionJSON) => {
      const { native, coordinator, update, snapshot } = fixture();
      native.acquire.mockResolvedValue({ ...snapshot, sessionJSON });
      const operation = vi.fn(() => Promise.resolve(update));
      await expect(coordinator.run("slot", operation)).rejects.toMatchObject({
        code: "vault_corrupt",
      });
      expect(operation).not.toHaveBeenCalled();
      expect(native.abandon).toHaveBeenCalledOnce();
    },
  );

  it("rejects nonserializable outgoing state and invalid coordinator settings", async () => {
    const { native, coordinator, update } = fixture();
    const circular: Record<string, unknown> = {};
    circular.self = circular;
    await expect(
      coordinator.run("slot", () =>
        Promise.resolve({ ...update, session: circular }),
      ),
    ).rejects.toMatchObject({ code: "vault_invalid_input" });
    expect(native.commit).not.toHaveBeenCalled();
    for (const duration of [4999, 120001, Number.NaN, 5000.5]) {
      expect(() =>
        createSessionCoordinator(native, {
          namespace: "issuer",
          leaseMilliseconds: duration,
        }),
      ).toThrow(FirstPartyClientError);
    }
  });
});
