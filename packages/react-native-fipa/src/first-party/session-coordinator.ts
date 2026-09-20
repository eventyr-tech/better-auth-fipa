import type { Spec } from "../NativeSessionVault.ts";
import { FirstPartyClientError, vaultError } from "./errors.ts";

/** Shared bridge contract implemented by the iOS and Android native vaults. */
export type SessionVaultNative = Pick<
  Spec,
  | "acquire"
  | "commit"
  | "renew"
  | "abandon"
  | "invalidate"
  | "discard"
  | "saveIdentity"
  | "clearSession"
  | "release"
  | "cancelInteraction"
>;
type RecordValue = Record<string, unknown> | null;
export interface SlotTransaction {
  readonly identity: RecordValue;
  readonly session: RecordValue;
  readonly recoveryRequired: boolean;
  readonly signal: AbortSignal;
  /** Recheck ownership before starting another external side effect. */
  checkpoint(): Promise<void>;
  /** Durable key-registration progress. Must complete before an irreversible key operation. */
  saveIdentity(identity: Record<string, unknown>): Promise<void>;
  /** Persist sign-out before remote revocation without releasing the slot. */
  clearSession(): Promise<void>;
  /** Only for application requests that cannot rotate session capabilities. */
  readOnly(): void;
}
interface SlotCommit<T> {
  identity: RecordValue;
  session: RecordValue;
  recoverySession?: RecordValue;
  hasInteraction?: boolean;
  /** Kept inside the coordinator until durable commit succeeds. */
  result: T;
}

/**
 * Internal orchestration primitive, not a custom AsyncStorage adapter. The
 * native implementation owns exclusion across JS runtimes and late-write
 * fencing. A pending UI interaction must be committed before returning to UI;
 * this lease covers an individual operation, never human think time.
 */
export function createSessionCoordinator(
  native: SessionVaultNative,
  options: {
    namespace: string;
    accessibility?: "when-unlocked" | "after-first-unlock";
    leaseMilliseconds?: number;
  },
) {
  const { namespace } = options;
  const accessibility = options.accessibility ?? "when-unlocked";
  const duration = options.leaseMilliseconds ?? 30_000;
  if (
    !namespace ||
    !Number.isSafeInteger(duration) ||
    duration < 5000 ||
    duration > 120_000 ||
    !["when-unlocked", "after-first-unlock"].includes(accessibility)
  )
    throw new FirstPartyClientError("vault_invalid_input");

  const active = new Map<string, Set<AbortController>>();
  const recoverable = new WeakSet<AbortController>();
  const settlements = new WeakMap<AbortController, Promise<void>>();
  async function call<T>(operation: () => Promise<T>): Promise<T> {
    try {
      return await operation();
    } catch (error) {
      throw vaultError(error);
    }
  }

  return {
    async run<T>(
      slot: string,
      operation: (transaction: SlotTransaction) => Promise<SlotCommit<T>>,
      signal?: AbortSignal,
      policy: { preserveSession?: boolean } = {},
    ): Promise<T> {
      if (signal?.aborted) throw new FirstPartyClientError("cancelled");
      const controller = new AbortController();
      if (policy.preserveSession) recoverable.add(controller);
      let settled!: () => void;
      settlements.set(
        controller,
        new Promise<void>((resolve) => {
          settled = resolve;
        }),
      );
      const controllers = active.get(slot) ?? new Set<AbortController>();
      controllers.add(controller);
      active.set(slot, controllers);
      const abort = () => controller.abort();
      signal?.addEventListener("abort", abort, { once: true });
      let snapshot:
        Awaited<ReturnType<SessionVaultNative["acquire"]>> | undefined;
      let timer: ReturnType<typeof setTimeout> | undefined;
      let stopped = false;
      let readOnly = false;
      let journaled = false;
      let failure: FirstPartyClientError | undefined;
      let committedGeneration: number | undefined;
      let commitAttemptGeneration: number | undefined;
      // Resolve this chain even on failure so neither timers nor concurrent
      // checkpoints leave an unhandled rejection or a late renew after commit.
      let pending = Promise.resolve();
      const ensureActive = () => {
        if (failure) throw failure;
        if (controller.signal.aborted || stopped)
          throw new FirstPartyClientError("cancelled");
      };
      const checkpoint = async () => {
        ensureActive();
        const current = snapshot!;
        const work = pending.then(async () => {
          ensureActive();
          await call(() =>
            native.renew(
              namespace,
              slot,
              current.leaseId,
              current.generation,
              duration,
            ),
          );
        });
        pending = work.catch((error: unknown) => {
          failure =
            error instanceof FirstPartyClientError
              ? error
              : new FirstPartyClientError("vault_storage_failed");
          controller.abort();
        });
        await pending;
        if (failure) throw failure;
      };
      const journal = async (
        write: (current: NonNullable<typeof snapshot>) => Promise<void>,
      ) => {
        ensureActive();
        if (readOnly) throw new FirstPartyClientError("invalid_state");
        journaled = true;
        const current = snapshot!;
        const work = pending.then(async () => {
          ensureActive();
          await call(() => write(current));
          ensureActive();
        });
        pending = work.catch((error: unknown) => {
          failure =
            error instanceof FirstPartyClientError
              ? error
              : new FirstPartyClientError("vault_storage_failed");
          controller.abort();
        });
        await pending;
        if (failure) throw failure;
      };
      const saveIdentity = async (identity: Record<string, unknown>) => {
        const json = encode(identity)!;
        await journal((current) =>
          native.saveIdentity(
            namespace,
            slot,
            current.leaseId,
            current.generation,
            json,
          ),
        );
      };
      const clearSession = () =>
        journal((current) =>
          native.clearSession(
            namespace,
            slot,
            current.leaseId,
            current.generation,
          ),
        );
      const schedule = () => {
        timer = setTimeout(
          () => {
            void checkpoint().then(
              () => {
                if (!stopped) schedule();
              },
              () => {
                /* failure and abort are recorded by checkpoint */
              },
            );
          },
          Math.floor(duration / 3),
        );
      };
      const stopRenewal = async () => {
        if (timer !== undefined) clearTimeout(timer);
        // Prevent rescheduling without cancelling a renew already in flight.
        stopped = true;
        await pending;
        if (timer !== undefined) clearTimeout(timer);
      };
      try {
        snapshot = await call(() =>
          native.acquire(
            namespace,
            slot,
            accessibility,
            duration,
            policy.preserveSession === true,
          ),
        );
        if (
          !snapshot ||
          !/^[A-Za-z0-9_-]{43}$/.test(snapshot.leaseId) ||
          !Number.isSafeInteger(snapshot.generation) ||
          snapshot.generation < 0 ||
          typeof snapshot.recoveryRequired !== "boolean"
        )
          throw new FirstPartyClientError("vault_corrupt");
        ensureActive();
        const identity = decode(snapshot.identityJSON);
        const session = decode(snapshot.sessionJSON);
        schedule();
        const update = await new Promise<SlotCommit<T>>((resolve, reject) => {
          const interrupted = () =>
            reject(failure ?? new FirstPartyClientError("cancelled"));
          controller.signal.addEventListener("abort", interrupted, {
            once: true,
          });
          // Observe late completion/rejection even when cancellation has already
          // won. A transport ignoring AbortSignal must not keep the slot locked
          // or allow its eventual response to become a committed session.
          void Promise.resolve()
            .then(() => {
              ensureActive();
              return operation({
                identity,
                session,
                recoveryRequired: snapshot!.recoveryRequired,
                signal: controller.signal,
                checkpoint,
                saveIdentity,
                clearSession,
                readOnly: () => {
                  ensureActive();
                  if (journaled)
                    throw new FirstPartyClientError("invalid_state");
                  readOnly = true;
                },
              });
            })
            .then(
              (value) => {
                controller.signal.removeEventListener("abort", interrupted);
                resolve(value);
              },
              (error: unknown) => {
                controller.signal.removeEventListener("abort", interrupted);
                reject(
                  error instanceof FirstPartyClientError
                    ? error
                    : new FirstPartyClientError("operation_failed"),
                );
              },
            );
        });
        // Serialize through any pending heartbeat before checking cancellation.
        if (timer !== undefined) clearTimeout(timer);
        await pending;
        ensureActive();
        await stopRenewal();
        if (failure) throw failure;
        if (controller.signal.aborted)
          throw new FirstPartyClientError("cancelled");
        const identityJSON = encode(update.identity);
        const sessionJSON = encode(update.session);
        if (
          readOnly &&
          (!sameRecord(identityJSON, encode(identity)) ||
            !sameRecord(sessionJSON, encode(session)))
        )
          throw new FirstPartyClientError("invalid_state");
        commitAttemptGeneration = snapshot.generation + 1;
        const committed = await call(() =>
          native.commit(
            namespace,
            slot,
            snapshot!.leaseId,
            snapshot!.generation,
            identityJSON,
            sessionJSON,
            encode(update.recoverySession ?? null),
            update.hasInteraction === true,
          ),
        );
        committedGeneration = snapshot.generation + 1;
        if (committed !== snapshot.generation + 1)
          throw new FirstPartyClientError("vault_corrupt");
        // Cancellation concurrent with a successful commit must not expose the
        // result. The invalidation below fences that newly committed generation.
        if (controller.signal.aborted) {
          throw new FirstPartyClientError("cancelled");
        }
        return update.result;
      } catch (error) {
        await stopRenewal();
        const safe =
          failure ??
          (error instanceof FirstPartyClientError
            ? error
            : new FirstPartyClientError(
                controller.signal.aborted ? "cancelled" : "operation_failed",
              ));
        controller.abort();
        let cleanup: "complete" | "not-owned" | "uncertain" = "not-owned";
        if (snapshot) {
          try {
            if (committedGeneration !== undefined && readOnly) {
              // This commit changed no capabilities. Cancellation must not turn
              // an ordinary resource request into account logout.
              cleanup = "complete";
            } else if (committedGeneration !== undefined) {
              cleanup = (await call(() =>
                native.discard(namespace, slot, committedGeneration!),
              ))
                ? "complete"
                : "not-owned";
            } else if (readOnly) {
              await call(() =>
                native.release(
                  namespace,
                  slot,
                  snapshot!.leaseId,
                  snapshot!.generation,
                ),
              );
              cleanup = "complete";
            } else {
              await call(() =>
                native.abandon(
                  namespace,
                  slot,
                  snapshot!.leaseId,
                  snapshot!.generation,
                ),
              );
              cleanup = "complete";
            }
          } catch (cleanupError) {
            cleanup =
              cleanupError instanceof FirstPartyClientError &&
              cleanupError.code === "vault_lost_lease"
                ? "not-owned"
                : "uncertain";
            // A rejected bridge result can be ambiguous after a native write.
            // If its lease was consumed, clear only that candidate generation.
            if (
              cleanup === "not-owned" &&
              commitAttemptGeneration !== undefined
            ) {
              try {
                cleanup = (await call(() =>
                  native.discard(namespace, slot, commitAttemptGeneration!),
                ))
                  ? "complete"
                  : "not-owned";
              } catch {
                cleanup = "uncertain";
              }
            }
          }
        }
        throw new FirstPartyClientError(safe.code, cleanup);
      } finally {
        settled();
        if (timer !== undefined) clearTimeout(timer);
        stopped = true;
        signal?.removeEventListener("abort", abort);
        controllers.delete(controller);
        if (!controllers.size && active.get(slot) === controllers)
          active.delete(slot);
      }
    },
    async invalidate(slot: string): Promise<void> {
      // Abort in-process work promptly even if storage is locked. The rejected
      // invalidation remains visible; it must not be reported as durable logout.
      for (const controller of active.get(slot) ?? []) controller.abort();
      await call(() => native.invalidate(namespace, slot, accessibility));
    },
    async cancelInteraction(
      slot: string,
    ): Promise<{ session: RecordValue; cancelled: boolean }> {
      // Let native storage linearize cancellation before abort cleanup can erase
      // the old step needed for best-effort server cancellation.
      const controllers = [...(active.get(slot) ?? [])];
      const result = await call(() =>
        native.cancelInteraction(namespace, slot, accessibility),
      );
      const pending: Promise<void>[] = [];
      for (const controller of controllers)
        if (recoverable.has(controller)) {
          controller.abort();
          pending.push(settlements.get(controller)!);
        }
      await Promise.all(pending);
      return {
        session: decode(result.sessionJSON),
        cancelled: result.cancelled,
      };
    },
  };
}

function decode(value: string | null): RecordValue {
  if (value === null) return null;
  try {
    if (typeof value !== "string") throw new Error();
    const parsed: unknown = JSON.parse(value);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed))
      throw new Error();
    return parsed as Record<string, unknown>;
  } catch {
    throw new FirstPartyClientError("vault_corrupt");
  }
}
function encode(value: RecordValue): string | null {
  if (value === null) return null;
  try {
    if (typeof value !== "object" || Array.isArray(value)) throw new Error();
    const encoded = JSON.stringify(value);
    decode(encoded);
    return encoded;
  } catch {
    throw new FirstPartyClientError("vault_invalid_input");
  }
}

// Schema parsing may reorder object properties without changing the record.
// Compare JSON values, retaining array order and every persisted field.
function sameRecord(left: string | null, right: string | null): boolean {
  if (left === right) return true;
  if (left === null || right === null) return false;
  const canonical = (json: string) =>
    JSON.stringify(JSON.parse(json), (_key, value: unknown) =>
      value && typeof value === "object" && !Array.isArray(value)
        ? Object.fromEntries(
            Object.entries(value).sort(([a], [b]) => a.localeCompare(b)),
          )
        : value,
    );
  return canonical(left) === canonical(right);
}
