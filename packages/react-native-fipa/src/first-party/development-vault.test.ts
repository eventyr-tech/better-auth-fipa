import { randomBytes } from "node:crypto";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { createDevelopmentVault } from "./development-vault.ts";
const saved = new Map<string, string>();
const write = vi.fn((key: string, value: string) => {
  saved.set(key, value);
  return Promise.resolve();
});
vi.mock("@react-native-async-storage/async-storage", () => ({
  default: {
    getItem: (key: string) => Promise.resolve(saved.get(key) ?? null),
    setItem: (key: string, value: string) => write(key, value),
  },
}));
const create = () =>
  createDevelopmentVault(() =>
    Promise.resolve(randomBytes(32).toString("base64url")),
  );
beforeEach(() => {
  saved.clear();
  write.mockClear();
});
afterEach(() => vi.useRealTimers());
it("persists leases across clients, serializes acquisition and fences an expired writer", async () => {
  vi.useFakeTimers();
  const a = create(),
    b = create();
  const first = await a.acquire("dev", "slot", "when-unlocked", 5000, false);
  await a.saveIdentity(
    "dev",
    "slot",
    first.leaseId,
    first.generation,
    '{"key":"reference"}',
  );
  await expect(
    b.acquire("dev", "slot", "when-unlocked", 5000, false),
  ).rejects.toMatchObject({ code: "vault_busy" });
  vi.advanceTimersByTime(5001);
  const second = await b.acquire("dev", "slot", "when-unlocked", 5000, false);
  expect(second).toMatchObject({
    identityJSON: '{"key":"reference"}',
    sessionJSON: null,
    recoveryRequired: true,
  });
  await expect(
    a.commit(
      "dev",
      "slot",
      first.leaseId,
      first.generation,
      null,
      "stale",
      null,
      false,
    ),
  ).rejects.toMatchObject({ code: "vault_lost_lease" });
  await b.renew("dev", "slot", second.leaseId, second.generation, 5000);
  await b.release("dev", "slot", second.leaseId, second.generation);
  const races = await Promise.allSettled([
    a.acquire("dev", "slot", "when-unlocked", 5000, false),
    b.acquire("dev", "slot", "when-unlocked", 5000, false),
  ]);
  expect(races.map((r) => r.status).sort()).toEqual(["fulfilled", "rejected"]);
});
it("cancellation preserves prior access, and stale compensation cannot erase a newer login", async () => {
  const v = create();
  let s = await v.acquire("dev", "slot", "when-unlocked", 5000, false);
  await v.commit(
    "dev",
    "slot",
    s.leaseId,
    s.generation,
    "{}",
    "active",
    "active",
    false,
  );
  s = await v.acquire("dev", "slot", "when-unlocked", 5000, true);
  await v.commit(
    "dev",
    "slot",
    s.leaseId,
    s.generation,
    "{}",
    "interaction",
    "active",
    true,
  );
  expect(await v.cancelInteraction("dev", "slot", "when-unlocked")).toEqual({
    sessionJSON: "interaction",
    cancelled: true,
  });
  s = await v.acquire("dev", "slot", "when-unlocked", 5000, false);
  expect(s.sessionJSON).toBe("active");
  await expect(
    v.cancelInteraction("dev", "slot", "when-unlocked"),
  ).rejects.toMatchObject({ code: "vault_busy" });
  const generation = await v.commit(
    "dev",
    "slot",
    s.leaseId,
    s.generation,
    "{}",
    "new",
    "new",
    false,
  );
  expect(await v.discard("dev", "slot", generation - 1)).toBe(false);
  expect(await v.discard("dev", "slot", generation)).toBe(true);
  expect(await v.cancelInteraction("dev", "slot", "when-unlocked")).toEqual({
    sessionJSON: null,
    cancelled: false,
  });
});
it("propagates storage failure, rejects corruption and isolates namespaces", async () => {
  const v = create();
  write.mockRejectedValueOnce(new Error("storage offline"));
  await expect(
    v.acquire("dev", "slot", "when-unlocked", 5000, false),
  ).rejects.toThrow();
  const s = await v.acquire("dev", "slot", "when-unlocked", 5000, false);
  await v.abandon("dev", "slot", s.leaseId, s.generation);
  const other = await v.acquire(
    "different",
    "slot",
    "when-unlocked",
    5000,
    false,
  );
  expect(other.generation).toBe(0);
  for (const key of saved.keys()) saved.set(key, "not-json");
  await expect(
    v.acquire("dev", "slot", "when-unlocked", 5000, false),
  ).rejects.toMatchObject({ code: "vault_corrupt" });
});
