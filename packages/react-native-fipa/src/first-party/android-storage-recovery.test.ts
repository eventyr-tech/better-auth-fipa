import { describe, expect, it, vi } from "vitest";
import { createAndroidStorageRecovery } from "./android-storage-recovery.ts";
import type { Spec as Recovery } from "../NativeAndroidVaultRecovery.ts";

const token = "x".repeat(43);
function fixture() {
  const native = {
    prepare: vi.fn<Recovery["prepare"]>(() =>
      Promise.resolve({
        token,
        inProgress: false,
      }),
    ),
    recover: vi.fn<Recovery["recover"]>(() => Promise.resolve(false)),
  };
  return { native, storage: createAndroidStorageRecovery(native) };
}

describe("explicit Android whole-vault recovery", () => {
  it("exposes global scope and never confirms recovery during preparation", async () => {
    const { native, storage } = fixture();
    await expect(storage.prepareRecovery()).resolves.toEqual({
      confirmationToken: token,
      scope: "all-local-native-accounts",
      kind: "vault-key-lost",
    });
    expect(native.recover).not.toHaveBeenCalled();
    await expect(
      storage.recover({
        confirmationToken: token,
        discardAllLocalAccounts: true,
      }),
    ).resolves.toEqual({
      kind: "fresh-login-required",
      scope: "all-local-native-accounts",
      signingKeys: "retained",
      remoteRevocation: "unconfirmed",
      alreadyCompleted: false,
    });
    expect(native.recover).toHaveBeenCalledExactlyOnceWith(token);
  });

  it("exposes resumable recovery and completed retries without hiding native results", async () => {
    const { native, storage } = fixture();
    native.prepare.mockResolvedValue({ token, inProgress: true });
    native.recover.mockResolvedValue(true);
    await expect(storage.prepareRecovery()).resolves.toMatchObject({
      kind: "recovery-in-progress",
    });
    await expect(
      storage.recover({
        confirmationToken: token,
        discardAllLocalAccounts: true,
      }),
    ).resolves.toMatchObject({
      alreadyCompleted: true,
      remoteRevocation: "unconfirmed",
    });
    native.prepare.mockResolvedValue(null);
    await expect(storage.prepareRecovery()).resolves.toBeNull();
  });

  it.each([
    null,
    {},
    { confirmationToken: token },
    { confirmationToken: token, discardAllLocalAccounts: false },
    { confirmationToken: token, discardAllLocalAccounts: "true" },
    { confirmationToken: "bad", discardAllLocalAccounts: true },
    { confirmationToken: 42, discardAllLocalAccounts: true },
  ])(
    "requires explicit confirmation before invoking native recovery: %j",
    async (input) => {
      const { native, storage } = fixture();
      await expect(storage.recover(input as never)).rejects.toMatchObject({
        code: "invalid_request",
      });
      expect(native.recover).not.toHaveBeenCalled();
    },
  );

  it.each([
    "vault_locked",
    "vault_unavailable",
    "vault_key_lost",
    "vault_recovery_pending",
    "vault_recovery_changed",
  ])(
    "preserves safe recovery code %s without leaking native details",
    async (code) => {
      const { native, storage } = fixture();
      const failure = { code, message: "private alias and token", token };
      native.prepare.mockRejectedValue(failure);
      native.recover.mockRejectedValue(failure);
      for (const action of [
        () => storage.prepareRecovery(),
        () =>
          storage.recover({
            confirmationToken: token,
            discardAllLocalAccounts: true,
          }),
      ]) {
        const error = await action().catch((e: unknown) => e);
        expect(error).toMatchObject({ code });
        expect(JSON.stringify(error)).not.toContain(token);
        expect(String(error)).not.toContain("private alias");
      }
    },
  );

  it.each([
    undefined,
    {},
    { token: "bad", inProgress: false },
    { token, inProgress: "true" },
  ])("rejects malformed native tickets: %j", async (ticket) => {
    const { native, storage } = fixture();
    native.prepare.mockResolvedValue(ticket as never);
    await expect(storage.prepareRecovery()).rejects.toMatchObject({
      code: "vault_storage_failed",
    });
    expect(native.recover).not.toHaveBeenCalled();
  });

  it("does not report success for a malformed native completion or unknown error", async () => {
    const { native, storage } = fixture();
    native.recover.mockResolvedValue(undefined as never);
    await expect(
      storage.recover({
        confirmationToken: token,
        discardAllLocalAccounts: true,
      }),
    ).rejects.toMatchObject({ code: "vault_storage_failed" });
    native.prepare.mockRejectedValue(new Error("sensitive"));
    await expect(storage.prepareRecovery()).rejects.toMatchObject({
      code: "vault_storage_failed",
    });
  });
});
