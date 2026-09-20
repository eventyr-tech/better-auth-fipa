import { describe, expect, it, vi } from "vitest";
import { readRetainedIOSKeys } from "./ios-retained-keys.ts";
import { createIOSKeyPorts } from "./ios-keys.ts";

const reference = {
  keyIdStoragePrefix: "EventyrAppAttestKeyId.v2.",
  credentialScope: "retained-account-scope",
  dpopAlias: "io.eventyr.mobile.dpop.user.v2.retained-account-scope",
};
function fixture() {
  return {
    appAttest: { getKey: vi.fn().mockResolvedValue("retained-apple-key") },
    dpop: { inspectDpop: vi.fn().mockResolvedValue("j".repeat(43)) },
  };
}
describe("retained iOS key inspection", () => {
  it("reads exact legacy locations without treating them as registration or account evidence", async () => {
    const native = fixture();
    const identity = await readRetainedIOSKeys(reference, native);
    expect(native.appAttest.getKey).toHaveBeenCalledWith(
      reference.keyIdStoragePrefix,
      reference.credentialScope,
    );
    expect(native.dpop.inspectDpop).toHaveBeenCalledWith(reference.dpopAlias);
    expect(identity).toEqual({
      version: 1,
      dpopAlias: reference.dpopAlias,
      dpopJkt: "j".repeat(43),
      providerStoragePrefix: reference.keyIdStoragePrefix,
      providerScope: reference.credentialScope,
      providerKeyId: "retained-apple-key",
      providerRegistration: "unknown",
    });
    expect(identity).not.toHaveProperty("account");
  });
  it("requires recovery if the App Attest reference is absent", async () => {
    const native = fixture();
    native.appAttest.getKey.mockResolvedValue(null);
    await expect(readRetainedIOSKeys(reference, native)).rejects.toMatchObject({
      code: "registration_recovery_required",
    });
    expect(native.dpop.inspectDpop).not.toHaveBeenCalled();
  });
  it.each(["key_missing", "key_locked", "key_unavailable"])(
    "never treats %s as permission to generate a replacement",
    async (code) => {
      const native = fixture();
      native.dpop.inspectDpop.mockRejectedValue({ code, message: "secret" });
      const result = await readRetainedIOSKeys(reference, native).catch(
        (error: unknown) => error,
      );
      expect(result).toMatchObject({
        code:
          code === "key_missing"
            ? "registration_recovery_required"
            : "operation_failed",
      });
      expect(String(result)).not.toContain("secret");
    },
  );
  it("rejects token or subject import and invalid locations before native access", async () => {
    const native = fixture();
    for (const input of [
      { ...reference, refreshToken: "legacy-secret" },
      { ...reference, subject: "guessed-user" },
      { ...reference, credentialScope: "" },
    ])
      await expect(readRetainedIOSKeys(input, native)).rejects.toMatchObject({
        code: "invalid_request",
      });
    expect(native.appAttest.getKey).not.toHaveBeenCalled();
  });
  it("rejects malformed native key material", async () => {
    const native = fixture();
    native.dpop.inspectDpop.mockResolvedValue("invalid");
    await expect(readRetainedIOSKeys(reference, native)).rejects.toMatchObject({
      code: "invalid_response",
    });
  });
  it("uses the retained prefix for availability and confirmed retirement", async () => {
    const native = fixture();
    const identity = await readRetainedIOSKeys(reference, native);
    const removeKey = vi.fn().mockResolvedValue(undefined);
    const removeDpop = vi.fn().mockResolvedValue(undefined);
    const keys = createIOSKeyPorts(
      {
        issuer: "https://issuer.example/auth",
        clientId: "mobile",
        applicationId: "TEAM.app",
        environment: "production",
        keyIdStoragePrefix: "new-default.",
        aliases: () => Promise.reject(new Error("must not prepare")),
      },
      {
        appAttest: {
          ...native.appAttest,
          removeKey,
          getOrCreateKey: vi.fn(),
          generateEvidence: vi.fn(),
        },
        dpop: {
          ...native.dpop,
          removeDpop,
          prepareDpop: vi.fn(),
          signDpop: vi.fn(),
        },
        send: vi.fn(),
      },
    );
    await keys.assertAvailable(identity);
    expect(native.appAttest.getKey).toHaveBeenLastCalledWith(
      reference.keyIdStoragePrefix,
      reference.credentialScope,
    );
    await keys.remove({ ...identity, retired: true });
    expect(removeKey).toHaveBeenCalledWith(
      reference.keyIdStoragePrefix,
      reference.credentialScope,
      identity.providerKeyId,
    );
    expect(removeDpop).toHaveBeenCalledWith(
      reference.dpopAlias,
      identity.dpopJkt,
    );
  });
});
