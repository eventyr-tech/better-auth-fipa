import { randomBytes } from "node:crypto";
import { createMemorySessionVault } from "../test-fixtures/session-vault.ts";
import type { SessionVaultNative } from "./session-coordinator.ts";
import { afterEach, describe, expect, it, vi } from "vitest";

const config = {
  issuer: "https://issuer.example/api/auth",
  clientId: "mobile",
  applicationId: "TEAM.application",
  environment: "production" as const,
  scopes: ["offline_access"],
  resources: [],
};
async function load(
  platform: string,
  absent?: string,
  modules: Record<string, unknown> = {},
) {
  const storage = new Map<string, string>();
  vi.doMock("@react-native-async-storage/async-storage", () => ({
    default: {
      getItem: (key: string) => Promise.resolve(storage.get(key) ?? null),
      setItem: (key: string, value: string) => {
        storage.set(key, value);
        return Promise.resolve();
      },
    },
  }));
  vi.resetModules();
  const get = vi.fn((name: string) =>
    name === absent ? null : (modules[name] ?? {}),
  );
  vi.doMock("react-native", () => ({
    Platform: { OS: platform },
    TurboModuleRegistry: { get },
  }));
  return { ...(await import("../first-party.ts")), get };
}
afterEach(() => {
  vi.doUnmock("react-native");
  vi.doUnmock("@react-native-async-storage/async-storage");
  vi.resetModules();
});

describe("default native first-party entry", () => {
  it.each(["web", "windows"])(
    "does not claim support or use a JS fallback on %s",
    async (platform) => {
      const { createNativeFirstPartyClient } = await load(platform);
      expect(() => createNativeFirstPartyClient(config)).toThrow(
        expect.objectContaining({ code: "unsupported_platform" }),
      );
    },
  );
  it.each([
    "DeviceAttestationAppAttest",
    "DeviceAttestationFirstPartyTransport",
    "DeviceAttestationSessionVault",
  ])("requires the compiled %s module", async (absent) => {
    const { createNativeFirstPartyClient } = await load("ios", absent);
    expect(() => createNativeFirstPartyClient(config)).toThrow(
      expect.objectContaining({ code: "native_unavailable" }),
    );
  });
  it("composes only the installed native modules without creating keys on construction", async () => {
    const { createNativeFirstPartyClient, get } = await load("ios");
    const sdk = createNativeFirstPartyClient(config);
    expect(typeof sdk.accounts.create).toBe("function");
    expect(typeof sdk.fetch).toBe("function");
    expect(get.mock.calls.map(([name]) => name).sort()).toEqual(
      [
        "DeviceAttestationAppAttest",
        "DeviceAttestationAndroidIntegrity",
        "DeviceAttestationAndroidVaultRecovery",
        "DeviceAttestationFirstPartyTransport",
        "DeviceAttestationSessionVault",
      ].sort(),
    );
  });
  it("rejects invalid configuration before using any native module", async () => {
    const { createNativeFirstPartyClient } = await load("ios");
    expect(() =>
      createNativeFirstPartyClient({
        ...config,
        issuer: "http://remote.example",
      }),
    ).toThrow(expect.objectContaining({ code: "invalid_configuration" }));
  });
});

describe("Android native first-party entry", () => {
  const android = {
    ...config,
    applicationId: "com.example.app",
    android: { cloudProjectNumber: "123456789", securityLevel: "tee" as const },
  };
  it("composes the native Android lifecycle and storage recovery", async () => {
    const { createNativeFirstPartyClient } = await load("android");
    const sdk = createNativeFirstPartyClient(android);
    expect(typeof sdk.start).toBe("function");
    expect("importIOSKeys" in sdk.accounts).toBe(false);
    expect(
      "storage" in sdk &&
        typeof (sdk.storage as { prepareRecovery: unknown }).prepareRecovery,
    ).toBe("function");
  });
  it.each([
    "DeviceAttestationAndroidIntegrity",
    "DeviceAttestationAndroidVaultRecovery",
    "DeviceAttestationFirstPartyTransport",
    "DeviceAttestationSessionVault",
  ])("requires installed %s", async (absent) => {
    const { createNativeFirstPartyClient } = await load("android", absent);
    expect(() => createNativeFirstPartyClient(android)).toThrow(
      expect.objectContaining({ code: "native_unavailable" }),
    );
  });
  it.each([
    config,
    { ...android, environment: "development" as const },
    { ...android, android: { ...android.android, cloudProjectNumber: "" } },
  ])("rejects absent or unsupported Android configuration", async (input) => {
    const { createNativeFirstPartyClient } = await load("android");
    expect(() => createNativeFirstPartyClient(input)).toThrow(
      expect.objectContaining({ code: "invalid_configuration" }),
    );
  });
  it("does not require the iOS-only bridge", async () => {
    const { createNativeFirstPartyClient } = await load(
      "android",
      "DeviceAttestationAppAttest",
    );
    expect(() => createNativeFirstPartyClient(android)).not.toThrow();
  });
});

it.each([
  "DeviceAttestationAndroidIntegrity",
  "DeviceAttestationAndroidVaultRecovery",
])("iOS does not require the Android-only %s bridge", async (absent) => {
  const { createNativeFirstPartyClient } = await load("ios", absent);
  expect(() => createNativeFirstPartyClient(config)).not.toThrow();
});

describe("explicit development selection", () => {
  const developmentConfig = {
    ...config,
    environment: "development" as const,
    provider: "development" as const,
  };
  it("does not require App Attest when explicitly opted in", async () => {
    const { createNativeFirstPartyClient } = await load(
      "ios",
      "DeviceAttestationAppAttest",
    );
    expect(() => createNativeFirstPartyClient(developmentConfig)).not.toThrow();
  });
  it.each(["ios", "android"])(
    "uses shared modules on %s without hardware attestation",
    async (os) => {
      const f = nativeTestModules();
      const { createNativeFirstPartyClient } = await load(
        os,
        "DeviceAttestationAppAttest",
        f.modules,
      );
      const sdk = createNativeFirstPartyClient(developmentConfig);
      expect(await sdk.accounts.create()).toHaveProperty("slotId");
      expect("importIOSKeys" in sdk.accounts).toBe(false);
    },
  );
  it.each(["ios", "android"])(
    "rejects production development configuration on %s",
    async (os) => {
      const { createNativeFirstPartyClient } = await load(os);
      expect(() =>
        createNativeFirstPartyClient({
          ...developmentConfig,
          environment: "production",
        }),
      ).toThrow(expect.objectContaining({ code: "invalid_configuration" }));
    },
  );
  it.each([
    ["http://eventyr.localhost:3000/api/auth", false, false],
    ["http://eventyr.localhost:3000/api/auth", true, true],
    ["http://remote.example/api/auth", true, false],
    ["https://remote.example/api/auth", false, true],
  ] as const)(
    "keeps the transport opt-in for %s (%s)",
    async (issuer, allowInsecureLoopback, allowed) => {
      const { createNativeFirstPartyClient } = await load("ios");
      const create = () =>
        createNativeFirstPartyClient({
          ...developmentConfig,
          issuer,
          allowInsecureLoopback,
        });
      if (allowed) expect(create).not.toThrow();
      else
        expect(create).toThrow(
          expect.objectContaining({ code: "invalid_configuration" }),
        );
    },
  );
});

function nativeTestModules() {
  const vaults = new Map<string, ReturnType<typeof createMemorySessionVault>>();
  const nativeVault = new Proxy({} as SessionVaultNative, {
    get(_target, name: keyof SessionVaultNative) {
      return (...args: unknown[]) => {
        const key = JSON.stringify(args.slice(0, 2));
        if (!vaults.has(key)) vaults.set(key, createMemorySessionVault());
        const source = vaults.get(key)!.native;
        return Reflect.apply(source[name], source, args) as unknown;
      };
    },
  });
  const hardware = {
    getOrCreateKey: vi.fn(() =>
      Promise.reject(
        Object.assign(new Error("private details"), {
          code: "app_attest_unavailable",
        }),
      ),
    ),
  };
  return {
    hardware,
    modules: {
      DeviceAttestationSessionVault: nativeVault,
      DeviceAttestationFirstPartyTransport: {
        prepareDpop: () =>
          Promise.resolve(randomBytes(32).toString("base64url")),
        randomToken: () =>
          Promise.resolve(randomBytes(32).toString("base64url")),
      },
      DeviceAttestationAppAttest: hardware,
    },
  };
}
it("never falls back after hardware failure and keeps catalogs separate even with the same storageNamespace", async () => {
  const f = nativeTestModules();
  const { createNativeFirstPartyClient } = await load(
    "ios",
    undefined,
    f.modules,
  );
  const settings = {
    ...config,
    environment: "development" as const,
    storageNamespace: "same",
  };
  const hardware = createNativeFirstPartyClient(settings);
  const development = createNativeFirstPartyClient({
    ...settings,
    provider: "development",
  });
  const account = await hardware.accounts.create();
  expect(await development.accounts.list()).toEqual([]);
  await expect(hardware.start(account.slotId)).rejects.toMatchObject({
    code: "app_attest_unavailable",
  });
  expect(f.hardware.getOrCreateKey).toHaveBeenCalledOnce();
  const developmentAccount = await development.accounts.create();
  expect(developmentAccount.slotId).not.toBe(account.slotId);
  expect(await hardware.accounts.list()).toHaveLength(1);
  expect(await development.accounts.list()).toHaveLength(1);
  expect("importIOSKeys" in development.accounts).toBe(false);
});
