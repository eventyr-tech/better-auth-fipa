import { afterEach, describe, expect, it, vi } from "vitest";

const config = {
  issuer: "https://issuer.example/api/auth",
  clientId: "mobile",
  applicationId: "TEAM.application",
  environment: "production" as const,
  scopes: ["offline_access"],
  resources: [],
};
async function load(platform: string, absent?: string) {
  vi.resetModules();
  const get = vi.fn((name: string) => (name === absent ? null : {}));
  vi.doMock("react-native", () => ({
    Platform: { OS: platform },
    TurboModuleRegistry: { get },
  }));
  return { ...(await import("../first-party.ts")), get };
}
afterEach(() => {
  vi.doUnmock("react-native");
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
    expect("storage" in sdk && typeof sdk.storage.prepareRecovery).toBe(
      "function",
    );
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
