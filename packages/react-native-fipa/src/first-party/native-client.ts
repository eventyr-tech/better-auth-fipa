import Simulator from "../NativeIOSSimulator.ts";
import { Platform } from "react-native";
import Integrity from "../NativeAndroidIntegrity.ts";
import Recovery from "../NativeAndroidVaultRecovery.ts";
import { createAndroidFirstPartyClient } from "./android-client.ts";
import AppAttest from "../NativeDeviceAttestation.ts";
import Transport from "../NativeFirstPartyTransport.ts";
import Vault from "../NativeSessionVault.ts";
import { FirstPartyClientError } from "./errors.ts";
import { createIOSFirstPartyClient } from "./ios-client.ts";
import type { NativeFirstPartyConfiguration } from "./native-lifecycle.ts";

/** Native platform selection. Signed-device release certification remains required. */
export function createNativeFirstPartyClient(
  config: NativeFirstPartyConfiguration,
) {
  if (Platform.OS === "android") {
    if (
      config.ios?.provider === "ios-simulator" ||
      config.environment !== "production" ||
      !config.android
    )
      throw new FirstPartyClientError("invalid_configuration");
    if (!Integrity || !Recovery || !Transport || !Vault)
      throw new FirstPartyClientError("native_unavailable");
    return createAndroidFirstPartyClient(
      { ...config, environment: "production", android: config.android },
      {
        integrity: Integrity,
        recovery: Recovery,
        transport: Transport,
        vault: Vault,
      },
    );
  }
  if (Platform.OS !== "ios")
    throw new FirstPartyClientError("unsupported_platform");
  if (config.ios?.provider === "ios-simulator") {
    if (config.environment !== "development")
      throw new FirstPartyClientError("invalid_configuration");
    if (!Simulator || !Transport || !Vault)
      throw new FirstPartyClientError("native_unavailable");
    const simulator = Simulator;
    const transport = Transport;
    return createIOSFirstPartyClient(config, {
      appAttest: {
        getKey: (...args) => simulator.getKey(...args),
        getOrCreateKey: (...args) => simulator.getOrCreateKey(...args),
        generateEvidence: (...args) => simulator.generateEvidence(...args),
        removeKey: (...args) => simulator.removeKey(...args),
        resetKey: () =>
          Promise.reject(new FirstPartyClientError("invalid_configuration")),
      },
      transport: {
        randomToken: () => transport.randomToken(),
        transaction: () => transport.transaction(),
        send: (...args) => transport.send(...args),
        cancel: (...args) => transport.cancel(...args),
        openBrowser: (...args) => transport.openBrowser(...args),
        cancelBrowser: (...args) => transport.cancelBrowser(...args),
        prepareDpop: (...args) => simulator.prepareDpop(...args),
        inspectDpop: (...args) => simulator.inspectDpop(...args),
        signDpop: (...args) => simulator.signDpop(...args),
        removeDpop: (...args) => simulator.removeDpop(...args),
      },
      vault: Vault,
    });
  }
  if (!AppAttest || !Transport || !Vault)
    throw new FirstPartyClientError("native_unavailable");
  return createIOSFirstPartyClient(config, {
    appAttest: AppAttest,
    transport: Transport,
    vault: Vault,
  });
}
