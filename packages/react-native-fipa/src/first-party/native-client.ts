import { createDevelopmentVault } from "./development-vault.ts";
import { createDevelopmentFirstPartyClient } from "./development-client.ts";
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
):
  | ReturnType<typeof createDevelopmentFirstPartyClient>
  | ReturnType<typeof createIOSFirstPartyClient>
  | ReturnType<typeof createAndroidFirstPartyClient> {
  if (
    config.provider !== undefined &&
    !["hardware", "development"].includes(config.provider)
  )
    throw new FirstPartyClientError("invalid_configuration");
  if (config.provider === "development") {
    if (config.environment !== "development")
      throw new FirstPartyClientError("invalid_configuration");
    if (!["ios", "android"].includes(Platform.OS))
      throw new FirstPartyClientError("unsupported_platform");
    if (!Transport) throw new FirstPartyClientError("native_unavailable");
    const transport = Transport;
    return createDevelopmentFirstPartyClient(config, {
      transport,
      vault: createDevelopmentVault(() => transport.randomToken()),
    });
  }
  if (Platform.OS === "android") {
    if (config.environment !== "production" || !config.android)
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
  if (!AppAttest || !Transport || !Vault)
    throw new FirstPartyClientError("native_unavailable");
  return createIOSFirstPartyClient(config, {
    appAttest: AppAttest,
    transport: Transport,
    vault: Vault,
  });
}
