import type { NativeIdentity } from "./identity.ts";
import type { Spec as Transport } from "../NativeFirstPartyTransport.ts";
import type { SessionVaultNative } from "./session-coordinator.ts";
import { createAccountCatalog } from "./account-catalog.ts";
import {
  createFirstPartyClientCore,
  firstPartyStorageNamespace,
  type FirstPartyClientConfiguration,
  type FirstPartyClientPorts,
} from "./client.ts";
import { FirstPartyClientError } from "./errors.ts";
import { createNativeProtocolTransport } from "./native-transport.ts";
import { createNativeBrowser } from "./native-browser.ts";

export type NativeFirstPartyConfiguration = Omit<
  FirstPartyClientConfiguration,
  "provider" | "storageNamespace" | "accessibility"
> & {
  storageNamespace?: string;
  /** Explicit software evidence for development on either platform; never a fallback. */
  provider?: "hardware" | "development";
  /** Required on Android; never selects a software-key fallback. */
  android?: { cloudProjectNumber: string; securityLevel: "tee" | "strongbox" };
};

/** Both platform compositions own the same catalog, leases and lifecycle.
 * This native-port seam is internal, never consumer-supplied storage/crypto. */
export function createNativeLifecycle(
  config: FirstPartyClientConfiguration,
  native: { transport: Transport; vault: SessionVaultNative },
  keys: (ports: {
    aliases: ReturnType<typeof createAccountCatalog>["aliases"];
    send: FirstPartyClientPorts["send"];
  }) => FirstPartyClientPorts["keys"],
  imports?: { normalizeReference(identity: NativeIdentity): NativeIdentity },
) {
  const transport = createNativeProtocolTransport(native.transport, config);
  const core = createFirstPartyClientCore(config, {
    ...transport,
    vault: native.vault,
    browser: createNativeBrowser(
      native.transport,
      config.allowInsecureLoopback,
    ),
    keys: keys({
      aliases: (slot) => catalog.aliases(slot),
      send: transport.send,
    }),
  });
  const catalog: ReturnType<typeof createAccountCatalog> = createAccountCatalog(
    {
      namespace: firstPartyStorageNamespace(config),
      vault: native.vault,
      randomToken: () => native.transport.randomToken(),
      inspect: (slot) => core.inspect(slot),
      beginRecovery: (slot, allowEmptyImport) =>
        core.beginRecovery(slot, allowEmptyImport),
      readIdentity: async (slot) => {
        const identity = await core.readIdentity(slot);
        return identity && imports
          ? imports.normalizeReference(identity)
          : identity;
      },
      installRetainedIdentity: (slot, identity) => {
        if (!imports) throw new FirstPartyClientError("invalid_request");
        return core.installRetainedIdentity(slot, identity);
      },
    },
  );
  // Check catalog membership before key preparation. The durable retired and
  // superseded identity markers fence operations already past this check.
  function checked<Args extends unknown[], Result>(
    operation: (slot: string, ...args: Args) => Promise<Result>,
  ) {
    return async (slot: string, ...args: Args): Promise<Result> => {
      await catalog.require(slot);
      return operation(slot, ...args);
    };
  }
  return {
    catalog,
    client: {
      accounts: {
        create: () => catalog.create(),
        list: () => catalog.list(),
        forget: (slot: string) => catalog.forget(slot),
        recover: (slot: string) => catalog.recover(slot),
      },
      start: checked(core.start.bind(core)),
      respond: checked(core.respond.bind(core)),
      openBrowser: checked(core.openBrowser.bind(core)),
      restore: checked(core.restore.bind(core)),
      fetch: checked(core.fetch.bind(core)),
      cancel: checked(core.cancel.bind(core)),
      logout: checked(core.logout.bind(core)),
      retire: checked(core.retire.bind(core)),
    },
  };
}
