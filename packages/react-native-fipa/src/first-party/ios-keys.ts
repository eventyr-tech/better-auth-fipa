import { createProviderKeyPorts } from "./provider-keys.ts";

/** Hardware App Attest composition retains its existing internal port contract. */
export function createIOSKeyPorts(
  options: Parameters<typeof createProviderKeyPorts>[0],
  native: Omit<Parameters<typeof createProviderKeyPorts>[1], "evidence"> & {
    appAttest: Parameters<typeof createProviderKeyPorts>[1]["evidence"];
  },
) {
  return createProviderKeyPorts(options, {
    ...native,
    evidence: native.appAttest,
  });
}
