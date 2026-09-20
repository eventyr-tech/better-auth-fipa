import { DeviceAttestationClientError } from "./errors.ts";
import type { DpopNative, DpopProofInput } from "./types.ts";

/** Keep aliases stable. Ordinary logout does not delete or rotate a key. */
export function createDpopClient(keyAlias: string, native: DpopNative) {
  if (!keyAlias) throw new TypeError("A nonempty DPoP key alias is required.");

  async function safely<T>(operation: () => Promise<T>): Promise<T> {
    try {
      return await operation();
    } catch {
      throw new DeviceAttestationClientError("DEVICE_ATTESTATION_DPOP_ERROR");
    }
  }

  const generate = (input: DpopProofInput) =>
    safely(async () => {
      const url = new URL(input.url);
      if (
        !["https:", "http:"].includes(url.protocol) ||
        url.username ||
        url.password
      )
        throw new TypeError("Invalid proof URL.");
      return native.generateProof({
        alias: keyAlias,
        htm: input.method,
        htu: `${url.origin}${url.pathname}`,
        requireHardwareBacked: true,
        ...(input.accessToken ? { accessToken: input.accessToken } : {}),
        ...(input.nonce === undefined ? {} : { nonce: input.nonce }),
      });
    });

  return {
    generateProof: async (input: DpopProofInput) =>
      (await generate(input)).proof,
    generateProofAndThumbprint: async (input: DpopProofInput) => {
      const result = await generate(input);
      return {
        proof: result.proof,
        thumbprint: await safely(() => result.getPublicKeyThumbprint()),
      };
    },
    assertHardwareBacked: () =>
      safely(() => native.assertHardwareBacked(keyAlias)),
    deleteKey: () => safely(() => native.deleteKeyPair(keyAlias)),
  };
}
