import type { GenericEndpointContext } from "@better-auth/core";
import { CREDENTIAL_MODEL } from "../credential-store.js";
import type { StoredAttestationCredential } from "../types.js";

export const ANDROID_PROVIDER = "android-hardware";
export const ANDROID_KEY_MODEL = "firstPartyAndroidKey";

/** Common lifecycle state only. Apple assertion counters and Android certificate
 * metadata remain in their own provider records. */
export type LifecycleProviderCredential = Pick<
  StoredAttestationCredential,
  | "id"
  | "lookupKey"
  | "provider"
  | "applicationId"
  | "environment"
  | "publicKey"
  | "userId"
  | "externallyBound"
  | "bindingVersion"
  | "status"
  | "unboundExpiresAt"
  | "revokedAt"
  | "revocationReason"
>;

export function nativeProviderCredentialModel(provider: string) {
  return provider === ANDROID_PROVIDER ? ANDROID_KEY_MODEL : CREDENTIAL_MODEL;
}

/** Select using server-owned policy/receipt/logical state, never a request's
 * model name. Android key ownership is fixed to its client and attested JKT. */
export async function readNativeProviderCredential(
  ctx: Pick<GenericEndpointContext, "context">,
  input: { provider: string; id: string; clientId: string; dpopJkt: string },
): Promise<LifecycleProviderCredential | null> {
  const row = await ctx.context.adapter.findOne<
    LifecycleProviderCredential & { clientId?: string; dpopJkt?: string }
  >({
    model: nativeProviderCredentialModel(input.provider),
    where: [{ field: "id", value: input.id }],
  });
  if (!row || row.provider !== input.provider) return null;
  if (
    input.provider === ANDROID_PROVIDER &&
    (row.clientId !== input.clientId || row.dpopJkt !== input.dpopJkt)
  )
    return null;
  return row;
}
