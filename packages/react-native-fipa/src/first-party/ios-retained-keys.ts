import { identifier } from "./identity.ts";
import { z } from "zod";
import type { Spec as AppAttest } from "../NativeDeviceAttestation.ts";
import type { Spec as Transport } from "../NativeFirstPartyTransport.ts";
import { FirstPartyClientError } from "./errors.ts";

const reference = z.strictObject({
  keyIdStoragePrefix: identifier,
  credentialScope: identifier,
  dpopAlias: identifier,
});
export type RetainedIOSKeyReference = z.infer<typeof reference>;
export { importedIdentitySchema as retainedIOSIdentitySchema } from "./identity.ts";
import {
  importedIdentitySchema as retainedIOSIdentitySchema,
  type ImportedIdentity,
} from "./identity.ts";
export type RetainedIOSIdentity = ImportedIdentity;

/** Read-only by construction: these ports expose no generation, reset, deletion
 * or token operations. Old session bytes and caller-provided subjects are never accepted. */
export async function readRetainedIOSKeys(
  input: RetainedIOSKeyReference,
  native: {
    appAttest: Pick<AppAttest, "getKey">;
    dpop: Pick<Transport, "inspectDpop">;
  },
): Promise<RetainedIOSIdentity> {
  const parsed = reference.safeParse(input);
  if (!parsed.success) throw new FirstPartyClientError("invalid_request");
  try {
    const providerKeyId = await native.appAttest.getKey(
      parsed.data.keyIdStoragePrefix,
      parsed.data.credentialScope,
    );
    if (providerKeyId === null)
      throw new FirstPartyClientError("registration_recovery_required");
    const dpopJkt = await native.dpop.inspectDpop(parsed.data.dpopAlias);
    const identity = retainedIOSIdentitySchema.safeParse({
      version: 1,
      providerKeyId,
      dpopJkt,
      dpopAlias: parsed.data.dpopAlias,
      providerScope: parsed.data.credentialScope,
      providerStoragePrefix: parsed.data.keyIdStoragePrefix,
      providerRegistration: "unknown",
    });
    if (!identity.success) throw new FirstPartyClientError("invalid_response");
    return identity.data;
  } catch (error) {
    if (error instanceof FirstPartyClientError) throw error;
    if (
      error &&
      typeof error === "object" &&
      "code" in error &&
      error.code === "key_missing"
    )
      throw new FirstPartyClientError("registration_recovery_required");
    throw new FirstPartyClientError("operation_failed");
  }
}
