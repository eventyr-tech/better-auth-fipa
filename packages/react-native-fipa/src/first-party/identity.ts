import { z } from "zod";
import { FirstPartyClientError } from "./errors.ts";

export const digest = z.string().regex(/^[A-Za-z0-9_-]{43}$/);
export const identifier = z.string().min(1).max(256);
export const accountSchema = z.strictObject({
  subject: identifier,
  credentialId: identifier,
});

/** Existing v1 storage layout. Provider codecs extend this without rewriting records. */
export const commonIdentitySchema = z.strictObject({
  version: z.literal(1),
  dpopAlias: identifier,
  dpopJkt: digest,
  providerKeyId: z.string().min(1).max(2048),
  providerScope: identifier,
  retired: z.literal(true).optional(),
  keysRemoved: z.literal(true).optional(),
  superseded: z.literal(true).optional(),
  account: accountSchema.optional(),
  providerRegistration: z
    .enum(["generated", "attesting", "registered", "unknown"])
    .optional(),
});
export type NativeIdentity = z.infer<typeof commonIdentitySchema> & {
  // Provider-owned reference metadata remains opaque to the coordinator.
  [field: string]: unknown;
};

/** Admission may advance enrollment, never replace keys, account binding or fences. */
export function assertRegistrationAdvance(
  before: NativeIdentity,
  after: NativeIdentity,
) {
  const { providerRegistration: previous, ...oldKey } = before;
  const { providerRegistration: next, ...newKey } = after;
  if (
    JSON.stringify(oldKey) !== JSON.stringify(newKey) ||
    !(
      next === previous ||
      next === "registered" ||
      (previous === "generated" && next === "attesting")
    )
  )
    throw new FirstPartyClientError("invalid_state");
}

/** Import is a reference-only operation, distinct from reading an active identity. */
export const importedIdentitySchema = commonIdentitySchema
  .pick({
    version: true,
    dpopAlias: true,
    dpopJkt: true,
    providerScope: true,
    providerKeyId: true,
  })
  .extend({
    providerStoragePrefix: identifier,
    providerRegistration: z.literal("unknown"),
  });
export type ImportedIdentity = z.infer<typeof importedIdentitySchema>;
