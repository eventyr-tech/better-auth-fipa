import { commonIdentitySchema, identifier } from "./identity.ts";

/** Apple key lookup may carry the original application's storage prefix. */
export const iosIdentitySchema = commonIdentitySchema.extend({
  providerStoragePrefix: identifier.optional(),
});
