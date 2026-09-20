import { z } from "zod";
import { commonIdentitySchema, digest } from "./identity.ts";

export const androidEnrollmentSchema = z.strictObject({
  keyChallengeToken: digest,
  attestationChallenge: digest,
  issuedAt: z.iso.datetime(),
  expiresAt: z.iso.datetime(),
});
/** Enrollment is server-issued before Android creates its attested signing key. */
export const androidIdentitySchema = commonIdentitySchema.extend({
  androidEnrollment: androidEnrollmentSchema.optional(),
});
