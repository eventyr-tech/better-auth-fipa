import { z } from "zod";
import { sha256 } from "../protocol/crypto.js";
import { FIRST_PARTY_PROFILE } from "./wire.js";

const identifier = z.string().min(1).max(256);
const digest = z.string().regex(/^[A-Za-z0-9_-]{43}$/);
export const nativeAdmissionBindingSchema = z.strictObject({
  profile: z.literal(FIRST_PARTY_PROFILE),
  mode: z.literal("native"),
  issuer: z.string().url().max(2048),
  clientId: identifier,
  provider: identifier,
  applicationId: identifier,
  environment: z.enum(["development", "production"]),
  attemptId: z.string().regex(/^[A-Za-z0-9_-]{22,128}$/),
  codeChallenge: digest,
  codeChallengeMethod: z.literal("S256"),
  dpopJkt: digest,
  scopes: z
    .array(
      z
        .string()
        .regex(/^[\x21\x23-\x5B\x5D-\x7E]+$/)
        .max(256),
    )
    .min(1)
    .max(32),
  resources: z.array(z.string().url().max(2048)).max(8),
  nonce: z.string().min(1).max(512).optional(),
  acrValues: z.array(identifier).max(16).optional(),
  maxAge: z
    .number()
    .int()
    .nonnegative()
    .max(86400 * 365)
    .optional(),
});
export type NativeAdmissionBinding = z.infer<
  typeof nativeAdmissionBindingSchema
>;

export function normalizeNativeAdmissionBinding(
  input: NativeAdmissionBinding,
): NativeAdmissionBinding {
  const parsed = nativeAdmissionBindingSchema.parse(input);
  return {
    ...parsed,
    scopes: [...new Set(parsed.scopes)].sort(),
    resources: [...new Set(parsed.resources)].sort(),
  };
}

/** Domain-separated, fixed-position JSON arrays retain set boundaries and nulls. */
export function encodeNativeAdmissionBinding(
  input: NativeAdmissionBinding,
): Buffer {
  const binding = normalizeNativeAdmissionBinding(input);
  return Buffer.from(
    JSON.stringify([
      "better-auth-device-attestation/first-party-admission-binding/v1",
      binding.profile,
      binding.mode,
      binding.issuer,
      binding.clientId,
      binding.provider,
      binding.applicationId,
      binding.environment,
      binding.attemptId,
      binding.codeChallenge,
      binding.codeChallengeMethod,
      binding.dpopJkt,
      binding.scopes,
      binding.resources,
      binding.nonce ?? null,
      binding.acrValues ?? null,
      binding.maxAge ?? null,
    ]),
    "utf8",
  );
}
export function hashNativeAdmissionBinding(
  input: NativeAdmissionBinding,
): Buffer {
  return sha256(encodeNativeAdmissionBinding(input));
}
