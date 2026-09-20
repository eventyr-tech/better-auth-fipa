import { createAndroidHardwareProvider } from "./android/provider.js";

export type AndroidHardwareOptions = Parameters<
  typeof createAndroidHardwareProvider
>[0];
export type {
  AndroidKeyPolicy,
  AndroidKeyProperties,
} from "./android/key-policy.js";
export type {
  PlayIntegrityPolicy,
  PlayIntegrityOptions,
  VerifiedPlayIntegrity,
} from "./android/play-integrity.js";

/** Actual DPoP-key hardware attestation plus fresh standard Play Integrity.
 * The public factory has no alternate verifier, transport or trust-root seam.
 * Signed-device acceptance remains a release requirement. */
export function androidHardware(options: AndroidHardwareOptions) {
  return createAndroidHardwareProvider(options);
}
