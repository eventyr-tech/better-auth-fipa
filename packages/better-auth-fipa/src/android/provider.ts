import { createAndroidKeyAttestationVerifier } from "./key-attestation.js";
import {
  createGoogleAttestationTrust,
  type GoogleTrustOptions,
} from "./google-trust.js";
import {
  createPlayIntegrityVerifier,
  type PlayIntegrityOptions,
} from "./play-integrity.js";
import type { AndroidKeyPolicy } from "./key-policy.js";
import { ANDROID_PROVIDER } from "../first-party/provider-credential.js";

/** Internal factory; the public androidHardware wrapper does not expose runtime
 * injection. This provider does not implement the legacy Apple-counter API. */
export function createAndroidHardwareProvider(
  options: {
    key: AndroidKeyPolicy;
    play: PlayIntegrityOptions;
    trust?: GoogleTrustOptions;
    unboundCredentialTtlSeconds?: number;
    expiredCredentialRetentionSeconds?: number;
  },
  runtime: { fetch?: typeof fetch; now?: () => Date } = {},
) {
  if (options.key.packageName !== options.play.packageName)
    throw new TypeError(
      "Android key and Play policies must identify the same application.",
    );
  const ttl = options.unboundCredentialTtlSeconds ?? 86_400;
  if (!Number.isSafeInteger(ttl) || ttl < 1 || ttl > 86_400)
    throw new TypeError("Invalid Android unbound credential lifetime.");
  const retention = options.expiredCredentialRetentionSeconds ?? 7 * 86_400;
  if (
    !Number.isSafeInteger(retention) ||
    retention < 1 ||
    retention > 30 * 86_400
  )
    throw new TypeError("Invalid Android expired credential retention.");
  const trust = createGoogleAttestationTrust(options.trust, runtime);
  const key = createAndroidKeyAttestationVerifier(options.key);
  const play = createPlayIntegrityVerifier(options.play, runtime);
  return Object.freeze({
    id: ANDROID_PROVIDER,
    kind: "android-hardware" as const,
    maxEvidenceBytes: 180_000,
    applicationId: options.key.packageName,
    unboundCredentialTtlSeconds: ttl,
    expiredCredentialRetentionSeconds: retention,
    trust,
    verifyKey: key,
    verifyPlay: play.verify.bind(play),
  });
}
export type AndroidHardwareProvider = ReturnType<
  typeof createAndroidHardwareProvider
>;
export function isAndroidHardwareProvider(provider: {
  id: string;
}): provider is AndroidHardwareProvider {
  return provider.id === ANDROID_PROVIDER;
}
