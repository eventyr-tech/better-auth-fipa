import { z } from "zod";
import { timingSafeEqual } from "node:crypto";
import { rejection } from "../errors.js";
import { parseAndroidKeyDescription } from "./key-description.js";

const digest = z
  .string()
  .regex(/^[A-Za-z0-9_-]{43}$/)
  .refine(
    (value) => Buffer.from(value, "base64url").toString("base64url") === value,
  );
const signerSet = z
  .array(digest)
  .min(1)
  .max(8)
  .refine((set) => new Set(set).size === set.length);
const policySchema = z.strictObject({
  policyVersion: z.string().min(1).max(128),
  packageName: z
    .string()
    .max(255)
    .regex(/^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$/),
  signingCertificateSets: z.array(signerSet).min(1).max(8),
  minimumVersionCode: z.string().regex(/^(?:0|[1-9][0-9]{0,18})$/),
  allowedSecurityLevels: z
    .array(z.enum(["tee", "strongbox"]))
    .min(1)
    .max(2),
  minimumOsVersion: z.number().int().min(1).max(999_999),
  minimumOsPatchLevel: z.number().int().refine(validMonth),
  minimumVendorPatchLevel: z.number().int().refine(validDay).optional(),
  minimumBootPatchLevel: z.number().int().refine(validDay).optional(),
  requireUnlockedDevice: z.boolean(),
});
export type AndroidKeyPolicy = z.infer<typeof policySchema>;
export interface AndroidKeyProperties {
  policyVersion: string;
  attestationVersion: number;
  keymasterVersion: number;
  attestationSecurityLevel: "tee" | "strongbox";
  keySecurityLevel: "tee" | "strongbox";
  algorithm: "ES256";
  origin: "generated";
  packageName: string;
  versionCodeAtCreation: string;
  signingCertificateDigestsAtCreation: string[];
  osVersionAtCreation: number;
  osPatchLevelAtCreation: number;
  vendorPatchLevelAtCreation?: number;
  bootPatchLevelAtCreation?: number;
  bootStateAtCreation: "verified-locked";
  unlockedDeviceRequired: "hardware" | "software" | "not-attested";
}

/** Claims validation only. The caller MUST validate the certificate path,
 * revocation and the containing certificate's actual public key before treating
 * these as attested properties. This function cannot establish key possession. */
export function createAndroidKeyPolicy(options: AndroidKeyPolicy) {
  const parsed = policySchema.safeParse(options);
  if (!parsed.success)
    throw new TypeError("Invalid Android key attestation policy.");
  const policy = parsed.data;
  return (
    extension: Uint8Array,
    expectedChallenge: Uint8Array,
  ): AndroidKeyProperties => {
    const description = parseAndroidKeyDescription(extension);
    const { hardware: hw, software: sw } = description;
    // Version 1 lacks the application binding required by the full profile.
    const versions = new Map([
      [2, 3],
      [3, 4],
      [4, 41],
      [100, 100],
      [200, 200],
      [300, 300],
      [400, 400],
      [500, 500],
    ]);
    const attestationLevel = securityLevel(
      description.attestationSecurityLevel,
    );
    const keyLevel = securityLevel(description.keymasterSecurityLevel);
    const root = hw.rootOfTrust;
    const app = description.application;
    const purpose = hw.sets.get(1);
    const digests = hw.sets.get(5);
    if (
      expectedChallenge.length !== 32 ||
      description.challenge.length !== 32 ||
      !timingSafeEqual(expectedChallenge, description.challenge) ||
      versions.get(description.attestationVersion) !==
        description.keymasterVersion ||
      !policy.allowedSecurityLevels.includes(attestationLevel) ||
      !policy.allowedSecurityLevels.includes(keyLevel) ||
      description.uniqueId.length !== 0 ||
      hw.flags.has(720) ||
      sw.flags.has(720) ||
      hw.flags.has(600) ||
      sw.flags.has(600) ||
      // Reject properties asserted only by software, including imported keys.
      hw.integers.get(2) !== 3n ||
      hw.integers.get(3) !== 256n ||
      hw.integers.get(10) !== 1n ||
      hw.integers.get(702) !== 0n ||
      !purpose?.includes(2n) ||
      purpose.some((value) => value !== 2n && value !== 3n) ||
      digests?.length !== 1 ||
      digests[0] !== 4n ||
      !root ||
      !root.deviceLocked ||
      root.verifiedBootState !== 0 ||
      !validBootHash(root.verifiedBootKey) ||
      (description.attestationVersion >= 3 &&
        (!root.verifiedBootHash || !validBootHash(root.verifiedBootHash))) ||
      // App identity is OS-enforced; a locked verified boot is mandatory above.
      !app ||
      app.packages.length !== 1 ||
      app.packages[0]!.name !== policy.packageName ||
      app.packages[0]!.version < BigInt(policy.minimumVersionCode) ||
      !policy.signingCertificateSets.some(
        (set) =>
          set.length === app.signingCertificateDigests.length &&
          app.signingCertificateDigests.every((signer) => set.includes(signer)),
      ) ||
      (policy.requireUnlockedDevice && !hw.flags.has(509) && !sw.flags.has(509))
    )
      throw rejected();
    const osVersion = hardwareNumber(hw.integers.get(705));
    const osPatchLevel = hardwareNumber(hw.integers.get(706));
    const vendorPatchLevel = hw.integers.has(718)
      ? hardwareNumber(hw.integers.get(718))
      : undefined;
    const bootPatchLevel = hw.integers.has(719)
      ? hardwareNumber(hw.integers.get(719))
      : undefined;
    if (
      osVersion > 999_999 ||
      osVersion < policy.minimumOsVersion ||
      !validMonth(osPatchLevel) ||
      osPatchLevel < policy.minimumOsPatchLevel ||
      (vendorPatchLevel !== undefined && !validDay(vendorPatchLevel)) ||
      (bootPatchLevel !== undefined && !validDay(bootPatchLevel)) ||
      (policy.minimumVendorPatchLevel !== undefined &&
        (vendorPatchLevel === undefined ||
          vendorPatchLevel < policy.minimumVendorPatchLevel)) ||
      (policy.minimumBootPatchLevel !== undefined &&
        (bootPatchLevel === undefined ||
          bootPatchLevel < policy.minimumBootPatchLevel))
    )
      throw rejected();
    return {
      policyVersion: policy.policyVersion,
      attestationVersion: description.attestationVersion,
      keymasterVersion: description.keymasterVersion,
      attestationSecurityLevel: attestationLevel,
      keySecurityLevel: keyLevel,
      algorithm: "ES256",
      origin: "generated",
      packageName: policy.packageName,
      versionCodeAtCreation: app.packages[0]!.version.toString(),
      signingCertificateDigestsAtCreation: app.signingCertificateDigests,
      osVersionAtCreation: osVersion,
      osPatchLevelAtCreation: osPatchLevel,
      ...(vendorPatchLevel !== undefined
        ? { vendorPatchLevelAtCreation: vendorPatchLevel }
        : {}),
      ...(bootPatchLevel !== undefined
        ? { bootPatchLevelAtCreation: bootPatchLevel }
        : {}),
      bootStateAtCreation: "verified-locked",
      unlockedDeviceRequired: hw.flags.has(509)
        ? "hardware"
        : sw.flags.has(509)
          ? "software"
          : "not-attested",
    };
  };
}
function securityLevel(value: number) {
  if (value === 1) return "tee" as const;
  if (value === 2) return "strongbox" as const;
  throw rejected();
}
function hardwareNumber(value: bigint | undefined) {
  if (value === undefined || value > BigInt(Number.MAX_SAFE_INTEGER))
    throw rejected();
  return Number(value);
}
function validMonth(value: number) {
  return (
    Number.isSafeInteger(value) &&
    value >= 200001 &&
    value <= 999912 &&
    value % 100 >= 1 &&
    value % 100 <= 12
  );
}
function validDay(value: number) {
  if (!Number.isSafeInteger(value) || !validMonth(Math.floor(value / 100)))
    return false;
  const year = Math.floor(value / 10000),
    month = Math.floor(value / 100) % 100,
    day = value % 100;
  const date = new Date(Date.UTC(year, month - 1, day));
  return (
    date.getUTCFullYear() === year &&
    date.getUTCMonth() === month - 1 &&
    date.getUTCDate() === day
  );
}
function validBootHash(value: Buffer) {
  return [32, 64].includes(value.length) && value.some((byte) => byte !== 0);
}
function rejected() {
  return rejection("platform-policy", "android_key_policy_rejected");
}
