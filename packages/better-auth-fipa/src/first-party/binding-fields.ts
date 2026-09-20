// Generated from protocol/first-party-binding.ts. Do not edit directly.
/** Canonical wire encoding. Labels and array positions are protocol identifiers,
 * independent of package names. Validation and cryptographic hashing belong to callers. */
export interface AdmissionBindingFields {
  profile: string;
  mode: string;
  issuer: string;
  clientId: string;
  provider: string;
  applicationId: string;
  environment: string;
  attemptId: string;
  codeChallenge: string;
  codeChallengeMethod: string;
  dpopJkt: string;
  scopes: readonly string[];
  resources: readonly string[];
  nonce?: string | undefined;
  acrValues?: readonly string[] | undefined;
  maxAge?: number | undefined;
}
export function admissionBindingFields(binding: AdmissionBindingFields) {
  return [
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
    [...new Set(binding.scopes)].sort(),
    [...new Set(binding.resources)].sort(),
    binding.nonce ?? null,
    binding.acrValues ?? null,
    binding.maxAge ?? null,
  ];
}
export function androidRegistrationFields(
  challenge: string,
  bindingHash: string,
) {
  return [
    "better-auth-device-attestation/android-registration/v1",
    challenge,
    bindingHash,
  ];
}
