export {
  appAttest,
  type AppAttestApplication,
  type AppAttestExtensionPresence,
  type AppAttestOptions,
  type UntrustedAppAttestReceipt,
} from "./app-attest/provider.js";
export type { AppAttestPlatform } from "./app-attest/platform-policy.js";
export {
  DEVICE_ATTESTATION_ERROR_CODES,
  DeviceAttestationError,
  type DeviceAttestationDiagnosticEvent,
  type DeviceAttestationFailureStage,
  type DeviceAttestationPublicErrorCode,
} from "./errors.js";
export { createDeviceAttestation } from "./plugin.js";
export type {
  AssertionVerificationResult,
  CredentialIssuanceBinding,
  DeviceAttestationComposition,
  DeviceAttestationEnvironment,
  DeviceAttestationOptions,
  DeviceAttestationProvider,
  OAuthAuthorizationBinding,
  RegistrationVerificationResult,
  StoredAttestationCredential,
  VerifiedAttestationGrant,
  VerifiedCredentialIssuanceGrant,
} from "./types.js";
