/** Separate entry point so legacy consumers do not need the OAuth provider peer. */
export { createNativeFirstPartyPlugin } from "./first-party/plugin.js";
export {
  requireNativeAccess,
  requireLegacyAccess,
  resolveFirstPartyTokenContext,
} from "./first-party/token-lifecycle.js";
export type {
  NativeTokenOptions,
  FirstPartyTokenContext,
} from "./first-party/token-lifecycle.js";
export type { LegacyCompatibilityOptions } from "./first-party/legacy-v1/adapter.js";
export type { LegacyClientPolicy } from "./first-party/legacy-v1/contract.js";
export type { NativeApplicationPolicy } from "./first-party/admission.js";
export type { ContinuationPolicy } from "./first-party/continuation.js";
export type {
  EmailDeliveryPolicy,
  EmailDeliveryConfiguration,
  EmailDeliveryLimit,
} from "./first-party/email-otp-delivery.js";

export { androidHardware } from "./android.js";
export type {
  AndroidHardwareOptions,
  AndroidKeyPolicy,
  PlayIntegrityPolicy,
} from "./android.js";

export { developmentProvider } from "./development.js";
