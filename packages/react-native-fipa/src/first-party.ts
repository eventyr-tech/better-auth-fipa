/** Native FiPA client. Storage, signing and transport stay inside the SDK. */
export { createNativeFirstPartyClient } from "./first-party/native-client.ts";
export { FirstPartyClientError } from "./first-party/errors.ts";
export type { FirstPartyErrorCode } from "./first-party/errors.ts";
export type { NativeFirstPartyConfiguration } from "./first-party/native-lifecycle.ts";
export type { RetainedIOSKeyReference } from "./first-party/ios-retained-keys.ts";
export type {
  AccountSlot,
  ClientState,
  ConfirmedAccount,
  ResourceRequest,
  ResourceResponse,
  TerminationResult,
} from "./first-party/client.ts";
export type NativeFirstPartyClient = ReturnType<
  typeof import("./first-party/native-client.ts").createNativeFirstPartyClient
>;
