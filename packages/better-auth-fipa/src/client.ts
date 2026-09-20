import type { createDeviceAttestation } from "./plugin.js";
import type { BetterAuthClientPlugin } from "better-auth/client";
import type { ClientFetchOption } from "@better-auth/core";

/** Request body for a new App Attest credential-registration challenge. */
export interface DeviceAttestationRegistrationChallengeRequest {
  provider: string;
  applicationId: string;
  operation: "register";
  keyId: string;
  purpose: "credential-registration";
}

/** Request body for a protected OAuth assertion challenge. */
export interface DeviceAttestationAssertionChallengeRequest {
  provider: string;
  applicationId: string;
  operation: "assert";
  keyId: string;
  purpose: "oauth-authorization";
  binding: {
    clientId: string;
    redirectUri: string;
    codeChallenge: string;
    codeChallengeMethod: "S256";
    dpopJkt: string;
    scope: string;
    resources?: string[];
    nonce?: string;
  };
}

/** Request body for an attested host credential-issuance challenge. */
export interface DeviceAttestationCredentialIssuanceChallengeRequest {
  provider: string;
  applicationId: string;
  operation: "assert";
  keyId: string;
  purpose: "credential-issuance";
  binding: {
    namespace: string;
    subject: string;
    dpopJkt: string;
  };
}

/** Valid request body for the shared challenge endpoint. */
export type DeviceAttestationChallengeRequest =
  | DeviceAttestationRegistrationChallengeRequest
  | DeviceAttestationAssertionChallengeRequest
  | DeviceAttestationCredentialIssuanceChallengeRequest;

/**
 * Create the Better Auth client plugin used to infer device-attestation
 * endpoints from the server plugin.
 *
 * This export has no Apple or native runtime dependency. Applications remain
 * responsible for calling their platform App Attest bridge and transporting
 * the resulting evidence through the inferred endpoints.
 */
export function deviceAttestationClient() {
  return {
    id: "device-attestation",
    version: "0.1.0-alpha.3",
    $InferServerPlugin: {} as ReturnType<
      typeof createDeviceAttestation
    >["serverPlugin"],
    // Better Auth currently flattens discriminated-union endpoint bodies during
    // inference. This custom action preserves the register/assert relationship.
    getActions: ($fetch) => ({
      deviceAttestation: {
        challenge: (
          body: DeviceAttestationChallengeRequest,
          fetchOptions?: ClientFetchOption<DeviceAttestationChallengeRequest>,
        ) =>
          $fetch("/device-attestation/challenge", {
            ...fetchOptions,
            method: "POST",
            body,
          }),
      },
    }),
    pathMethods: {
      "/device-attestation/challenge": "POST",
      "/device-attestation/verify": "POST",
      "/device-attestation/credentials": "GET",
      "/device-attestation/credentials/retire": "POST",
    },
  } satisfies BetterAuthClientPlugin;
}
