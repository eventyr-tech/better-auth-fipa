import { createAuthClient } from "better-auth/client";
import { describe, expect, expectTypeOf, it } from "vitest";

import { deviceAttestationClient } from "./client.js";

describe("device attestation client plugin", () => {
  it("declares explicit methods for every inferred endpoint", () => {
    expect(deviceAttestationClient().pathMethods).toEqual({
      "/device-attestation/challenge": "POST",
      "/device-attestation/verify": "POST",
      "/device-attestation/credentials": "GET",
      "/device-attestation/credentials/retire": "POST",
    });
  });

  it("infers challenge, verification, credential, and retirement methods", () => {
    const client = createAuthClient({
      baseURL: "http://localhost:3000",
      plugins: [deviceAttestationClient()],
    });

    expectTypeOf(client.deviceAttestation.challenge).toBeFunction();
    expectTypeOf(client.deviceAttestation.verify).toBeFunction();
    expectTypeOf(client.deviceAttestation.credentials).toBeFunction();
    expectTypeOf(client.deviceAttestation.credentials.retire).toBeFunction();

    const typecheckChallengeBodies = () => {
      void client.deviceAttestation.challenge({
        provider: "app-attest",
        applicationId: "TEAMID.com.example.mobile",
        operation: "register",
        keyId: "base64-key-id",
        purpose: "credential-registration",
      });
      void client.deviceAttestation.challenge({
        provider: "app-attest",
        applicationId: "TEAMID.com.example.mobile",
        operation: "assert",
        keyId: "base64-key-id",
        purpose: "oauth-authorization",
        binding: {
          clientId: "mobile-app",
          redirectUri: "com.example.mobile:/oauth/callback",
          codeChallenge: "challenge",
          codeChallengeMethod: "S256",
          dpopJkt: "thumbprint",
          scope: "openid",
        },
      });
      void client.deviceAttestation.challenge({
        provider: "app-attest",
        applicationId: "TEAMID.com.example.mobile",
        operation: "assert",
        keyId: "base64-key-id",
        purpose: "credential-issuance",
        binding: {
          namespace: "example.device-pairing",
          subject: "pairing-transaction-digest",
          dpopJkt: "thumbprint",
        },
      });
    };
    expectTypeOf(typecheckChallengeBodies).toBeFunction();
  });
});
