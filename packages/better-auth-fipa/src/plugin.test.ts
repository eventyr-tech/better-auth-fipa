import { betterAuth } from "better-auth";
import type { StoredAuthorizationQuery } from "@better-auth/oauth-provider";
import { describe, expect, it, vi } from "vitest";

import { decodeBase64Strict } from "./encoding/base64.js";
import { createDeviceAttestation } from "./plugin.js";
import { sha256 } from "./protocol/crypto.js";
import type {
  DeviceAttestationProvider,
  OAuthAuthorizationBinding,
  OAuthProviderTokenContext,
  StoredAttestationCredential,
} from "./types.js";

const APP_ID = "TEAMID.com.example.mobile";
const KEY_ID = Buffer.alloc(32, 0x5a);
const PUBLIC_KEY = Buffer.alloc(91, 0x6b).toString("base64");

describe("device attestation Better Auth plugin", () => {
  it("registers, asserts, consumes a grant, and binds the credential", async () => {
    const diagnostics = vi.fn();
    const provider = mockProvider();
    const composition = createDeviceAttestation({
      providers: [provider],
      purposes: {
        credentialRegistration: {
          challengeTtlSeconds: 120,
          unboundCredentialTtlSeconds: 3600,
        },
        oauthAuthorization: {
          protectedClientIds: ["mobile-app"],
          challengeTtlSeconds: 120,
          grantTtlSeconds: 300,
          requireDpopJkt: true,
        },
      },
      diagnostics: { report: diagnostics },
    });
    const auth = betterAuth({
      baseURL: "http://localhost:3000",
      secret: "test-secret-that-is-at-least-thirty-two-characters",
      plugins: [composition.serverPlugin],
    });
    const context = await auth.$context;

    const registrationChallenge =
      await auth.api.createDeviceAttestationChallenge({
        body: {
          provider: "mock-attestation",
          applicationId: APP_ID,
          operation: "register",
          keyId: KEY_ID.toString("base64"),
          purpose: "credential-registration",
        },
      });
    const registration = await auth.api.verifyDeviceAttestation({
      body: {
        challengeToken: registrationChallenge.challengeToken,
        keyId: KEY_ID.toString("base64"),
        evidence: Buffer.from("registration-evidence").toString("base64"),
      },
    });

    await expect(
      auth.api.verifyDeviceAttestation({
        body: {
          challengeToken: registrationChallenge.challengeToken,
          keyId: KEY_ID.toString("base64"),
          evidence: Buffer.from("registration-evidence").toString("base64"),
        },
      }),
    ).rejects.toMatchObject({ status: "FORBIDDEN" });
    expect(diagnostics).toHaveBeenLastCalledWith({
      provider: "unknown",
      operation: "verify",
      stage: "challenge",
      reason: "challenge_unavailable",
      retryable: false,
    });
    expect(JSON.stringify(diagnostics.mock.lastCall)).not.toContain(
      registrationChallenge.challengeToken,
    );
    diagnostics.mockClear();

    expect(registration.credentialState).toBe("registered-unbound");
    if (registration.credentialState !== "registered-unbound") {
      expect.fail("Expected credential registration response.");
    }
    const credentialId = registration.credentialId;
    const credentialBeforeAssertion =
      await context.adapter.findOne<StoredAttestationCredential>({
        model: "deviceAttestationCredential",
        where: [{ field: "id", value: credentialId }],
      });
    expect(credentialBeforeAssertion).toMatchObject({
      userId: null,
      counter: 0,
      status: "active",
    });

    const binding = oauthBinding();
    const assertionChallenge = await auth.api.createDeviceAttestationChallenge({
      body: {
        provider: "mock-attestation",
        applicationId: APP_ID,
        operation: "assert",
        keyId: KEY_ID.toString("base64"),
        purpose: "oauth-authorization",
        binding,
      },
    });
    const assertion = await auth.api.verifyDeviceAttestation({
      body: {
        challengeToken: assertionChallenge.challengeToken,
        keyId: KEY_ID.toString("base64"),
        evidence: Buffer.from("assertion-evidence").toString("base64"),
      },
    });
    expect(assertion).toMatchObject({
      credentialState: "asserted",
    });
    if (assertion.credentialState !== "asserted") {
      expect.fail("Expected assertion response.");
    }

    const user = await context.adapter.create<{
      id: string;
      name: string;
      email: string;
      emailVerified: boolean;
      createdAt: Date;
      updatedAt: Date;
    }>({
      model: "user",
      data: {
        name: "Test User",
        email: "test@example.com",
        emailVerified: true,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
    });
    const protectedOAuth = composition.protectOAuthProvider({
      loginPage: "/login",
      consentPage: "/consent",
      customTokenResponseFields: (info: OAuthProviderTokenContext) => {
        void info;
        return {};
      },
    });
    const verificationQuery: StoredAuthorizationQuery & {
      device_attestation: string;
    } = {
      response_type: "code",
      client_id: binding.clientId,
      redirect_uri: binding.redirectUri,
      code_challenge: binding.codeChallenge,
      code_challenge_method: binding.codeChallengeMethod,
      dpop_jkt: binding.dpopJkt,
      scope: binding.scope,
      ...(binding.resources === undefined
        ? {}
        : { resource: binding.resources }),
      ...(binding.nonce === undefined ? {} : { nonce: binding.nonce }),
      device_attestation: assertion.grantToken,
    };
    await Promise.resolve(
      protectedOAuth.customTokenResponseFields?.({
        grantType: "authorization_code",
        user,
        scopes: ["openid", "offline_access"],
        verificationValue: {
          type: "authorization_code",
          query: verificationQuery,
          sessionId: "session-1",
          userId: user.id,
        },
      }),
    );

    const credentialAfterGrant =
      await context.adapter.findOne<StoredAttestationCredential>({
        model: "deviceAttestationCredential",
        where: [{ field: "id", value: credentialId }],
      });
    expect(credentialAfterGrant).toMatchObject({
      userId: user.id,
      counter: 1,
      bindingVersion: 1,
      status: "active",
    });
    await context.internalAdapter.deleteUser(user.id);
    const credentialAfterUserDeletion =
      await context.adapter.findOne<StoredAttestationCredential>({
        model: "deviceAttestationCredential",
        where: [{ field: "id", value: credentialId }],
      });
    expect(credentialAfterUserDeletion).toMatchObject({
      userId: user.id,
      status: "revoked",
      revocationReason: "user_deleted",
      publicKey: null,
    });
    expect(diagnostics).not.toHaveBeenCalled();
  });
});

function mockProvider(): DeviceAttestationProvider {
  return {
    id: "mock-attestation",
    maxEvidenceBytes: 1024,
    decodeKeyId(value) {
      return decodeBase64Strict(value, {
        label: "mock_key_id",
        exactBytes: 32,
        maxBytes: 32,
      });
    },
    verifyRegistration(input) {
      expect(input.applicationId).toBe(APP_ID);
      expect(input.keyId).toEqual(KEY_ID);
      expect(input.clientDataHash).toHaveLength(32);
      expect(input.evidence).toEqual(Buffer.from("registration-evidence"));
      return Promise.resolve({
        applicationId: APP_ID,
        environment: "production",
        publicKey: PUBLIC_KEY,
        counter: 0,
        extensionsPresent: true,
        validationCategory: 2,
        bundleVersion: "42",
      });
    },
    verifyAssertion(input) {
      expect(input.credential.applicationId).toBe(APP_ID);
      expect(input.clientDataHash).toHaveLength(32);
      expect(input.evidence).toEqual(Buffer.from("assertion-evidence"));
      return Promise.resolve({
        counter: input.credential.counter + 1,
        extensionsPresent: true,
        validationCategory: 4,
        bundleVersion: "42",
      });
    },
  };
}

function oauthBinding(): OAuthAuthorizationBinding {
  return {
    clientId: "mobile-app",
    redirectUri: "com.example.mobile:/oauth/callback",
    codeChallenge: Buffer.alloc(32, 0x33).toString("base64url"),
    codeChallengeMethod: "S256",
    dpopJkt: sha256(Buffer.from("dpop-public-key")).toString("base64url"),
    scope: "openid offline_access",
    resources: ["https://api.example.com"],
    nonce: "oidc-nonce",
  };
}
