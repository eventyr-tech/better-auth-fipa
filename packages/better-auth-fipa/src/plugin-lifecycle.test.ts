import { betterAuth } from "better-auth";
import { APIError } from "better-auth/api";
import type { StoredAuthorizationQuery } from "@better-auth/oauth-provider";
import { describe, expect, it, vi } from "vitest";

import { decodeBase64Strict } from "./encoding/base64.js";
import { createDeviceAttestation } from "./plugin.js";
import { sha256 } from "./protocol/crypto.js";
import type {
  DeviceAttestationDiagnosticEvent,
  DeviceAttestationProvider,
  CredentialIssuanceBinding,
  OAuthAuthorizationBinding,
  StoredAttestationCredential,
} from "./index.js";
import type { OAuthProviderTokenContext } from "./types.js";

const APP_ID = "TEAMID.com.example.mobile";
const KEY_ID = Buffer.alloc(32, 0x51);
const SECOND_KEY_ID = Buffer.alloc(32, 0x52);
const PUBLIC_KEY = Buffer.alloc(91, 0x61).toString("base64");
const UINT32_MAX = 0xffff_ffff;

describe("device attestation lifecycle and concurrency", () => {
  it("binds host credential issuance and later the same key to a user", async () => {
    const harness = await createHarness();
    await harness.register();
    const issuance = await harness.assertCredentialIssuance();

    await expect(
      harness.composition.consumeCredentialIssuanceGrant({
        grantToken: issuance.grantToken,
        binding: harness.credentialIssuanceBinding,
      }),
    ).resolves.toMatchObject({
      provider: "mock-attestation",
      applicationId: APP_ID,
    });
    await expect(harness.credential()).resolves.toMatchObject({
      externallyBound: true,
      userId: null,
      unboundExpiresAt: null,
      bindingVersion: 1,
    });

    const oauthAssertion = await harness.assert();
    const user = await harness.createUser("paired@example.com");
    await harness.composition.consumeOAuthAuthorizationGrant({
      grantToken: oauthAssertion.grantToken,
      binding: harness.binding,
      userId: user.id,
    });
    await expect(harness.credential()).resolves.toMatchObject({
      externallyBound: true,
      userId: user.id,
      bindingVersion: 2,
    });
  });

  it("does not allow a grant to cross purpose boundaries", async () => {
    const harness = await createHarness();
    await harness.register();
    const oauthAssertion = await harness.assert();

    await expect(
      harness.composition.consumeCredentialIssuanceGrant({
        grantToken: oauthAssertion.grantToken,
        binding: harness.credentialIssuanceBinding,
      }),
    ).rejects.toMatchObject({ reason: "grant_purpose_mismatch" });
    const user = await harness.createUser("consumed@example.com");
    await expect(
      harness.composition.consumeOAuthAuthorizationGrant({
        grantToken: oauthAssertion.grantToken,
        binding: harness.binding,
        userId: user.id,
      }),
    ).rejects.toMatchObject({ reason: "grant_unavailable" });
  });

  it("rejects an unconfigured credential issuance namespace", async () => {
    const harness = await createHarness();
    await harness.register();

    await expect(
      harness.credentialIssuanceChallenge({
        ...harness.credentialIssuanceBinding,
        namespace: "untrusted-namespace",
      }),
    ).rejects.toMatchObject({ status: "FORBIDDEN" });
  });

  it("allows exactly one concurrent consumer of a registration challenge", async () => {
    const harness = await createHarness();
    const challenge = await harness.registrationChallenge(KEY_ID);
    const attempts = await Promise.allSettled([
      harness.verifyRegistration(challenge.challengeToken, KEY_ID),
      harness.verifyRegistration(challenge.challengeToken, KEY_ID),
    ]);

    expect(
      attempts.filter((result) => result.status === "fulfilled"),
    ).toHaveLength(1);
    expect(
      attempts.filter((result) => result.status === "rejected"),
    ).toHaveLength(1);
    expect(harness.diagnostics).toHaveBeenCalledWith(
      expect.objectContaining({
        stage: "challenge",
        reason: "challenge_unavailable",
      }),
    );
  });

  it("allows exactly one concurrent counter advance from the same prior value", async () => {
    const barrier = twoPartyBarrier();
    const harness = await createHarness({ assertionBarrier: barrier });
    await harness.register();
    const first = await harness.assertionChallenge();
    const second = await harness.assertionChallenge();

    const attempts = await Promise.allSettled([
      harness.verifyAssertion(first.challengeToken),
      harness.verifyAssertion(second.challengeToken),
    ]);

    expect(
      attempts.filter((result) => result.status === "fulfilled"),
    ).toHaveLength(1);
    expect(
      attempts.filter((result) => result.status === "rejected"),
    ).toHaveLength(1);
    expect(harness.diagnostics).toHaveBeenCalledWith(
      expect.objectContaining({
        stage: "counter",
        reason: "assertion_counter_race",
      }),
    );
    await expect(harness.credential()).resolves.toMatchObject({ counter: 1 });
  });

  it("allows exactly one concurrent consumer of an OAuth grant", async () => {
    const harness = await createHarness();
    await harness.register();
    const assertion = await harness.assert();
    const user = await harness.createUser("one@example.com");

    const attempts = await Promise.allSettled([
      harness.consumeGrant(assertion.grantToken, user),
      harness.consumeGrant(assertion.grantToken, user),
    ]);

    expect(
      attempts.filter((result) => result.status === "fulfilled"),
    ).toHaveLength(1);
    expect(
      attempts.filter((result) => result.status === "rejected"),
    ).toHaveLength(1);
    expect(harness.diagnostics).toHaveBeenCalledWith(
      expect.objectContaining({
        stage: "grant-binding",
        reason: "grant_unavailable",
      }),
    );
  });

  it("consumes a grant before rejecting an OAuth binding mismatch", async () => {
    const harness = await createHarness();
    await harness.register();
    const assertion = await harness.assert();
    const user = await harness.createUser("binding@example.com");
    const mismatchedBinding = {
      ...harness.binding,
      redirectUri: "com.example.mobile:/different-callback",
    };

    await expect(
      harness.consumeGrant(assertion.grantToken, user, mismatchedBinding),
    ).rejects.toMatchObject({ status: "FORBIDDEN" });
    await expect(
      harness.consumeGrant(assertion.grantToken, user),
    ).rejects.toMatchObject({ status: "FORBIDDEN" });
    expect(harness.diagnostics).toHaveBeenCalledWith(
      expect.objectContaining({ reason: "oauth_binding_mismatch" }),
    );
  });

  it("never binds one credential to two users", async () => {
    const harness = await createHarness();
    await harness.register();
    const firstAssertion = await harness.assert();
    const firstUser = await harness.createUser("first@example.com");
    await harness.consumeGrant(firstAssertion.grantToken, firstUser);

    const secondAssertion = await harness.assert();
    const secondUser = await harness.createUser("second@example.com");
    await expect(
      harness.consumeGrant(secondAssertion.grantToken, secondUser),
    ).rejects.toMatchObject({ status: "FORBIDDEN" });
    await expect(harness.credential()).resolves.toMatchObject({
      userId: firstUser.id,
      bindingVersion: 1,
    });
  });

  it("rejects expired unbound credentials before generating an assertion challenge", async () => {
    const harness = await createHarness();
    await harness.register();
    const credential = await harness.credential();
    if (!credential) {
      expect.fail("Expected a registered credential.");
    }
    await harness.context.adapter.update({
      model: "deviceAttestationCredential",
      where: [{ field: "id", value: credential.id }],
      update: { unboundExpiresAt: new Date(Date.now() - 1) },
    });

    await expect(harness.assertionChallenge()).rejects.toMatchObject({
      status: "FORBIDDEN",
    });
    expect(harness.diagnostics).toHaveBeenCalledWith(
      expect.objectContaining({ reason: "unbound_credential_expired" }),
    );
  });

  it("enforces the active unbound credential quota", async () => {
    const harness = await createHarness({ maxUnbound: 1 });
    await harness.register(KEY_ID);
    const challenge = await harness.registrationChallenge(SECOND_KEY_ID);

    await expect(
      harness.verifyRegistration(challenge.challengeToken, SECOND_KEY_ID),
    ).rejects.toMatchObject({ status: "SERVICE_UNAVAILABLE" });
    expect(harness.diagnostics).toHaveBeenCalledWith(
      expect.objectContaining({ reason: "unbound_credential_quota_reached" }),
    );
  });

  it("does not reactivate or replace an already registered key", async () => {
    const harness = await createHarness();
    const registration = await harness.register();
    const challenge = await harness.registrationChallenge(KEY_ID);

    await expect(
      harness.verifyRegistration(challenge.challengeToken, KEY_ID),
    ).rejects.toMatchObject({ status: "FORBIDDEN" });
    await expect(harness.credential()).resolves.toMatchObject({
      id: registration.credentialId,
      status: "active",
    });
  });

  it("retires a credential at UInt32 exhaustion but permits its final grant", async () => {
    const harness = await createHarness({ nextCounter: UINT32_MAX });
    await harness.register();
    const assertion = await harness.assert();
    const user = await harness.createUser("exhausted@example.com");

    await harness.consumeGrant(assertion.grantToken, user);
    await expect(harness.credential()).resolves.toMatchObject({
      counter: UINT32_MAX,
      status: "revoked",
      revocationReason: "counter_exhausted",
      userId: user.id,
    });
    await expect(harness.assertionChallenge()).rejects.toMatchObject({
      status: "FORBIDDEN",
    });
  });

  it.each([0, 1.5, UINT32_MAX + 1])(
    "rejects an invalid provider counter result: %s",
    async (nextCounter) => {
      const harness = await createHarness({ nextCounter });
      await harness.register();

      await expect(harness.assert()).rejects.toMatchObject({
        status: "FORBIDDEN",
      });
      expect(harness.diagnostics).toHaveBeenCalledWith(
        expect.objectContaining({ reason: "invalid_assertion_counter" }),
      );
    },
  );

  it("rejects a malformed counter returned by a database adapter", async () => {
    const harness = await createHarness();
    await harness.register();
    const credential = await harness.credential();
    if (!credential) {
      expect.fail("Expected a registered credential.");
    }
    await harness.context.adapter.update({
      model: "deviceAttestationCredential",
      where: [{ field: "id", value: credential.id }],
      update: { counter: "1e2" },
    });

    await expect(harness.assert()).rejects.toMatchObject({
      status: "FORBIDDEN",
    });
    expect(harness.diagnostics).toHaveBeenCalledWith(
      expect.objectContaining({
        stage: "storage",
        reason: "invalid_stored_counter",
      }),
    );
  });

  it("rejects a malformed validation category returned by a database adapter", async () => {
    const harness = await createHarness();
    await harness.register();
    const credential = await harness.credential();
    if (!credential) {
      expect.fail("Expected a registered credential.");
    }
    await harness.context.adapter.update({
      model: "deviceAttestationCredential",
      where: [{ field: "id", value: credential.id }],
      update: { validationCategory: "1e2" },
    });

    await expect(harness.assert()).rejects.toMatchObject({
      status: "FORBIDDEN",
    });
    expect(harness.diagnostics).toHaveBeenCalledWith(
      expect.objectContaining({
        stage: "storage",
        reason: "invalid_stored_validation_category",
      }),
    );
  });

  it("preserves host token fields for unprotected and refresh grants", async () => {
    const hostCallback = vi.fn().mockResolvedValue({ host: "field" });
    const harness = await createHarness({ hostCallback });
    const user = await harness.createUser("host@example.com");

    await expect(
      harness.invokeTokenCallback({
        grantType: "authorization_code",
        user,
        query: { ...oauthQuery(harness.binding), client_id: "web-app" },
      }),
    ).resolves.toEqual({ host: "field" });
    await expect(
      harness.invokeTokenCallback({
        grantType: "refresh_token",
        user,
        query: oauthQuery(harness.binding),
      }),
    ).resolves.toEqual({ host: "field" });
    expect(hostCallback).toHaveBeenCalledTimes(2);
  });

  it("requires a grant for protected authorization-code issuance", async () => {
    const harness = await createHarness();
    const user = await harness.createUser("missing@example.com");

    await expect(
      harness.invokeTokenCallback({
        grantType: "authorization_code",
        user,
        query: oauthQuery(harness.binding),
      }),
    ).rejects.toMatchObject({ status: "FORBIDDEN" });
    expect(harness.diagnostics).toHaveBeenCalledWith(
      expect.objectContaining({ reason: "missing_grant_or_user" }),
    );
  });

  it("does not let a throwing diagnostic reporter replace the public error", async () => {
    const report = vi
      .fn()
      .mockRejectedValue(new Error("telemetry unavailable"));
    const harness = await createHarness({ report });

    await expect(
      harness.auth.api.createDeviceAttestationChallenge({
        body: {
          provider: "unknown-provider",
          applicationId: APP_ID,
          operation: "register",
          keyId: KEY_ID.toString("base64"),
          purpose: "credential-registration",
        },
      }),
    ).rejects.toMatchObject({ status: "FORBIDDEN" });
    expect(report).toHaveBeenCalledWith(
      expect.objectContaining({
        provider: "unknown-provider",
        stage: "request",
        reason: "unknown_provider",
      }),
    );
  });

  it("contains a synchronous diagnostic reporter failure", async () => {
    const report = vi.fn(() => {
      throw new Error("telemetry failed synchronously");
    });
    const harness = await createHarness({ report });

    await expect(
      harness.auth.api.createDeviceAttestationChallenge({
        body: {
          provider: "unknown-provider",
          applicationId: APP_ID,
          operation: "register",
          keyId: KEY_ID.toString("base64"),
          purpose: "credential-registration",
        },
      }),
    ).rejects.toMatchObject({ status: "FORBIDDEN" });
    expect(report).toHaveBeenCalledOnce();
  });

  it("does not wait for a stalled diagnostic reporter", async () => {
    const report = vi.fn(() => new Promise<void>(() => undefined));
    const harness = await createHarness({ report });

    const result = await Promise.race([
      harness.auth.api
        .createDeviceAttestationChallenge({
          body: {
            provider: "unknown-provider",
            applicationId: APP_ID,
            operation: "register",
            keyId: KEY_ID.toString("base64"),
            purpose: "credential-registration",
          },
        })
        .then(
          () => "unexpected-success",
          (error: unknown) =>
            error instanceof APIError ? error.status : "unexpected-error",
        ),
      new Promise<string>((resolve) => {
        setTimeout(() => resolve("reporter-timeout"), 100);
      }),
    ]);

    expect(result).toBe("FORBIDDEN");
    expect(report).toHaveBeenCalledWith(
      expect.objectContaining({
        provider: "unknown-provider",
        stage: "request",
        reason: "unknown_provider",
      }),
    );
  });

  it("rejects invalid composition configuration", () => {
    const provider = mockProvider({});
    expect(() => createComposition({ providers: [] })).toThrow(TypeError);
    expect(() =>
      createComposition({ providers: [provider, provider] }),
    ).toThrow(TypeError);
    expect(() =>
      createComposition({ providers: [provider], protectedClientIds: [] }),
    ).toThrow(TypeError);
    expect(() =>
      createComposition({
        providers: [provider],
        protectedClientIds: ["mobile-app", "mobile-app"],
      }),
    ).toThrow(TypeError);
  });
});

interface HarnessOptions {
  assertionBarrier?: () => Promise<void>;
  hostCallback?: (
    context: OAuthProviderTokenContext,
  ) => Promise<Record<string, unknown>>;
  maxUnbound?: number;
  nextCounter?: number;
  report?: (event: DeviceAttestationDiagnosticEvent) => void | Promise<void>;
}

async function createHarness(options: HarnessOptions = {}) {
  const diagnostics = options.report ?? vi.fn();
  const provider = mockProvider(options);
  const composition = createComposition({
    providers: [provider],
    report: diagnostics,
    ...(options.maxUnbound === undefined
      ? {}
      : { maxUnbound: options.maxUnbound }),
  });
  const auth = betterAuth({
    baseURL: "http://localhost:3000",
    secret: "test-secret-that-is-at-least-thirty-two-characters",
    plugins: [composition.serverPlugin],
  });
  const context = await auth.$context;
  const binding = oauthBinding();
  const credentialIssuanceBinding = hostCredentialIssuanceBinding();
  const protectedOAuth = composition.protectOAuthProvider({
    loginPage: "/login",
    consentPage: "/consent",
    ...(options.hostCallback === undefined
      ? {}
      : { customTokenResponseFields: options.hostCallback }),
  });

  const registrationChallenge = (keyId = KEY_ID) =>
    auth.api.createDeviceAttestationChallenge({
      body: {
        provider: provider.id,
        applicationId: APP_ID,
        operation: "register",
        keyId: keyId.toString("base64"),
        purpose: "credential-registration",
      },
    });
  const verifyRegistration = (challengeToken: string, keyId = KEY_ID) =>
    auth.api.verifyDeviceAttestation({
      body: {
        challengeToken,
        keyId: keyId.toString("base64"),
        evidence: Buffer.from("registration-evidence").toString("base64"),
      },
    });
  const register = async (keyId = KEY_ID) => {
    const challenge = await registrationChallenge(keyId);
    const result = await verifyRegistration(challenge.challengeToken, keyId);
    if (result.credentialState !== "registered-unbound") {
      throw new TypeError("Expected a credential registration.");
    }
    return result;
  };
  const assertionChallenge = () =>
    auth.api.createDeviceAttestationChallenge({
      body: {
        provider: provider.id,
        applicationId: APP_ID,
        operation: "assert",
        keyId: KEY_ID.toString("base64"),
        purpose: "oauth-authorization",
        binding,
      },
    });
  const verifyAssertion = (challengeToken: string) =>
    auth.api.verifyDeviceAttestation({
      body: {
        challengeToken,
        keyId: KEY_ID.toString("base64"),
        evidence: Buffer.from("assertion-evidence").toString("base64"),
      },
    });
  const assert = async () => {
    const challenge = await assertionChallenge();
    const result = await verifyAssertion(challenge.challengeToken);
    if (result.credentialState !== "asserted") {
      throw new TypeError("Expected an assertion grant.");
    }
    return result;
  };
  const credentialIssuanceChallenge = (
    issuanceBinding = credentialIssuanceBinding,
  ) =>
    auth.api.createDeviceAttestationChallenge({
      body: {
        provider: provider.id,
        applicationId: APP_ID,
        operation: "assert",
        keyId: KEY_ID.toString("base64"),
        purpose: "credential-issuance",
        binding: issuanceBinding,
      },
    });
  const assertCredentialIssuance = async () => {
    const challenge = await credentialIssuanceChallenge();
    const result = await verifyAssertion(challenge.challengeToken);
    if (result.credentialState !== "asserted") {
      throw new TypeError("Expected a credential issuance grant.");
    }
    return result;
  };
  const createUser = (email: string) =>
    context.adapter.create<{
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
        email,
        emailVerified: true,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
    });
  const invokeTokenCallback = (input: {
    grantType: string;
    user: Awaited<ReturnType<typeof createUser>>;
    query: StoredAuthorizationQuery & { device_attestation?: string };
  }) =>
    Promise.resolve(
      protectedOAuth.customTokenResponseFields?.({
        grantType: input.grantType,
        user: input.user,
        scopes: ["openid"],
        verificationValue: {
          type: "authorization_code",
          query: input.query,
          sessionId: "session-1",
          userId: input.user.id,
        },
      }),
    );
  const consumeGrant = (
    grantToken: string,
    user: Awaited<ReturnType<typeof createUser>>,
    grantBinding = binding,
  ) =>
    invokeTokenCallback({
      grantType: "authorization_code",
      user,
      query: {
        ...oauthQuery(grantBinding),
        device_attestation: grantToken,
      },
    });
  const credential = () =>
    context.adapter.findOne<StoredAttestationCredential>({
      model: "deviceAttestationCredential",
      where: [
        { field: "provider", value: provider.id },
        { field: "applicationId", value: APP_ID },
      ],
    });

  return {
    assert,
    assertCredentialIssuance,
    assertionChallenge,
    auth,
    binding,
    credentialIssuanceBinding,
    credentialIssuanceChallenge,
    composition,
    consumeGrant,
    context,
    createUser,
    credential,
    diagnostics,
    invokeTokenCallback,
    register,
    registrationChallenge,
    verifyAssertion,
    verifyRegistration,
  };
}

function createComposition(input: {
  providers: DeviceAttestationProvider[];
  protectedClientIds?: string[];
  maxUnbound?: number;
  report?: (event: DeviceAttestationDiagnosticEvent) => void | Promise<void>;
}) {
  return createDeviceAttestation({
    providers: input.providers,
    purposes: {
      credentialRegistration: {
        challengeTtlSeconds: 120,
        unboundCredentialTtlSeconds: 3600,
        ...(input.maxUnbound === undefined
          ? {}
          : { maxActiveUnboundCredentialsPerApplication: input.maxUnbound }),
      },
      oauthAuthorization: {
        protectedClientIds: input.protectedClientIds ?? ["mobile-app"],
        challengeTtlSeconds: 120,
        grantTtlSeconds: 300,
        requireDpopJkt: true,
      },
      credentialIssuance: {
        allowedNamespaces: ["example.device-pairing"],
        challengeTtlSeconds: 120,
        grantTtlSeconds: 300,
        requireDpopJkt: true,
      },
    },
    ...(input.report === undefined
      ? {}
      : { diagnostics: { report: input.report } }),
  });
}

function mockProvider(options: HarnessOptions): DeviceAttestationProvider {
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
      return Promise.resolve({
        applicationId: input.applicationId,
        environment: "production",
        publicKey: PUBLIC_KEY,
        counter: 0,
        extensionsPresent: true,
        validationCategory: 2,
        bundleVersion: "42",
      });
    },
    async verifyAssertion(input) {
      await options.assertionBarrier?.();
      return {
        counter: options.nextCounter ?? input.credential.counter + 1,
        extensionsPresent: true,
        validationCategory: 4,
        bundleVersion: "42",
      };
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

function hostCredentialIssuanceBinding(): CredentialIssuanceBinding {
  return {
    namespace: "example.device-pairing",
    subject: sha256(Buffer.from("pairing-transaction")).toString("base64url"),
    dpopJkt: sha256(Buffer.from("paired-device-dpop-key")).toString(
      "base64url",
    ),
  };
}

function oauthQuery(
  binding: OAuthAuthorizationBinding,
): StoredAuthorizationQuery {
  return {
    response_type: "code",
    client_id: binding.clientId,
    redirect_uri: binding.redirectUri,
    code_challenge: binding.codeChallenge,
    code_challenge_method: binding.codeChallengeMethod,
    dpop_jkt: binding.dpopJkt,
    scope: binding.scope,
    ...(binding.resources === undefined ? {} : { resource: binding.resources }),
    ...(binding.nonce === undefined ? {} : { nonce: binding.nonce }),
  };
}

function twoPartyBarrier(): () => Promise<void> {
  let arrivals = 0;
  let release: () => void = () => {};
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  return async () => {
    arrivals += 1;
    if (arrivals === 2) {
      release();
    }
    await gate;
  };
}
