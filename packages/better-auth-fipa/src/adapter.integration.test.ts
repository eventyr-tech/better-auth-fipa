import type { StoredAuthorizationQuery } from "@better-auth/oauth-provider";
import { getTestInstance } from "better-auth/test";
import { describe, expect, it } from "vitest";

import { deviceAttestationClient } from "./client.js";
import { decodeBase64Strict } from "./encoding/base64.js";
import { createDeviceAttestation } from "./plugin.js";
import { sha256 } from "./protocol/crypto.js";
import type {
  DeviceAttestationProvider,
  OAuthAuthorizationBinding,
  OAuthProviderTokenContext,
  StoredAttestationCredential,
} from "./types.js";

const APP_ID = "TEAMID.com.example.adapter-contract";
const KEY_ID = Buffer.alloc(32, 0x71);
const PUBLIC_KEY = Buffer.alloc(91, 0x72).toString("base64");
const UINT32_MAX = 0xffff_ffff;
const NODE_SQLITE_AVAILABLE = supportsBuiltInSqlite();
const POSTGRES_ENABLED = process.env.TEST_POSTGRES === "true";

describe.runIf(NODE_SQLITE_AVAILABLE)(
  "Better Auth SQLite plugin contract",
  () => {
    it("preserves the device-attestation lifecycle and atomic invariants", async () => {
      await exerciseAdapterContract("sqlite");
    });
  },
);

describe.runIf(POSTGRES_ENABLED)(
  "Better Auth PostgreSQL plugin contract",
  () => {
    it("preserves the device-attestation lifecycle and atomic invariants", async () => {
      await exerciseAdapterContract("postgres");
    });
  },
);

async function exerciseAdapterContract(
  testWith: "sqlite" | "postgres",
): Promise<void> {
  const assertionBarrier = twoPartyBarrier();
  const provider = mockProvider(assertionBarrier);
  const diagnosticReasons: string[] = [];
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
    diagnostics: {
      report(event) {
        diagnosticReasons.push(`${event.stage}:${event.reason}`);
      },
    },
  });
  const { auth, client, signInWithTestUser } = await getTestInstance(
    { plugins: [composition.serverPlugin] },
    {
      testWith,
      clientOptions: { plugins: [deviceAttestationClient()] },
    },
  );
  const context = await auth.$context;
  const binding = oauthBinding();
  const verifyRegistration = (challengeToken: string) =>
    auth.api.verifyDeviceAttestation({
      body: {
        challengeToken,
        keyId: KEY_ID.toString("base64"),
        evidence: Buffer.from("registration").toString("base64"),
      },
    });
  const createAssertionChallenge = async () => {
    const response = await client.deviceAttestation.challenge({
      provider: provider.id,
      applicationId: APP_ID,
      operation: "assert",
      keyId: KEY_ID.toString("base64"),
      purpose: "oauth-authorization",
      binding: clientBinding(binding),
    });
    if (response.error || !isChallengeData(response.data)) {
      expect.fail(response.error?.message ?? "Missing assertion challenge.");
    }
    return response.data;
  };
  const verifyAssertion = (challengeToken: string) =>
    auth.api.verifyDeviceAttestation({
      body: {
        challengeToken,
        keyId: KEY_ID.toString("base64"),
        evidence: Buffer.from("assertion").toString("base64"),
      },
    });

  const challengeResponse = await client.deviceAttestation.challenge({
    provider: provider.id,
    applicationId: APP_ID,
    operation: "register",
    keyId: KEY_ID.toString("base64"),
    purpose: "credential-registration",
  });
  if (challengeResponse.error || !isChallengeData(challengeResponse.data)) {
    expect.fail(
      challengeResponse.error?.message ?? "Missing registration challenge.",
    );
  }
  const registrationAttempts = await Promise.allSettled([
    verifyRegistration(challengeResponse.data.challengeToken),
    verifyRegistration(challengeResponse.data.challengeToken),
  ]);
  expect(
    registrationAttempts.filter((result) => result.status === "fulfilled"),
  ).toHaveLength(1);

  const credential = await context.adapter.findOne<StoredAttestationCredential>(
    {
      model: "deviceAttestationCredential",
      where: [{ field: "applicationId", value: APP_ID }],
    },
  );
  if (!credential) {
    expect.fail("Expected registration to persist a credential.");
  }
  const storedCategory: unknown = credential.validationCategory;
  expect(storedCategory).toBe(
    testWith === "postgres" ? String(UINT32_MAX) : UINT32_MAX,
  );
  await context.adapter.update({
    model: "deviceAttestationCredential",
    where: [{ field: "id", value: credential.id }],
    update: { counter: 0x7fff_ffff },
  });

  const firstChallenge = await createAssertionChallenge();
  const secondChallenge = await createAssertionChallenge();
  const assertionAttempts = await Promise.allSettled([
    verifyAssertion(firstChallenge.challengeToken),
    verifyAssertion(secondChallenge.challengeToken),
  ]);
  const successfulAssertions = assertionAttempts.filter(
    (
      result,
    ): result is PromiseFulfilledResult<{
      grantToken: string;
      expiresAt: Date;
      credentialState: "asserted";
    }> => result.status === "fulfilled",
  );
  const assertionFailures = assertionAttempts
    .filter(
      (result): result is PromiseRejectedResult => result.status === "rejected",
    )
    .map((result) =>
      result.reason instanceof Error
        ? `${result.reason.name}: ${result.reason.message}`
        : String(result.reason),
    );
  expect(
    successfulAssertions,
    [...assertionFailures, ...diagnosticReasons].join("\n"),
  ).toHaveLength(1);
  expect(
    assertionAttempts.filter((result) => result.status === "rejected"),
  ).toHaveLength(1);

  const advanced = await context.adapter.findOne<StoredAttestationCredential>({
    model: "deviceAttestationCredential",
    where: [{ field: "id", value: credential.id }],
  });
  expect(Number(advanced?.counter)).toBe(0x8000_0000);

  const { user } = await signInWithTestUser();
  const protectedOAuth = composition.protectOAuthProvider({
    loginPage: "/login",
    consentPage: "/consent",
    customTokenResponseFields: (context: OAuthProviderTokenContext) => {
      void context;
      return {};
    },
  });
  const grantToken = successfulAssertions[0]?.value.grantToken;
  if (!grantToken) {
    expect.fail("Expected a successful assertion grant.");
  }
  const tokenContext = oauthTokenContext(binding, grantToken, user);
  const grantAttempts = await Promise.allSettled([
    Promise.resolve(protectedOAuth.customTokenResponseFields?.(tokenContext)),
    Promise.resolve(protectedOAuth.customTokenResponseFields?.(tokenContext)),
  ]);
  expect(
    grantAttempts.filter((result) => result.status === "fulfilled"),
  ).toHaveLength(1);
  expect(
    grantAttempts.filter((result) => result.status === "rejected"),
  ).toHaveLength(1);
}

function isChallengeData(value: unknown): value is {
  challengeToken: string;
} {
  if (!value || typeof value !== "object") {
    return false;
  }
  return typeof Reflect.get(value, "challengeToken") === "string";
}

function mockProvider(
  assertionBarrier: () => Promise<void>,
): DeviceAttestationProvider {
  return {
    id: "adapter-contract-attestation",
    maxEvidenceBytes: 1024,
    decodeKeyId(value) {
      return decodeBase64Strict(value, {
        label: "adapter_contract_key_id",
        exactBytes: 32,
        maxBytes: 32,
      });
    },
    verifyRegistration() {
      return Promise.resolve({
        applicationId: APP_ID,
        environment: "production",
        publicKey: PUBLIC_KEY,
        counter: 0,
        extensionsPresent: true,
        validationCategory: UINT32_MAX,
      });
    },
    async verifyAssertion(input) {
      await assertionBarrier();
      expect(input.credential.validationCategory).toBe(UINT32_MAX);
      return {
        counter: input.credential.counter + 1,
        extensionsPresent: true,
        validationCategory: UINT32_MAX,
      };
    },
  };
}

function oauthBinding(): OAuthAuthorizationBinding {
  return {
    clientId: "mobile-app",
    redirectUri: "com.example.mobile:/oauth/callback",
    codeChallenge: Buffer.alloc(32, 0x73).toString("base64url"),
    codeChallengeMethod: "S256",
    dpopJkt: sha256(Buffer.from("adapter-contract-dpop-key")).toString(
      "base64url",
    ),
    scope: "openid offline_access",
  };
}

function clientBinding(binding: OAuthAuthorizationBinding) {
  return {
    clientId: binding.clientId,
    redirectUri: binding.redirectUri,
    codeChallenge: binding.codeChallenge,
    codeChallengeMethod: binding.codeChallengeMethod,
    dpopJkt: binding.dpopJkt,
    scope: binding.scope,
    ...(binding.resources === undefined
      ? {}
      : { resources: [...binding.resources] }),
    ...(binding.nonce === undefined ? {} : { nonce: binding.nonce }),
  };
}

function oauthTokenContext(
  binding: OAuthAuthorizationBinding,
  grantToken: string,
  user: {
    id: string;
    name: string;
    email: string;
    emailVerified: boolean;
    createdAt: Date;
    updatedAt: Date;
  },
): OAuthProviderTokenContext {
  const query: StoredAuthorizationQuery & { device_attestation: string } = {
    response_type: "code",
    client_id: binding.clientId,
    redirect_uri: binding.redirectUri,
    code_challenge: binding.codeChallenge,
    code_challenge_method: binding.codeChallengeMethod,
    dpop_jkt: binding.dpopJkt,
    scope: binding.scope,
    device_attestation: grantToken,
  };
  return {
    grantType: "authorization_code",
    user,
    scopes: ["openid", "offline_access"],
    verificationValue: {
      type: "authorization_code",
      query,
      sessionId: "adapter-contract-session",
      userId: user.id,
    },
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

function supportsBuiltInSqlite(): boolean {
  const [major = 0, minor = 0] = process.versions.node
    .split(".")
    .map((value) => Number.parseInt(value, 10));
  return major > 22 || (major === 22 && minor >= 5);
}
