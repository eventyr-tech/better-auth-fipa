import type { BetterAuthPlugin } from "better-auth";
import { userSecuritySchema } from "./user-security.js";
import type { DBPrimitive } from "@better-auth/core/db";

const text = {
  type: "string",
  required: true,
  input: false,
  returned: false,
} as const;
const date = {
  type: "date",
  required: true,
  input: false,
  returned: false,
} as const;
const integer = {
  type: "number",
  required: true,
  input: false,
  returned: false,
} as const;

// Better Auth's default SQLite JSON decoder revives every ISO-looking string
// as Date, including opaque protocol values. Decode before that generic pass
// so binding bytes and scope/resource strings survive a round trip unchanged.
const structured = {
  output: (value: DBPrimitive): DBPrimitive =>
    typeof value === "string" ? (JSON.parse(value) as DBPrimitive) : value,
};

/** Internal schema: installed by the first-party integration, not the legacy plugin. */
export const firstPartyStateSchema = {
  ...userSecuritySchema,
  firstPartyEmailDelivery: {
    fields: {
      keyHash: { ...text, unique: true },
      bindingHash: text,
      outcome: {
        ...text,
        type: ["dispatching", "requested", "rejected", "unknown"],
      },
      expiresAt: { ...date, index: true },
    },
  },
  firstPartyEmailBudget: {
    fields: {
      keyHash: { ...text, unique: true },
      revision: integer,
      requests: integer,
      windowExpiresAt: { ...date, index: true },
      nextRequestAt: date,
    },
  },
  session: {
    fields: {
      firstPartyBrowserHandoffId: { ...text, required: false },
      firstPartyBrowserSecurityHash: { ...text, required: false },
    },
  },
  firstPartyBrowser: {
    fields: {
      requestHash: { ...text, unique: true },
      cookieHash: { ...text, required: false, unique: true },
      clientId: text,
      sessionId: { ...text, index: true },
      attemptId: text,
      stepId: text,
      redirectUri: text,
      state: text,
      status: { ...text, type: ["prepared", "opened", "consumed"] },
      openedAt: { ...date, required: false },
      expiresAt: date,
    },
  },
  firstPartyAccess: {
    fields: {
      tokenHash: { ...text, unique: true },
      familyId: { ...text, index: true },
      scopes: { ...text, type: "string[]", transform: structured },
      resources: { ...text, type: "string[]", transform: structured },
      expiresAt: date,
    },
  },
  firstPartyRefresh: {
    fields: {
      tokenHash: { ...text, unique: true },
      providerTokenId: { ...text, unique: true },
      familyId: { ...text, index: true },
      status: { ...text, type: ["active", "used"] },
      expiresAt: date,
    },
  },
  firstPartySession: {
    fields: {
      handleHash: { ...text, unique: true },
      credentialId: { ...text, index: true },
      credentialVersion: integer,
      clientId: text,
      dpopJkt: text,
      activeAttemptId: { ...text, required: false },
      userId: { ...text, required: false },
      authenticatedAt: { ...date, required: false },
      generation: integer,
      status: { ...text, type: ["active", "revoked"] },
      createdAt: date,
      expiresAt: date,
      absoluteExpiresAt: date,
    },
  },
  firstPartyAttempt: {
    fields: {
      attemptId: { ...text, unique: true },
      sessionId: { ...text, index: true },
      binding: { ...text, type: "json", transform: structured },
      receipt: { ...text, type: "json", transform: structured },
      evidenceExpiresAt: date,
      stepId: text,
      status: {
        ...text,
        type: [
          "password",
          "authentication",
          "email-otp",
          "email-otp-sending",
          "processing",
          "evidence",
          "browser",
          "code-issued",
          "cancelled",
        ],
      },
      operationId: { ...text, required: false },
      userId: { ...text, required: false },
      authenticatedAt: { ...date, required: false },
      userSecurityHash: { ...text, required: false },
      methods: { ...text, type: "string[]", transform: structured },
      email: { ...text, required: false },
      resumeStatus: { ...text, required: false },
      authenticationMethods: {
        ...text,
        type: "string[]",
        transform: structured,
      },
      createdAt: date,
      expiresAt: date,
    },
  },
  firstPartyAndroidKey: {
    fields: {
      lookupKey: { ...text, unique: true },
      provider: text,
      clientId: { ...text, index: true },
      applicationId: text,
      environment: { ...text, type: ["production"] },
      publicKey: { ...text, required: false },
      dpopJkt: text,
      // Android-specific, verified creation evidence. Never an Apple counter.
      attestationChallenge: { ...text, required: false },
      certificateChain: {
        ...text,
        type: "string[]",
        transform: structured,
        required: false,
      },
      keyVerifiedAt: date,
      keyEvidence: {
        ...text,
        type: "json",
        transform: structured,
        required: false,
      },
      userId: { ...text, required: false, index: true },
      externallyBound: { ...text, type: "boolean", defaultValue: false },
      bindingVersion: integer,
      status: { ...text, type: ["active", "expired", "revoked"] },
      unboundExpiresAt: { ...date, required: false, index: true },
      createdAt: date,
      updatedAt: date,
      boundAt: { ...date, required: false },
      lastUsedAt: { ...date, required: false },
      revokedAt: { ...date, required: false },
      revocationReason: {
        ...text,
        required: false,
        type: ["user", "user_deleted", "provider"],
      },
    },
  },
  firstPartyCredential: {
    fields: {
      issuer: text,
      clientId: { ...text, index: true },
      applicationId: text,
      environment: { ...text, type: ["development", "production"] },
      provider: text,
      providerCredentialId: { ...text, unique: true },
      dpopJkt: text,
      // Preserve ownership tombstones even if the associated user is deleted.
      // The integration's user-deletion hook must retire credentials first.
      userId: { ...text, required: false, index: true },
      status: { ...text, type: ["active", "revoked"] },
      version: integer,
      revision: integer,
      createdAt: date,
      revokedAt: { ...date, required: false },
    },
  },
  firstPartyAuthorization: {
    fields: {
      attemptId: { ...text, unique: true },
      nativeSessionId: { ...text, required: false },
      nonce: { ...text, required: false },
      redirectUri: { ...text, required: false },
      credentialId: { ...text, index: true },
      credentialVersion: integer,
      providerCredentialBindingVersion: integer,
      clientId: text,
      userId: text,
      userSecurityHash: text,
      dpopJkt: text,
      codeChallenge: text,
      codeHash: { ...text, required: false, unique: true },
      codeExpiresAt: { ...date, required: false },
      status: {
        ...text,
        type: ["authorized", "code-issued", "consumed", "cancelled"],
      },
      scopes: { ...text, type: "string[]", transform: structured },
      resources: { ...text, type: "string[]", transform: structured },
      assurance: { ...text, type: "json", transform: structured },
      assuranceExpiresAt: date,
      authenticatedAt: date,
      familyExpiresAt: date,
      createdAt: date,
      expiresAt: date,
    },
  },
  firstPartyTokenFamily: {
    fields: {
      nativeSessionId: { ...text, required: false },
      scopes: { ...text, type: "string[]", transform: structured },
      resources: { ...text, type: "string[]", transform: structured },
      credentialId: { ...text, index: true },
      credentialVersion: integer,
      authorizationId: { ...text, unique: true },
      clientId: text,
      userId: text,
      userSecurityHash: text,
      dpopJkt: text,
      status: { ...text, type: ["active", "revoked"] },
      assurance: { ...text, type: "json", transform: structured },
      authenticatedAt: date,
      createdAt: date,
      expiresAt: date,
      revokedAt: { ...date, required: false },
    },
  },
} satisfies NonNullable<BetterAuthPlugin["schema"]>;
