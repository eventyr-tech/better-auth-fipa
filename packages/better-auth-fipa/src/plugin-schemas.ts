import { z } from "zod";

import { standardBase64Length } from "./encoding/base64.js";
import { MAX_APPLICATION_ID_LENGTH } from "./limits.js";
export const oauthBindingSchema = z.object({
  clientId: z.string().min(1).max(256),
  redirectUri: z.string().min(1).max(2048),
  codeChallenge: z.string().min(1).max(256),
  codeChallengeMethod: z.literal("S256"),
  dpopJkt: z.string().min(1).max(256),
  scope: z.string().min(1).max(2048),
  resources: z.array(z.string().min(1).max(2048)).max(16).optional(),
  nonce: z.string().max(512).optional(),
});

export const credentialIssuanceBindingSchema = z.object({
  namespace: z.string().min(1).max(256),
  subject: z.string().min(1).max(512),
  dpopJkt: z.string().min(1).max(256),
});

export const challengeBodySchema = z.discriminatedUnion("purpose", [
  z.object({
    provider: z.string().min(1).max(64),
    applicationId: z.string().min(1).max(MAX_APPLICATION_ID_LENGTH),
    operation: z.literal("register"),
    keyId: z.string().min(1).max(1024),
    purpose: z.literal("credential-registration"),
  }),
  z.object({
    provider: z.string().min(1).max(64),
    applicationId: z.string().min(1).max(MAX_APPLICATION_ID_LENGTH),
    operation: z.literal("assert"),
    keyId: z.string().min(1).max(1024),
    purpose: z.literal("oauth-authorization"),
    binding: oauthBindingSchema,
  }),
  z.object({
    provider: z.string().min(1).max(64),
    applicationId: z.string().min(1).max(MAX_APPLICATION_ID_LENGTH),
    operation: z.literal("assert"),
    keyId: z.string().min(1).max(1024),
    purpose: z.literal("credential-issuance"),
    binding: credentialIssuanceBindingSchema,
  }),
]);

export function createVerifyBodySchema(maxEvidenceBytes: number) {
  return z.object({
    challengeToken: z.string().min(1).max(128),
    keyId: z.string().min(1).max(1024),
    evidence: z.string().min(1).max(standardBase64Length(maxEvidenceBytes)),
  });
}

export const retireBodySchema = z.object({
  credentialId: z.string().min(1).max(512),
});

export const challengeStateSchema = z.object({
  version: z.literal(1),
  provider: z.string(),
  applicationId: z.string().min(1).max(MAX_APPLICATION_ID_LENGTH),
  operation: z.enum(["register", "assert"]),
  purpose: z.enum([
    "credential-registration",
    "credential-issuance",
    "oauth-authorization",
  ]),
  credentialLookupKey: z.string(),
  clientDataHash: z.string(),
  bindingHash: z.string().optional(),
});

export const grantStateSchema = z.object({
  version: z.literal(1),
  provider: z.string(),
  applicationId: z.string().min(1).max(MAX_APPLICATION_ID_LENGTH),
  credentialId: z.string(),
  credentialBindingVersion: z.number().int().nonnegative(),
  purpose: z.enum(["credential-issuance", "oauth-authorization"]),
  bindingHash: z.string(),
  counterExhausted: z.boolean(),
});
