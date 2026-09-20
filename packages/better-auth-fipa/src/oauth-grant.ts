import { decodeBase64UrlStrict } from "./encoding/base64.js";
import { DeviceAttestationError, rejection } from "./errors.js";
import { grantStateSchema } from "./plugin-schemas.js";
import {
  hashCredentialIssuanceBinding,
  hashOAuthBinding,
  normalizeOAuthBinding,
} from "./protocol/binding.js";
import { equalBytes, hmacSha256 } from "./protocol/crypto.js";
import {
  CREDENTIAL_MODEL,
  requireUsableCredential,
  type RuntimeContext,
} from "./credential-store.js";
import type {
  CredentialIssuanceBinding,
  OAuthAuthorizationBinding,
  OAuthProviderTokenContext,
  StoredAttestationCredential,
  VerifiedAttestationGrant,
  VerifiedCredentialIssuanceGrant,
} from "./types.js";

type GrantPurpose = "credential-issuance" | "oauth-authorization";

export async function consumeAndBindGrant(
  runtime: RuntimeContext,
  info: OAuthProviderTokenContext,
): Promise<void> {
  const query = info.verificationValue?.query;
  const grantToken = readQueryString(query, "device_attestation");
  const userId = info.user?.id;
  if (!grantToken || !userId) {
    throw new DeviceAttestationError({
      code: "DEVICE_ATTESTATION_GRANT_REQUIRED",
      stage: "grant-binding",
      reason: "missing_grant_or_user",
    });
  }

  await consumeOAuthAuthorizationGrant(runtime, {
    grantToken,
    userId,
    binding: oauthBindingFromQuery(query),
  });
}

export async function consumeOAuthAuthorizationGrant(
  runtime: RuntimeContext,
  input: {
    grantToken: string;
    binding: OAuthAuthorizationBinding;
    userId: string;
  },
): Promise<VerifiedAttestationGrant> {
  if (!input.userId) {
    throw rejection("grant-binding", "missing_user");
  }
  const { credential, exhaustedCredential, grant } = await consumeGrant(
    runtime,
    input.grantToken,
    "oauth-authorization",
    hashOAuthBinding(input.binding),
  );

  if (credential.userId === input.userId) {
    return verifiedOAuthGrant(credential, input.userId);
  }
  if (credential.userId) {
    throw rejection("credential-binding", "credential_user_mismatch");
  }
  if (
    !credential.externallyBound &&
    (!credential.unboundExpiresAt ||
      credential.unboundExpiresAt.getTime() <= Date.now())
  ) {
    throw rejection("credential-binding", "unbound_credential_expired");
  }

  const bound = await runtime.adapter.incrementOne<StoredAttestationCredential>(
    {
      model: CREDENTIAL_MODEL,
      where: [
        { field: "id", value: credential.id },
        {
          field: "bindingVersion",
          value: grant.credentialBindingVersion,
        },
        { field: "userId", value: null },
        {
          field: "status",
          value: exhaustedCredential ? "revoked" : "active",
        },
      ],
      increment: { bindingVersion: 1 },
      set: {
        userId: input.userId,
        boundAt: new Date(),
        unboundExpiresAt: null,
      },
    },
  );
  if (!bound) {
    const raced = await findCredential(runtime, credential.id);
    if (
      raced?.userId !== input.userId ||
      (!exhaustedCredential && raced.status !== "active")
    ) {
      throw rejection("credential-binding", "credential_binding_race");
    }
    return verifiedOAuthGrant(raced, input.userId);
  }
  return verifiedOAuthGrant(bound, input.userId);
}

export async function consumeCredentialIssuanceGrant(
  runtime: RuntimeContext,
  input: {
    grantToken: string;
    binding: CredentialIssuanceBinding;
  },
): Promise<VerifiedCredentialIssuanceGrant> {
  const { credential, exhaustedCredential, grant } = await consumeGrant(
    runtime,
    input.grantToken,
    "credential-issuance",
    hashCredentialIssuanceBinding(input.binding),
  );
  const bound = await runtime.adapter.incrementOne<StoredAttestationCredential>(
    {
      model: CREDENTIAL_MODEL,
      where: [
        { field: "id", value: credential.id },
        {
          field: "bindingVersion",
          value: grant.credentialBindingVersion,
        },
        {
          field: "status",
          value: exhaustedCredential ? "revoked" : "active",
        },
      ],
      increment: { bindingVersion: 1 },
      set: {
        externallyBound: true,
        unboundExpiresAt: null,
      },
    },
  );
  if (!bound) {
    throw rejection("credential-binding", "credential_binding_race");
  }
  return verifiedCredentialIssuanceGrant(bound);
}

/** Internal legacy-login admission: consume the signed binding before account
 * work, but defer user ownership until actual authentication and issuance.
 * The caller must include this consumption in its continuation transaction. */
export async function consumeOAuthAdmissionGrant(
  runtime: RuntimeContext,
  grantToken: string,
  binding: OAuthAuthorizationBinding,
) {
  const verified = await consumeGrant(
    runtime,
    grantToken,
    "oauth-authorization",
    hashOAuthBinding(binding),
  );
  requireUsableCredential(verified.credential);
  return verified;
}

async function consumeGrant(
  runtime: RuntimeContext,
  grantToken: string,
  purpose: GrantPurpose,
  actualBindingHash: Uint8Array,
) {
  decodeBase64UrlStrict(grantToken, {
    label: "grant_token",
    maxBytes: 32,
    exactBytes: 32,
  });
  const verification = await runtime.internalAdapter.consumeVerificationValue(
    grantIdentifier(runtime.secret, grantToken),
  );
  if (!verification) {
    throw new DeviceAttestationError({
      code: "DEVICE_ATTESTATION_GRANT_REQUIRED",
      stage: "grant-binding",
      reason: "grant_unavailable",
    });
  }
  const grant = parseGrantState(verification.value);
  if (grant.purpose !== purpose) {
    throw rejection("grant-binding", "grant_purpose_mismatch");
  }
  if (
    !equalBytes(actualBindingHash, Buffer.from(grant.bindingHash, "base64url"))
  ) {
    throw rejection(
      "grant-binding",
      purpose === "oauth-authorization"
        ? "oauth_binding_mismatch"
        : "credential_issuance_binding_mismatch",
    );
  }

  const credential = await findCredential(runtime, grant.credentialId);
  const exhaustedCredential =
    grant.counterExhausted &&
    credential?.status === "revoked" &&
    credential.revocationReason === "counter_exhausted";
  if (!exhaustedCredential) {
    requireUsableCredential(credential);
  }
  if (!credential) {
    throw rejection("credential-binding", "credential_not_found");
  }
  if (
    credential.provider !== grant.provider ||
    credential.applicationId !== grant.applicationId ||
    credential.bindingVersion !== grant.credentialBindingVersion
  ) {
    throw rejection("grant-binding", "grant_credential_mismatch");
  }
  return {
    credential,
    exhaustedCredential,
    grant,
    verifiedAt: verification.createdAt,
    expiresAt: verification.expiresAt,
  };
}

function findCredential(runtime: RuntimeContext, credentialId: string) {
  return runtime.adapter.findOne<StoredAttestationCredential>({
    model: CREDENTIAL_MODEL,
    where: [{ field: "id", value: credentialId }],
  });
}

function verifiedOAuthGrant(
  credential: StoredAttestationCredential,
  userId: string,
): VerifiedAttestationGrant {
  return {
    credentialId: credential.id,
    provider: credential.provider,
    applicationId: credential.applicationId,
    userId,
  };
}

function verifiedCredentialIssuanceGrant(
  credential: StoredAttestationCredential,
): VerifiedCredentialIssuanceGrant {
  return {
    credentialId: credential.id,
    provider: credential.provider,
    applicationId: credential.applicationId,
  };
}

export function isProtectedClient(
  info: OAuthProviderTokenContext,
  protectedClientIds: string[],
): boolean {
  const clientId = readQueryString(info.verificationValue?.query, "client_id");
  return clientId !== undefined && protectedClientIds.includes(clientId);
}

export function grantIdentifier(secret: string, token: string): string {
  return `device-attestation:grant:${hmacSha256(secret, token)}`;
}

function parseGrantState(value: string) {
  try {
    return grantStateSchema.parse(JSON.parse(value) as unknown);
  } catch {
    throw rejection("storage", "invalid_grant_state");
  }
}

function oauthBindingFromQuery(
  query: object | undefined,
): OAuthAuthorizationBinding {
  const resource = readQueryValue(query, "resource");
  const resources = Array.isArray(resource)
    ? resource.filter((value): value is string => typeof value === "string")
    : typeof resource === "string"
      ? [resource]
      : undefined;
  return normalizeOAuthBinding({
    clientId: requireQueryString(query, "client_id"),
    redirectUri: requireQueryString(query, "redirect_uri"),
    codeChallenge: requireQueryString(query, "code_challenge"),
    codeChallengeMethod: requireQueryString(
      query,
      "code_challenge_method",
    ) as "S256",
    dpopJkt: requireQueryString(query, "dpop_jkt"),
    scope: requireQueryString(query, "scope"),
    ...(resources === undefined ? {} : { resources }),
    ...(typeof readQueryValue(query, "nonce") === "string"
      ? { nonce: readQueryValue(query, "nonce") as string }
      : {}),
  });
}

function readQueryString(
  query: object | undefined,
  key: string,
): string | undefined {
  const value = readQueryValue(query, key);
  return typeof value === "string" ? value : undefined;
}

function readQueryValue(query: object | undefined, key: string): unknown {
  return query === undefined ? undefined : Reflect.get(query, key);
}

function requireQueryString(query: object | undefined, key: string): string {
  const value = readQueryString(query, key);
  if (!value) {
    throw rejection("grant-binding", `missing_${key}`);
  }
  return value;
}
