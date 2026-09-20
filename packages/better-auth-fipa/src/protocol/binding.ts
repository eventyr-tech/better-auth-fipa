import { rejection } from "../errors.js";
import type {
  CredentialIssuanceBinding,
  OAuthAuthorizationBinding,
} from "../types.js";
import { sha256 } from "./crypto.js";

const CLIENT_DATA_DOMAIN = "better-auth-device-attestation/client-data/v1";
const BINDING_DOMAIN = "better-auth-device-attestation/oauth-binding/v1";
const CREDENTIAL_ISSUANCE_BINDING_DOMAIN =
  "better-auth-device-attestation/credential-issuance-binding/v1";

export function normalizeOAuthBinding(
  input: OAuthAuthorizationBinding,
): OAuthAuthorizationBinding {
  if (input.codeChallengeMethod !== "S256") {
    throw rejection("request", "unsupported_code_challenge_method");
  }

  const scope = [...new Set(input.scope.split(/\s+/u).filter(Boolean))]
    .sort()
    .join(" ");
  const resources = [...new Set(input.resources ?? [])].sort();

  if (
    input.clientId.length === 0 ||
    input.redirectUri.length === 0 ||
    input.codeChallenge.length === 0 ||
    input.dpopJkt.length === 0 ||
    scope.length === 0
  ) {
    throw rejection("request", "incomplete_oauth_binding");
  }

  return {
    clientId: input.clientId,
    redirectUri: input.redirectUri,
    codeChallenge: input.codeChallenge,
    codeChallengeMethod: "S256",
    dpopJkt: input.dpopJkt,
    scope,
    ...(resources.length === 0 ? {} : { resources }),
    ...(input.nonce === undefined ? {} : { nonce: input.nonce }),
  };
}

export function hashOAuthBinding(input: OAuthAuthorizationBinding): Buffer {
  const normalized = normalizeOAuthBinding(input);
  return sha256(
    encodeLengthPrefixed([
      BINDING_DOMAIN,
      normalized.clientId,
      normalized.redirectUri,
      normalized.codeChallenge,
      normalized.codeChallengeMethod,
      normalized.dpopJkt,
      normalized.scope,
      ...(normalized.resources ?? []),
      normalized.nonce ?? "",
    ]),
  );
}

export function normalizeCredentialIssuanceBinding(
  input: CredentialIssuanceBinding,
): CredentialIssuanceBinding {
  if (
    input.namespace.length === 0 ||
    input.subject.length === 0 ||
    input.dpopJkt.length === 0
  ) {
    throw rejection("request", "incomplete_credential_issuance_binding");
  }
  return {
    namespace: input.namespace,
    subject: input.subject,
    dpopJkt: input.dpopJkt,
  };
}

export function hashCredentialIssuanceBinding(
  input: CredentialIssuanceBinding,
): Buffer {
  const normalized = normalizeCredentialIssuanceBinding(input);
  return sha256(
    encodeLengthPrefixed([
      CREDENTIAL_ISSUANCE_BINDING_DOMAIN,
      normalized.namespace,
      normalized.subject,
      normalized.dpopJkt,
    ]),
  );
}

export function createClientData(input: {
  nonce: Uint8Array;
  provider: string;
  operation: "register" | "assert";
  purpose:
    "credential-registration" | "credential-issuance" | "oauth-authorization";
  applicationId: string;
  keyLookupHash: string;
  bindingHash?: Uint8Array;
}): Buffer {
  return encodeLengthPrefixed([
    CLIENT_DATA_DOMAIN,
    Buffer.from(input.nonce).toString("base64url"),
    input.provider,
    input.operation,
    input.purpose,
    input.applicationId,
    input.keyLookupHash,
    input.bindingHash === undefined
      ? ""
      : Buffer.from(input.bindingHash).toString("base64url"),
  ]);
}

function encodeLengthPrefixed(values: string[]): Buffer {
  const encoded = values.map((value) => Buffer.from(value, "utf8"));
  const chunks: Buffer[] = [];

  for (const value of encoded) {
    const length = Buffer.alloc(4);
    length.writeUInt32BE(value.length);
    chunks.push(length, value);
  }

  return Buffer.concat(chunks);
}
