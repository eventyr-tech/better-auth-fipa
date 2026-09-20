import type { BetterAuthPlugin } from "better-auth";
import type { OAuthOptions } from "@better-auth/oauth-provider";

import type { DeviceAttestationDiagnosticEvent } from "./errors.js";

/** App Attest environment encoded by the credential AAGUID. */
export type DeviceAttestationEnvironment = "development" | "production";

/**
 * OAuth transaction values committed into an assertion challenge and its
 * resulting one-time grant.
 *
 * Values must be the exact normalized values later stored by the Better Auth
 * OAuth Provider. In particular, `dpopJkt` is the RFC 7638 thumbprint of the
 * non-exportable key that will be used at the token endpoint.
 */
export interface OAuthAuthorizationBinding {
  /** OAuth client identifier. */
  clientId: string;
  /** Exact registered redirect URI. */
  redirectUri: string;
  /** Base64url SHA-256 PKCE challenge. */
  codeChallenge: string;
  /** Only PKCE S256 is accepted. */
  codeChallengeMethod: "S256";
  /** RFC 7638 JWK thumbprint supplied as `dpop_jkt`. */
  dpopJkt: string;
  /** Space-delimited OAuth scope value. */
  scope: string;
  /** Optional RFC 8707 resource indicators. */
  resources?: string[] | undefined;
  /** Optional OpenID Connect nonce. */
  nonce?: string | undefined;
}

/**
 * Host credential issuance values committed into an assertion challenge.
 *
 * `subject` is a host-defined, non-secret identifier for the issuance ceremony
 * (for example, a hash of a pairing transaction). It must not contain the raw
 * credential or pairing secret.
 */
export interface CredentialIssuanceBinding {
  /** Host-defined namespace configured as trusted server policy. */
  namespace: string;
  /** Stable non-secret identifier for the exact issuance ceremony. */
  subject: string;
  /** RFC 7638 thumbprint of the key bound to the issued credential. */
  dpopJkt: string;
}

/**
 * Credential record supplied to an attestation provider during assertion
 * verification.
 *
 * Provider implementations must treat every property as untrusted database
 * input and must not log the public key, lookup key, or user binding.
 */
export interface StoredAttestationCredential {
  /** Better Auth model identifier. */
  id: string;
  /** Irreversible lookup value derived from provider, application, and key ID. */
  lookupKey: string;
  /** Provider ID that created the credential. */
  provider: string;
  /** Provider-specific application identity, such as an Apple App ID. */
  applicationId: string;
  /** Environment verified during registration. */
  environment: DeviceAttestationEnvironment;
  /** Base64-encoded SPKI public key while the credential remains usable. */
  publicKey?: string | null;
  /** Last accepted monotonic counter, represented across the full UInt32 range. */
  counter: number;
  /** Permanently bound Better Auth user, or null before first authorization. */
  userId?: string | null;
  /** Whether a host credential has been issued from this attested key. */
  externallyBound: boolean;
  /** Guard value used for atomic first-user binding and retirement. */
  bindingVersion: number;
  /** Current credential lifecycle state. */
  status: "active" | "expired" | "revoked";
  /** Last verified provider distribution category. */
  validationCategory?: number | null;
  /** Last verified provider bundle version. */
  bundleVersion?: string | null;
  /** Whether the last accepted evidence included distribution extensions. */
  extensionsPresent: boolean;
  /** Expiration for an active credential that has not yet bound to a user. */
  unboundExpiresAt?: Date | null;
  /** Permanent retirement time. */
  revokedAt?: Date | null;
  /** Closed, non-sensitive reason for permanent retirement. */
  revocationReason?:
    "user" | "user_deleted" | "counter_exhausted" | "provider" | null;
}

/** Verified material returned by a provider for a new credential. */
export interface RegistrationVerificationResult {
  /** Verified application identity. Must match the registration challenge. */
  applicationId: string;
  /** Environment established from provider-signed evidence. */
  environment: DeviceAttestationEnvironment;
  /** Canonical base64 SPKI public key used for later assertion verification. */
  publicKey: string;
  /** App Attest registration always begins at zero. */
  counter: 0;
  /** Verified provider distribution category, when extensions were present. */
  validationCategory?: number;
  /** Verified provider bundle version, when extensions were present. */
  bundleVersion?: string;
  /** Whether verified distribution extensions were present. */
  extensionsPresent: boolean;
  /**
   * Opaque receipt bytes. These remain untrusted until independently processed
   * through the provider's fraud-risk service and must never be logged.
   */
  untrustedReceipt?: Uint8Array;
}

/** Verified material returned after a provider assertion. */
export interface AssertionVerificationResult {
  /** Strictly advanced monotonic counter. */
  counter: number;
  /** Verified provider distribution category, when extensions were present. */
  validationCategory?: number;
  /** Verified provider bundle version, when extensions were present. */
  bundleVersion?: string;
  /** Whether verified distribution extensions were present. */
  extensionsPresent: boolean;
}

/**
 * Provider boundary used by the Better Auth plugin.
 *
 * A provider owns structural and cryptographic evidence verification. The
 * shared plugin owns challenges, persistence, replay protection, user binding,
 * grants, and OAuth composition.
 */
export interface DeviceAttestationProvider {
  /** Stable provider identifier stored with credentials and ephemeral state. */
  readonly id: string;
  /** Maximum decoded evidence size accepted before provider verification. */
  readonly maxEvidenceBytes: number;
  /**
   * Strictly decode and validate a transport key identifier.
   *
   * @throws {DeviceAttestationError} When the value is not canonical or does
   * not satisfy the provider's key-ID format.
   */
  decodeKeyId(value: string): Uint8Array;
  /** Verify registration evidence against a one-time client-data hash. */
  verifyRegistration(input: {
    /** Application selected by the challenge. */
    applicationId: string;
    /** Provider key identifier returned by `decodeKeyId`. */
    keyId: Uint8Array;
    /** SHA-256 hash committed to the platform attestation operation. */
    clientDataHash: Uint8Array;
    /** Decoded provider evidence. */
    evidence: Uint8Array;
  }): Promise<RegistrationVerificationResult>;
  /** Verify an assertion for an already registered credential. */
  verifyAssertion(input: {
    /** Current credential snapshot. */
    credential: StoredAttestationCredential;
    /** Provider key identifier returned by `decodeKeyId`. */
    keyId: Uint8Array;
    /** SHA-256 hash committed to the platform assertion operation. */
    clientDataHash: Uint8Array;
    /** Decoded provider evidence. */
    evidence: Uint8Array;
  }): Promise<AssertionVerificationResult>;
}

/** Options for the Better Auth device-attestation composition. */
export interface DeviceAttestationOptions {
  /** One or more providers with unique IDs. */
  providers: DeviceAttestationProvider[];
  /** Lifecycle policy for registration and protected OAuth authorization. */
  purposes: {
    /** New provider-key registration policy. */
    credentialRegistration: {
      /** Registration challenge lifetime in seconds. Defaults to 120. */
      challengeTtlSeconds?: number;
      /** Unbound credential lifetime in seconds. Defaults to 24 hours. */
      unboundCredentialTtlSeconds?: number;
      /** Retention for expired, never-bound rows. Defaults to 7 days. */
      expiredCredentialRetentionSeconds?: number;
      /** Optional cap on active unbound credentials per provider application. */
      maxActiveUnboundCredentialsPerApplication?: number;
    };
    /** OAuth authorization assertion and grant policy. */
    oauthAuthorization: {
      /** OAuth client IDs for which token issuance requires a matching grant. */
      protectedClientIds: string[];
      /** Assertion challenge lifetime in seconds. Defaults to 120. */
      challengeTtlSeconds?: number;
      /** One-time attestation grant lifetime in seconds. Defaults to 300. */
      grantTtlSeconds?: number;
      /** Must be true; protected OAuth authorizations require `dpop_jkt`. */
      requireDpopJkt: true;
    };
    /** Optional host credential-issuance assertion and grant policy. */
    credentialIssuance?: {
      /** Host-defined namespaces allowed to request issuance grants. */
      allowedNamespaces: string[];
      /** Assertion challenge lifetime in seconds. Defaults to 120. */
      challengeTtlSeconds?: number;
      /** One-time attestation grant lifetime in seconds. Defaults to 300. */
      grantTtlSeconds?: number;
      /** Must be true; issued credentials require a DPoP key binding. */
      requireDpopJkt: true;
    };
  };
  /** Optional safe server-side rejection reporting. */
  diagnostics?: {
    /**
     * Receive redacted structured events as a best-effort side effect. The
     * authentication response does not wait for asynchronous delivery, and
     * reporter failures cannot replace the authentication result.
     */
    report?: (event: DeviceAttestationDiagnosticEvent) => void | Promise<void>;
  };
}

/** Result of consuming and binding an attestation grant. */
export interface VerifiedAttestationGrant {
  /** Bound plugin credential ID. */
  credentialId: string;
  /** Provider that verified the evidence. */
  provider: string;
  /** Verified application identity. */
  applicationId: string;
  /** Better Auth user permanently bound to the credential. */
  userId: string;
}

/** Result of consuming a host credential-issuance attestation grant. */
export interface VerifiedCredentialIssuanceGrant {
  /** Plugin credential ID that authorized the issuance. */
  credentialId: string;
  /** Provider that verified the evidence. */
  provider: string;
  /** Verified application identity. */
  applicationId: string;
}

/** Server plugin and OAuth Provider options composer returned by the factory. */
export interface DeviceAttestationComposition {
  /** Install this plugin in exactly one `betterAuth()` instance. */
  serverPlugin: BetterAuthPlugin;
  /**
   * Wrap OAuth Provider options so protected authorization-code token issuance
   * consumes and binds the one-time attestation grant.
   */
  protectOAuthProvider<T extends OAuthProviderCompositionOptions>(
    options: T,
  ): T;
  /**
   * Consume a one-time OAuth attestation grant and bind its credential to the
   * authenticated Better Auth user.
   */
  consumeOAuthAuthorizationGrant(input: {
    grantToken: string;
    binding: OAuthAuthorizationBinding;
    userId: string;
  }): Promise<VerifiedAttestationGrant>;
  /**
   * Consume a one-time attestation grant for a host credential issuance and
   * permanently mark the attestation credential as externally bound.
   */
  consumeCredentialIssuanceGrant(input: {
    grantToken: string;
    binding: CredentialIssuanceBinding;
  }): Promise<VerifiedCredentialIssuanceGrant>;
}

/** OAuth Provider options accepted by `protectOAuthProvider`. */
export type OAuthProviderCompositionOptions = OAuthOptions;

/** Token callback context exposed by the supported OAuth Provider version. */
export type OAuthProviderTokenContext = Parameters<
  NonNullable<OAuthOptions["customTokenResponseFields"]>
>[0];
