/** Values committed to the server's OAuth challenge. No private keys cross JS. */
export interface OAuthAuthorizationBinding {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  codeChallengeMethod: "S256";
  dpopJkt: string;
  scope: string;
  resources?: string[];
  nonce?: string;
}

export interface CredentialIssuanceBinding {
  namespace: string;
  subject: string;
  dpopJkt: string;
}

export interface AppAttestKey {
  created: boolean;
  keyId: string;
}

/** Native bridge contract. Apple's service owns the private key. */
export interface AppAttestNative {
  getOrCreateKey(
    storagePrefix: string,
    credentialScope: string,
  ): Promise<AppAttestKey>;
  generateEvidence(
    keyId: string,
    clientData: string,
    operation: "register" | "assert",
  ): Promise<string>;
  resetKey(storagePrefix: string, credentialScope: string): Promise<void>;
}

export interface AttestationEvidence {
  challengeToken: string;
  keyId: string;
  evidence: string;
}

export interface AppAttestClientOptions {
  /** Complete Better Auth base URL, for example https://example.com/api/auth. */
  authBaseURL: string;
  /** Trusted server configuration must independently accept this Apple App ID. */
  applicationId: string;
  /** Stable UserDefaults prefix. Preserve this value across app upgrades. */
  keyIdStoragePrefix: string;
  /** Host-owned telemetry may wrap fetch. Never log request bodies or responses. */
  fetch?: typeof globalThis.fetch;
}

export type AttestationPurpose =
  | { purpose: "oauth-authorization"; binding: OAuthAuthorizationBinding }
  | { purpose: "credential-issuance"; binding: CredentialIssuanceBinding };

export interface DpopProofInput {
  method: string;
  url: string;
  accessToken?: string;
  nonce?: string;
}

export interface DpopNative {
  generateProof(input: {
    alias: string;
    htm: string;
    htu: string;
    requireHardwareBacked: true;
    accessToken?: string;
    nonce?: string;
  }): Promise<{ proof: string; getPublicKeyThumbprint(): Promise<string> }>;
  assertHardwareBacked(alias: string): Promise<void>;
  deleteKeyPair(alias: string): Promise<void>;
}
