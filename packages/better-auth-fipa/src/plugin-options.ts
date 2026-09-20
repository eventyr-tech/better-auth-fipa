import type {
  DeviceAttestationOptions,
  DeviceAttestationProvider,
} from "./types.js";

export interface ResolvedDeviceAttestationOptions {
  providers: Map<string, DeviceAttestationProvider>;
  challengeTtlSeconds: number;
  registrationChallengeTtlSeconds: number;
  grantTtlSeconds: number;
  credentialIssuanceChallengeTtlSeconds: number | undefined;
  credentialIssuanceGrantTtlSeconds: number | undefined;
  credentialIssuanceNamespaces: ReadonlySet<string>;
  unboundCredentialTtlSeconds: number;
  expiredCredentialRetentionSeconds: number;
  maxActiveUnboundCredentialsPerApplication: number | undefined;
}

export function resolveDeviceAttestationOptions(
  options: DeviceAttestationOptions,
): ResolvedDeviceAttestationOptions {
  const providers = new Map<string, DeviceAttestationProvider>();
  for (const provider of options.providers) {
    if (providers.has(provider.id)) {
      throw new TypeError(
        `Duplicate device attestation provider: ${provider.id}`,
      );
    }
    providers.set(provider.id, provider);
  }
  if (providers.size === 0) {
    throw new TypeError(
      "At least one device attestation provider is required.",
    );
  }

  const oauthPurpose = options.purposes.oauthAuthorization;
  const registrationPurpose = options.purposes.credentialRegistration;
  const credentialIssuancePurpose = options.purposes.credentialIssuance;
  if (
    oauthPurpose.requireDpopJkt !== true ||
    oauthPurpose.protectedClientIds.length === 0 ||
    oauthPurpose.protectedClientIds.some((clientId) => clientId.length === 0)
  ) {
    throw new TypeError(
      "OAuth authorization requires DPoP and at least one non-empty protected client ID.",
    );
  }
  if (
    credentialIssuancePurpose &&
    (credentialIssuancePurpose.requireDpopJkt !== true ||
      credentialIssuancePurpose.allowedNamespaces.length === 0 ||
      credentialIssuancePurpose.allowedNamespaces.some(
        (namespace) => namespace.length === 0,
      ))
  ) {
    throw new TypeError(
      "Credential issuance requires DPoP and at least one non-empty namespace.",
    );
  }
  if (
    credentialIssuancePurpose &&
    new Set(credentialIssuancePurpose.allowedNamespaces).size !==
      credentialIssuancePurpose.allowedNamespaces.length
  ) {
    throw new TypeError("allowedNamespaces must not contain duplicates.");
  }
  if (
    new Set(oauthPurpose.protectedClientIds).size !==
    oauthPurpose.protectedClientIds.length
  ) {
    throw new TypeError("protectedClientIds must not contain duplicates.");
  }

  return {
    providers,
    challengeTtlSeconds: positiveSeconds(
      oauthPurpose.challengeTtlSeconds,
      120,
      "purposes.oauthAuthorization.challengeTtlSeconds",
    ),
    registrationChallengeTtlSeconds: positiveSeconds(
      registrationPurpose.challengeTtlSeconds,
      120,
      "purposes.credentialRegistration.challengeTtlSeconds",
    ),
    grantTtlSeconds: positiveSeconds(
      oauthPurpose.grantTtlSeconds,
      300,
      "purposes.oauthAuthorization.grantTtlSeconds",
    ),
    credentialIssuanceChallengeTtlSeconds: credentialIssuancePurpose
      ? positiveSeconds(
          credentialIssuancePurpose.challengeTtlSeconds,
          120,
          "purposes.credentialIssuance.challengeTtlSeconds",
        )
      : undefined,
    credentialIssuanceGrantTtlSeconds: credentialIssuancePurpose
      ? positiveSeconds(
          credentialIssuancePurpose.grantTtlSeconds,
          300,
          "purposes.credentialIssuance.grantTtlSeconds",
        )
      : undefined,
    credentialIssuanceNamespaces: new Set(
      credentialIssuancePurpose?.allowedNamespaces ?? [],
    ),
    unboundCredentialTtlSeconds: positiveSeconds(
      registrationPurpose.unboundCredentialTtlSeconds,
      24 * 60 * 60,
      "purposes.credentialRegistration.unboundCredentialTtlSeconds",
    ),
    expiredCredentialRetentionSeconds: positiveSeconds(
      registrationPurpose.expiredCredentialRetentionSeconds,
      7 * 24 * 60 * 60,
      "purposes.credentialRegistration.expiredCredentialRetentionSeconds",
    ),
    maxActiveUnboundCredentialsPerApplication: optionalPositiveInteger(
      registrationPurpose.maxActiveUnboundCredentialsPerApplication,
      "purposes.credentialRegistration.maxActiveUnboundCredentialsPerApplication",
    ),
  };
}

function positiveSeconds(
  value: number | undefined,
  fallback: number,
  label: string,
): number {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved <= 0) {
    throw new TypeError(`${label} must be a positive safe integer.`);
  }
  return resolved;
}

function optionalPositiveInteger(
  value: number | undefined,
  label: string,
): number | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new TypeError(`${label} must be a positive safe integer.`);
  }
  return value;
}
