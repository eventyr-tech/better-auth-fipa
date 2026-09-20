import {
  DeviceAttestationClientError,
  isRecord,
  serverError,
} from "./errors.ts";
import type {
  AppAttestClientOptions,
  AppAttestNative,
  AttestationEvidence,
  AttestationPurpose,
  CredentialIssuanceBinding,
  OAuthAuthorizationBinding,
} from "./types.ts";

// Shared across client instances so the same native key cannot race itself.
const operations = new Map<string, Promise<unknown>>();

async function serialized<T>(
  key: string,
  operation: () => Promise<T>,
): Promise<T> {
  const prior = operations.get(key) ?? Promise.resolve();
  const next = prior.catch(() => undefined).then(operation);
  operations.set(key, next);
  try {
    return await next;
  } finally {
    if (operations.get(key) === next) operations.delete(key);
  }
}

/** Platform-independent orchestration, also used by the native default client. */
export function createAppAttestClient(
  options: AppAttestClientOptions,
  native: AppAttestNative,
) {
  const baseURL = new URL(options.authBaseURL);
  if (
    !["https:", "http:"].includes(baseURL.protocol) ||
    baseURL.username ||
    baseURL.password ||
    baseURL.search ||
    baseURL.hash
  ) {
    throw new TypeError(
      "authBaseURL must be an HTTP(S) URL without credentials, query, or fragment.",
    );
  }
  if (!options.applicationId || !options.keyIdStoragePrefix) {
    throw new TypeError("applicationId and keyIdStoragePrefix are required.");
  }
  const prefix = options.keyIdStoragePrefix;
  const url = options.authBaseURL.replace(/\/+$/u, "");
  const fetch = options.fetch ?? globalThis.fetch;

  async function post(
    path: string,
    body: unknown,
  ): Promise<Record<string, unknown>> {
    let response: Response;
    try {
      response = await fetch(`${url}/device-attestation/${path}`, {
        method: "POST",
        credentials: "omit",
        redirect: "error",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        body: JSON.stringify(body),
      });
    } catch {
      throw new DeviceAttestationClientError(
        "DEVICE_ATTESTATION_NETWORK_ERROR",
      );
    }
    let payload: unknown;
    try {
      payload = await response.json();
    } catch {
      payload = null;
    }
    if (!response.ok) throw serverError(response, payload);
    if (!isRecord(payload))
      throw new DeviceAttestationClientError(
        "DEVICE_ATTESTATION_INVALID_RESPONSE",
      );
    return payload;
  }

  async function nativeCall<T>(operation: () => Promise<T>): Promise<T> {
    try {
      return await operation();
    } catch (error) {
      if (error instanceof DeviceAttestationClientError) throw error;
      throw new DeviceAttestationClientError("DEVICE_ATTESTATION_NATIVE_ERROR");
    }
  }

  async function challenge(
    keyId: string,
    purpose: AttestationPurpose | { purpose: "credential-registration" },
  ) {
    const operation =
      purpose.purpose === "credential-registration" ? "register" : "assert";
    const response = await post("challenge", {
      provider: "app-attest",
      applicationId: options.applicationId,
      keyId,
      operation,
      ...purpose,
    });
    if (
      typeof response.challengeToken !== "string" ||
      !response.challengeToken ||
      typeof response.clientData !== "string" ||
      !response.clientData
    ) {
      throw new DeviceAttestationClientError(
        "DEVICE_ATTESTATION_INVALID_RESPONSE",
      );
    }
    const evidence = await nativeCall(() =>
      native.generateEvidence(keyId, response.clientData as string, operation),
    );
    return { challengeToken: response.challengeToken, keyId, evidence };
  }

  async function register(keyId: string) {
    const response = await post(
      "verify",
      await challenge(keyId, { purpose: "credential-registration" }),
    );
    if (
      response.credentialState !== "registered-unbound" ||
      typeof response.credentialId !== "string"
    ) {
      throw new DeviceAttestationClientError(
        "DEVICE_ATTESTATION_INVALID_RESPONSE",
      );
    }
  }

  async function prepare(
    credentialScope: string,
    purpose: AttestationPurpose,
  ): Promise<AttestationEvidence> {
    let key = await nativeCall(() =>
      native.getOrCreateKey(prefix, credentialScope),
    );
    if (key.created) {
      await register(key.keyId);
      return challenge(key.keyId, purpose);
    }
    try {
      return await challenge(key.keyId, purpose);
    } catch (error) {
      if (
        !(error instanceof DeviceAttestationClientError) ||
        error.code !== "DEVICE_ATTESTATION_CREDENTIAL_REQUIRED"
      )
        throw error;
    }
    // Only an explicit missing/retired server credential triggers replacement.
    // Lost registration responses first probe the existing key, never re-attest it.
    await nativeCall(() => native.resetKey(prefix, credentialScope));
    key = await nativeCall(() =>
      native.getOrCreateKey(prefix, credentialScope),
    );
    await register(key.keyId);
    return challenge(key.keyId, purpose);
  }

  function run<T>(scope: string, task: () => Promise<T>): Promise<T> {
    if (!scope)
      return Promise.reject(
        new TypeError("credentialScope must not be empty."),
      );
    return serialized(JSON.stringify([prefix, scope]), task);
  }

  async function grant(scope: string, purpose: AttestationPurpose) {
    return run(scope, async () => {
      const response = await post("verify", await prepare(scope, purpose));
      if (
        response.credentialState !== "asserted" ||
        typeof response.grantToken !== "string" ||
        !response.grantToken
      ) {
        throw new DeviceAttestationClientError(
          "DEVICE_ATTESTATION_INVALID_RESPONSE",
        );
      }
      return response.grantToken;
    });
  }

  return {
    prepareOAuthGrant: (scope: string, binding: OAuthAuthorizationBinding) =>
      grant(scope, { purpose: "oauth-authorization", binding }),
    prepareCredentialIssuanceGrant: (
      scope: string,
      binding: CredentialIssuanceBinding,
    ) => grant(scope, { purpose: "credential-issuance", binding }),
    /** Advanced transport: caller must serialize through server verification. */
    prepareOAuthEvidence: (scope: string, binding: OAuthAuthorizationBinding) =>
      run(scope, () =>
        prepare(scope, { purpose: "oauth-authorization", binding }),
      ),
    /** Keeps the per-key lock until a host authorization endpoint verifies evidence. */
    withOAuthEvidence: <T>(
      scope: string,
      binding: OAuthAuthorizationBinding,
      consume: (evidence: AttestationEvidence) => Promise<T>,
    ) =>
      run(scope, async () =>
        consume(
          await prepare(scope, { purpose: "oauth-authorization", binding }),
        ),
      ),
    /** For explicit local recovery. This does not retire the server credential. */
    resetKey: (scope: string) =>
      run(scope, () => nativeCall(() => native.resetKey(prefix, scope))),
  };
}
