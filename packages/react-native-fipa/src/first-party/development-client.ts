import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { utf8ToBytes } from "@noble/hashes/utils.js";
import { base64, base64urlnopad } from "@scure/base";
import type { Spec as Transport } from "../NativeFirstPartyTransport.ts";
import { firstPartyStorageNamespace } from "./client.ts";
import { FirstPartyClientError } from "./errors.ts";
import {
  createNativeLifecycle,
  type NativeFirstPartyConfiguration,
} from "./native-lifecycle.ts";
import { createProviderKeyPorts } from "./provider-keys.ts";
import {
  createSessionCoordinator,
  type SessionVaultNative,
} from "./session-coordinator.ts";

const encode = base64urlnopad.encode;
const decode = base64urlnopad.decode;
const bytes = utf8ToBytes;
const digest = (value: string) => encode(sha256(bytes(value)));
const json = (value: unknown) => encode(bytes(JSON.stringify(value)));

/** Shared software evidence. No App Attest, Play Integrity or hardware assurance.
 * Persistence and transport use the SDK's existing platform-neutral contracts.
 * Secret scalars are deliberately accessible to JS in this development mode. */
export function createDevelopmentFirstPartyClient(
  configuration: NativeFirstPartyConfiguration,
  native: { transport: Transport; vault: SessionVaultNative },
) {
  if (
    configuration.provider !== "development" ||
    configuration.environment !== "development"
  )
    throw new FirstPartyClientError("invalid_configuration");
  const config = {
    ...configuration,
    provider: "development" as const,
    storageNamespace:
      configuration.storageNamespace ?? "device-attestation.first-party.v1",
    accessibility: "when-unlocked" as const,
  };
  const prefix = "fipa.development.v1.";
  const store = createSessionCoordinator(native.vault, {
    namespace: `${firstPartyStorageNamespace(config)}:development-keys/v1`,
  });
  const random = async () => {
    const token = await native.transport.randomToken();
    if (!/^[A-Za-z0-9_-]{43}$/.test(token))
      throw new FirstPartyClientError("key_unavailable");
    const value = decode(token);
    if (value.length !== 32) throw new FirstPartyClientError("key_unavailable");
    return value;
  };
  async function key(
    alias: string,
    create = false,
  ): Promise<{ secret: Uint8Array; created: boolean } | null> {
    return store.run<{ secret: Uint8Array; created: boolean } | null>(
      digest(alias),
      async (transaction) => {
        const stored = transaction.identity?.secret;
        if (
          stored !== undefined &&
          (typeof stored !== "string" ||
            !p256.utils.isValidSecretKey(decode(stored)))
        )
          throw new FirstPartyClientError("vault_corrupt");
        if (typeof stored === "string")
          return {
            identity: transaction.identity,
            session: null,
            result: { secret: decode(stored), created: false },
          };
        if (!create) {
          transaction.readOnly();
          return { identity: null, session: null, result: null };
        }
        const secret = await random();
        if (!p256.utils.isValidSecretKey(secret))
          throw new FirstPartyClientError("key_unavailable");
        return {
          identity: { secret: encode(secret) },
          session: null,
          result: { secret, created: true },
        };
      },
    );
  }
  const required = async (alias: string) => {
    const result = await key(alias);
    if (!result)
      throw new FirstPartyClientError("registration_recovery_required");
    return result.secret;
  };
  const jwk = (secret: Uint8Array) => {
    const publicKey = p256.getPublicKey(secret, false);
    return {
      crv: "P-256",
      kty: "EC",
      x: encode(publicKey.slice(1, 33)),
      y: encode(publicKey.slice(33)),
    };
  };
  const thumbprint = (secret: Uint8Array) =>
    digest(JSON.stringify(jwk(secret)));
  const keyId = (scope: string) =>
    base64.encode(sha256(bytes(`${prefix}\0${scope}`)));
  const remove = (alias: string) =>
    store.run(digest(alias), () =>
      Promise.resolve({ identity: null, session: null, result: undefined }),
    );
  const evidenceKeys = {
    getKey: async (_prefix: string, scope: string) =>
      (await key(`evidence:${keyId(scope)}`)) ? keyId(scope) : null,
    getOrCreateKey: async (_prefix: string, scope: string) => {
      const id = keyId(scope);
      const result = await key(`evidence:${id}`, true);
      return { keyId: id, created: result!.created };
    },
    generateEvidence: async (
      id: string,
      clientData: string,
      operation: string,
    ) => {
      if (!["register", "assert"].includes(operation))
        throw new FirstPartyClientError("invalid_request");
      const secret = await required(`evidence:${id}`);
      const message = `fipa/development/v1\n${operation}\n${id}\n${base64.encode(sha256(decode(clientData)))}`;
      return base64.encode(
        bytes(
          JSON.stringify({
            version: 1,
            provider: "development",
            operation,
            jwk: jwk(secret),
            signature: encode(p256.sign(bytes(message), secret)),
          }),
        ),
      );
    },
    removeKey: async (_prefix: string, scope: string, expected: string) => {
      if (keyId(scope) !== expected)
        throw new FirstPartyClientError("invalid_state");
      await remove(`evidence:${expected}`);
    },
  };
  const dpop = {
    prepareDpop: async (alias: string) =>
      thumbprint((await key(`dpop:${alias}`, true))!.secret),
    inspectDpop: async (alias: string) =>
      thumbprint(await required(`dpop:${alias}`)),
    removeDpop: async (alias: string, expected: string) => {
      const existing = await key(`dpop:${alias}`);
      if (existing && thumbprint(existing.secret) !== expected)
        throw new FirstPartyClientError("invalid_state");
      await remove(`dpop:${alias}`);
    },
    signDpop: async (
      alias: string,
      expected: string,
      url: string,
      method: string,
      accessToken: string | null,
      nonce: string | null,
    ) => {
      const secret = await required(`dpop:${alias}`);
      if (thumbprint(secret) !== expected)
        throw new FirstPartyClientError("registration_recovery_required");
      const target = new URL(url);
      target.search = "";
      target.hash = "";
      const header = json({ typ: "dpop+jwt", alg: "ES256", jwk: jwk(secret) });
      const payload = json({
        jti: encode(await random()),
        htm: method.toUpperCase(),
        htu: target.href,
        iat: Math.floor(Date.now() / 1000),
        ...(accessToken ? { ath: digest(accessToken) } : {}),
        ...(nonce ? { nonce } : {}),
      });
      const input = `${header}.${payload}`;
      return `${input}.${encode(p256.sign(bytes(input), secret))}`;
    },
  };
  return createNativeLifecycle(config, native, ({ aliases, send }) =>
    createProviderKeyPorts(
      { ...config, keyIdStoragePrefix: prefix, aliases },
      { evidence: evidenceKeys, dpop, send },
    ),
  ).client;
}
