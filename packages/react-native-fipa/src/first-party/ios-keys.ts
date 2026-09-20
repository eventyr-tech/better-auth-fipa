import { z } from "zod";
import type { Spec as AppAttest } from "../NativeDeviceAttestation.ts";
import type { Spec as Transport } from "../NativeFirstPartyTransport.ts";
import type { FirstPartyClientPorts, NativeIdentity } from "./client.ts";
import { FirstPartyClientError } from "./errors.ts";

const digest = z.string().regex(/^[A-Za-z0-9_-]{43}$/);
const identifier = z.string().min(1).max(256);
const keyId = z.string().min(1).max(2048);
const challengeSchema = z.object({
  challengeToken: z.string().min(1).max(128),
  clientData: z
    .string()
    .min(1)
    .max(32768)
    .regex(/^[A-Za-z0-9_-]+$/),
});
const evidenceSchema = z
  .string()
  .min(1)
  .max(1_398_104)
  .regex(/^[A-Za-z0-9+/]+={0,2}$/);
type AdmissionContext = Parameters<
  FirstPartyClientPorts["keys"]["admission"]
>[2];

/** Internal iOS provider adapter. Aliases are assigned by the installation/slot
 * catalog, never derived from user input or changed after identity preparation. */
export function createIOSKeyPorts(
  options: {
    issuer: string;
    clientId: string;
    applicationId: string;
    environment: "development" | "production";
    keyIdStoragePrefix: string;
    allowInsecureLoopback?: boolean;
    aliases(
      slot: string,
    ): Promise<{ dpopAlias: string; providerScope: string }>;
  },
  native: {
    appAttest: Pick<
      AppAttest,
      "getKey" | "getOrCreateKey" | "generateEvidence" | "removeKey"
    >;
    dpop: Pick<
      Transport,
      "prepareDpop" | "inspectDpop" | "signDpop" | "removeDpop"
    >;
    send: FirstPartyClientPorts["send"];
  },
): FirstPartyClientPorts["keys"] {
  options = { ...options };
  let issuer: string;
  try {
    const url = new URL(options.issuer);
    if (
      url.username ||
      url.password ||
      url.search ||
      url.hash ||
      (url.protocol !== "https:" &&
        !(
          options.allowInsecureLoopback === true &&
          url.protocol === "http:" &&
          ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)
        ))
    )
      throw new Error();
    issuer = url.href.replace(/\/+$/u, "");
    identifier.parse(options.clientId);
    identifier.parse(options.applicationId);
    identifier.parse(options.keyIdStoragePrefix);
    z.enum(["development", "production"]).parse(options.environment);
  } catch {
    throw new FirstPartyClientError("invalid_configuration");
  }
  const check = (context: AdmissionContext) => {
    if (context.signal.aborted) throw new FirstPartyClientError("cancelled");
  };
  async function call<T>(operation: () => Promise<T>): Promise<T> {
    try {
      return await operation();
    } catch {
      throw new FirstPartyClientError("operation_failed");
    }
  }
  async function available(identity: NativeIdentity) {
    const existing = await call(() =>
      native.appAttest.getKey(
        identity.providerStoragePrefix ?? options.keyIdStoragePrefix,
        identity.providerScope,
      ),
    );
    if (existing !== identity.providerKeyId)
      throw new FirstPartyClientError("registration_recovery_required");
    const jkt = await call(() => native.dpop.inspectDpop(identity.dpopAlias));
    if (jkt !== identity.dpopJkt)
      throw new FirstPartyClientError("registration_recovery_required");
  }
  async function post(path: string, body: unknown, context: AdmissionContext) {
    check(context);
    const url = `${issuer}${path}`;
    const response = await native.send({
      url,
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
      signal: context.signal,
      maximumResponseBytes: 65536,
    });
    check(context);
    if (
      response.url !== url ||
      !Number.isInteger(response.status) ||
      response.status < 200 ||
      response.status >= 600 ||
      (response.status >= 300 && response.status < 400) ||
      new TextEncoder().encode(response.body).byteLength > 65536
    )
      throw new FirstPartyClientError("invalid_response");
    let payload: unknown;
    try {
      payload = JSON.parse(response.body);
    } catch {
      throw new FirstPartyClientError("invalid_response");
    }
    return { status: response.status, body: payload };
  }
  function success(response: { status: number; body: unknown }) {
    if (response.status !== 200)
      throw new FirstPartyClientError("request_failed");
    return response.body;
  }
  function challenge(response: { status: number; body: unknown }) {
    const parsed = challengeSchema.safeParse(success(response));
    if (!parsed.success) throw new FirstPartyClientError("invalid_response");
    return parsed.data;
  }
  async function evidence(
    identity: NativeIdentity,
    clientData: string,
    operation: "register" | "assert",
    context: AdmissionContext,
  ) {
    check(context);
    const value = await call(() =>
      native.appAttest.generateEvidence(
        identity.providerKeyId,
        clientData,
        operation,
      ),
    );
    check(context);
    const parsed = evidenceSchema.safeParse(value);
    if (!parsed.success) throw new FirstPartyClientError("invalid_response");
    return parsed.data;
  }
  return {
    prepare: async (slot) => {
      const aliases = z
        .strictObject({ dpopAlias: identifier, providerScope: identifier })
        .safeParse(await options.aliases(slot));
      if (!aliases.success)
        throw new FirstPartyClientError("invalid_configuration");
      const dpopJkt = digest.safeParse(
        await call(() => native.dpop.prepareDpop(aliases.data.dpopAlias)),
      );
      if (!dpopJkt.success) throw new FirstPartyClientError("invalid_response");
      const key = z
        .strictObject({ keyId, created: z.boolean() })
        .safeParse(
          await call(() =>
            native.appAttest.getOrCreateKey(
              options.keyIdStoragePrefix,
              aliases.data.providerScope,
            ),
          ),
        );
      if (!key.success) throw new FirstPartyClientError("invalid_response");
      return {
        version: 1,
        ...aliases.data,
        dpopJkt: dpopJkt.data,
        providerKeyId: key.data.keyId,
        providerRegistration: key.data.created ? "generated" : "unknown",
      };
    },
    assertAvailable: available,
    remove: async (identity) => {
      if (!identity.retired) throw new FirstPartyClientError("invalid_state");
      await call(() =>
        native.appAttest.removeKey(
          identity.providerStoragePrefix ?? options.keyIdStoragePrefix,
          identity.providerScope,
          identity.providerKeyId,
        ),
      );
      await call(() =>
        native.dpop.removeDpop(identity.dpopAlias, identity.dpopJkt),
      );
    },
    proof: async (identity, request) => {
      // inspect/sign never create a key, including when an imported alias is absent.
      const proof = await call(() =>
        native.dpop.signDpop(
          identity.dpopAlias,
          identity.dpopJkt,
          request.url,
          request.method,
          request.accessToken ?? null,
          request.nonce ?? null,
        ),
      );
      if (
        typeof proof !== "string" ||
        proof.length > 16384 ||
        !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(proof)
      )
        throw new FirstPartyClientError("invalid_response");
      return proof;
    },
    admission: async (identity, binding, context) => {
      check(context);
      if (
        binding.provider !== "app-attest" ||
        binding.dpopJkt !== identity.dpopJkt ||
        binding.issuer !== issuer ||
        binding.clientId !== options.clientId ||
        binding.applicationId !== options.applicationId ||
        binding.environment !== options.environment
      )
        throw new FirstPartyClientError("invalid_state");
      await available(identity);
      const probe = () =>
        post(
          "/first-party/attestation/challenge",
          { keyId: identity.providerKeyId, binding },
          context,
        );
      let response = await probe();
      const missing = z
        .object({ code: z.literal("DEVICE_ATTESTATION_CREDENTIAL_REQUIRED") })
        .safeParse(response.body);
      if (response.status === 400 && missing.success) {
        if (identity.providerRegistration !== "generated")
          throw new FirstPartyClientError("registration_recovery_required");
        const registration = challenge(
          await post(
            "/device-attestation/challenge",
            {
              provider: "app-attest",
              applicationId: options.applicationId,
              keyId: identity.providerKeyId,
              operation: "register",
              purpose: "credential-registration",
            },
            context,
          ),
        );
        // Once this durable marker exists, no retry may call Apple's attestKey on
        // this key. A lost server response is recovered by a fresh assertion probe.
        await context.saveIdentity({
          ...identity,
          providerRegistration: "attesting",
        });
        const value = await evidence(
          identity,
          registration.clientData,
          "register",
          context,
        );
        const registered = z
          .object({
            credentialState: z.literal("registered-unbound"),
            credentialId: z.string().min(1),
          })
          .safeParse(
            success(
              await post(
                "/device-attestation/verify",
                {
                  challengeToken: registration.challengeToken,
                  keyId: identity.providerKeyId,
                  evidence: value,
                },
                context,
              ),
            ),
          );
        if (!registered.success)
          throw new FirstPartyClientError("invalid_response");
        await context.saveIdentity({
          ...identity,
          providerRegistration: "registered",
        });
        response = await probe();
      }
      const assertion = challenge(response);
      const value = await evidence(
        identity,
        assertion.clientData,
        "assert",
        context,
      );
      const verified = z
        .object({ grantToken: z.string().min(1).max(16384) })
        .safeParse(
          success(
            await post(
              "/first-party/attestation/verify",
              {
                clientId: options.clientId,
                challengeToken: assertion.challengeToken,
                keyId: identity.providerKeyId,
                evidence: value,
              },
              context,
            ),
          ),
        );
      if (!verified.success)
        throw new FirstPartyClientError("invalid_response");
      if (identity.providerRegistration !== "registered")
        await context.saveIdentity({
          ...identity,
          providerRegistration: "registered",
        });
      check(context);
      return verified.data.grantToken;
    },
  };
}
