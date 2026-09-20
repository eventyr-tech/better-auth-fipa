import { z } from "zod";
import type { Spec as AndroidIntegrity } from "../NativeAndroidIntegrity.ts";
import type {
  FirstPartyClientPorts,
  NativeBinding,
  NativeIdentity,
} from "./client.ts";
import { FirstPartyClientError } from "./errors.ts";

const digest = z.string().regex(/^[A-Za-z0-9_-]{43}$/);
const identifier = z.string().min(1).max(256);
const enrollment = z.strictObject({
  keyChallengeToken: digest,
  attestationChallenge: digest,
  issuedAt: z.iso.datetime(),
  expiresAt: z.iso.datetime(),
});
const challenge = z.object({
  challengeToken: digest,
  requestHash: digest,
  issuedAt: z.iso.datetime(),
  expiresAt: z.iso.datetime(),
});
const chain = z
  .array(
    z
      .string()
      .min(1)
      .max(21_848)
      .regex(/^[A-Za-z0-9+/]+={0,2}$/),
  )
  .min(4)
  .max(5);
const token = z.string().min(1).max(32_768);
type Context = Parameters<FirstPartyClientPorts["keys"]["admission"]>[2];

/** Internal adapter for the native Android client. There is no software-key or
 * classic Play Integrity fallback. Device certification is a separate gate. */
export function createAndroidKeyPorts(
  options: {
    issuer: string;
    clientId: string;
    applicationId: string;
    environment: "production";
    cloudProjectNumber: string;
    securityLevel: "tee" | "strongbox";
    allowInsecureLoopback?: boolean;
    aliases(
      slot: string,
    ): Promise<{ dpopAlias: string; providerScope: string }>;
  },
  native: { integrity: AndroidIntegrity; send: FirstPartyClientPorts["send"] },
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
    z.literal("production").parse(options.environment);
    z.enum(["tee", "strongbox"]).parse(options.securityLevel);
    // Keep Google's int64 project number out of JS floating-point conversions.
    z.string()
      .regex(/^[1-9][0-9]{0,18}$/)
      .refine((v) => BigInt(v) <= 9223372036854775807n)
      .parse(options.cloudProjectNumber);
  } catch {
    throw new FirstPartyClientError("invalid_configuration");
  }
  const check = (signal: AbortSignal) => {
    if (signal.aborted) throw new FirstPartyClientError("cancelled");
  };
  async function call<T>(operation: () => Promise<T>): Promise<T> {
    try {
      return await operation();
    } catch {
      throw new FirstPartyClientError("operation_failed");
    }
  }
  function parse<T>(schema: z.ZodType<T>, value: unknown): T {
    const parsed = schema.safeParse(value);
    if (!parsed.success) throw new FirstPartyClientError("invalid_response");
    return parsed.data;
  }
  function window(
    value: { issuedAt: string; expiresAt: string },
    registered = false,
  ) {
    const start = Date.parse(value.issuedAt),
      end = Date.parse(value.expiresAt),
      now = Date.now();
    if (
      end <= now ||
      end <= start ||
      end - start > 120_000 ||
      start > now + 30_000
    )
      throw new FirstPartyClientError(
        registered ? "request_failed" : "registration_recovery_required",
      );
  }
  function sameKey(identity: NativeIdentity) {
    if (
      !digest.safeParse(identity.dpopJkt).success ||
      identity.providerKeyId !== identity.dpopJkt
    )
      throw new FirstPartyClientError("invalid_state");
  }
  async function available(identity: NativeIdentity) {
    sameKey(identity);
    const existing = await call(() =>
      native.integrity.inspectKey(identity.dpopAlias),
    );
    if (existing !== identity.dpopJkt)
      throw new FirstPartyClientError("registration_recovery_required");
  }
  const proof: FirstPartyClientPorts["keys"]["proof"] = async (
    identity,
    request,
  ) => {
    sameKey(identity);
    return parse(
      z
        .string()
        .max(16384)
        .regex(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/),
      await call(() =>
        native.integrity.signDpop(
          identity.dpopAlias,
          identity.dpopJkt,
          request.url,
          request.method,
          request.accessToken ?? null,
          request.nonce ?? null,
        ),
      ),
    );
  };
  async function post(
    path: string,
    body: unknown,
    signal: AbortSignal,
    identity?: NativeIdentity,
  ) {
    check(signal);
    const url = `${issuer}${path}`;
    const headers: Record<string, string> = {
      Accept: "application/json",
      "Content-Type": "application/json",
    };
    if (identity) headers.DPoP = await proof(identity, { url, method: "POST" });
    check(signal);
    let response: Awaited<ReturnType<FirstPartyClientPorts["send"]>>;
    try {
      response = await native.send({
        url,
        method: "POST",
        headers,
        body: JSON.stringify(body),
        signal,
        maximumResponseBytes: 65536,
      });
    } catch {
      check(signal);
      throw new FirstPartyClientError("request_failed");
    }
    check(signal);
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
  async function hash(value: unknown) {
    return parse(
      digest,
      await call(() => native.integrity.sha256Utf8(JSON.stringify(value))),
    );
  }
  async function registrationHash(binding: NativeBinding, nonce: string) {
    const bindingHash = await hash([
      "better-auth-device-attestation/first-party-admission-binding/v1",
      binding.profile,
      binding.mode,
      binding.issuer,
      binding.clientId,
      binding.provider,
      binding.applicationId,
      binding.environment,
      binding.attemptId,
      binding.codeChallenge,
      binding.codeChallengeMethod,
      binding.dpopJkt,
      [...new Set(binding.scopes)].sort(),
      [...new Set(binding.resources)].sort(),
      null,
      null,
      null,
    ]);
    return hash([
      "better-auth-device-attestation/android-registration/v1",
      nonce,
      bindingHash,
    ]);
  }
  async function play(requestHash: string, signal: AbortSignal) {
    check(signal);
    const evidence = await call(() =>
      native.integrity.standardIntegrity(
        options.cloudProjectNumber,
        requestHash,
      ),
    );
    check(signal);
    return parse(token, evidence);
  }
  async function accepted(
    response: { status: number; body: unknown },
    identity: NativeIdentity,
    context: Context,
  ) {
    const receipt = parse(
      z.object({ grantToken: z.string().min(1).max(16384) }),
      success(response),
    );
    await context.saveIdentity({
      ...identity,
      providerRegistration: "registered",
    });
    check(context.signal);
    return receipt.grantToken;
  }
  return {
    prepare: async (slot, context) => {
      const signal = context?.signal ?? new AbortController().signal;
      check(signal);
      const aliases = z
        .strictObject({ dpopAlias: identifier, providerScope: identifier })
        .safeParse(await options.aliases(slot));
      if (!aliases.success)
        throw new FirstPartyClientError("invalid_configuration");
      check(signal);
      const existing = await call(() =>
        native.integrity.inspectKey(aliases.data.dpopAlias),
      );
      check(signal);
      if (existing !== null) {
        const jkt = parse(digest, existing);
        // A lost creation result can recover only a server-enrolled key. Never
        // replace it or invent an enrollment handle for a pre-existing key.
        return {
          version: 1,
          ...aliases.data,
          dpopJkt: jkt,
          providerKeyId: jkt,
          providerRegistration: "unknown",
        };
      }
      const pending = parse(
        enrollment,
        success(
          await post(
            "/first-party/android/key-challenge",
            { clientId: options.clientId },
            signal,
          ),
        ),
      );
      window(pending);
      check(signal);
      const jkt = parse(
        digest,
        await call(() =>
          native.integrity.createKey(
            aliases.data.dpopAlias,
            pending.attestationChallenge,
            options.securityLevel,
          ),
        ),
      );
      check(signal);
      return {
        version: 1,
        ...aliases.data,
        dpopJkt: jkt,
        providerKeyId: jkt,
        providerRegistration: "generated",
        androidEnrollment: pending,
      };
    },
    assertAvailable: available,
    proof,
    remove: async (identity) => {
      if (!identity.retired) throw new FirstPartyClientError("invalid_state");
      sameKey(identity);
      await call(() =>
        native.integrity.removeKey(identity.dpopAlias, identity.dpopJkt),
      );
    },
    admission: async (identity, binding, context) => {
      check(context.signal);
      if (
        binding.provider !== "android-hardware" ||
        binding.dpopJkt !== identity.dpopJkt ||
        binding.issuer !== issuer ||
        binding.clientId !== options.clientId ||
        binding.applicationId !== options.applicationId ||
        binding.environment !== options.environment
      )
        throw new FirstPartyClientError("invalid_state");
      await available(identity);
      const response = await post(
        "/first-party/attestation/challenge",
        { keyId: identity.providerKeyId, binding },
        context.signal,
        identity,
      );
      const missing = z
        .object({ code: z.literal("DEVICE_ATTESTATION_CREDENTIAL_REQUIRED") })
        .safeParse(response.body);
      if (response.status === 400 && missing.success) {
        if (
          identity.providerRegistration !== "generated" ||
          !identity.androidEnrollment
        )
          throw new FirstPartyClientError("registration_recovery_required");
        const pending = parse(enrollment, identity.androidEnrollment);
        window(pending);
        const certificateChain = parse(
          chain,
          await call(() =>
            native.integrity.certificateChain(
              identity.dpopAlias,
              identity.dpopJkt,
            ),
          ),
        );
        const requestHash = await registrationHash(
          binding,
          pending.attestationChallenge,
        );
        const integrityToken = await play(requestHash, context.signal);
        window(pending);
        // Write before the one-time server nonce can be consumed. A lost response
        // is recovered with the normal admission probe, never a second enrollment.
        await context.saveIdentity({
          ...identity,
          providerRegistration: "attesting",
        });
        return accepted(
          await post(
            "/first-party/android/register",
            {
              binding,
              keyChallengeToken: pending.keyChallengeToken,
              certificateChain,
              integrityToken,
            },
            context.signal,
            identity,
          ),
          identity,
          context,
        );
      }
      const current = parse(challenge, success(response));
      window(current, true);
      const evidence = await play(current.requestHash, context.signal);
      window(current, true);
      return accepted(
        await post(
          "/first-party/attestation/verify",
          {
            clientId: options.clientId,
            keyId: identity.providerKeyId,
            challengeToken: current.challengeToken,
            evidence,
          },
          context.signal,
          identity,
        ),
        identity,
        context,
      );
    },
  };
}
