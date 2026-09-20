import { digest, identifier } from "./identity.ts";
import {
  admissionBindingFields,
  androidRegistrationFields,
} from "./binding-fields.ts";
import {
  assertAdmissionBinding,
  normalizeIssuer,
  nativeOperation as call,
  checkCancelled,
  createAdmissionTransport,
  successfulResponse as success,
  signProof,
  aliasesSchema,
  parseResponse as parse,
} from "./adapter-operations.ts";
import {
  androidIdentitySchema,
  androidEnrollmentSchema,
} from "./android-identity.ts";
import { z } from "zod";
import type { Spec as AndroidIntegrity } from "../NativeAndroidIntegrity.ts";
import type {
  FirstPartyClientPorts,
  NativeBinding,
  NativeIdentity,
} from "./client.ts";
import { FirstPartyClientError } from "./errors.ts";

const enrollment = androidEnrollmentSchema;
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
    issuer = normalizeIssuer(options.issuer, options.allowInsecureLoopback);
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
  const check = checkCancelled;
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
  async function available(identity: NativeIdentity, signal?: AbortSignal) {
    sameKey(identity);
    const existing = await call(
      () => native.integrity.inspectKey(identity.dpopAlias),
      signal,
    );
    if (existing !== identity.dpopJkt)
      throw new FirstPartyClientError("registration_recovery_required");
  }
  const proof: FirstPartyClientPorts["keys"]["proof"] = async (
    identity,
    request,
  ) => {
    sameKey(identity);
    return signProof(
      (...args) => native.integrity.signDpop(...args),
      identity,
      request,
    );
  };
  const post = createAdmissionTransport(issuer, native.send, proof);
  async function hash(value: unknown, signal: AbortSignal) {
    return parse(
      digest,
      await call(
        () => native.integrity.sha256Utf8(JSON.stringify(value)),
        signal,
      ),
    );
  }
  async function registrationHash(
    binding: NativeBinding,
    nonce: string,
    signal: AbortSignal,
  ) {
    const bindingHash = await hash(admissionBindingFields(binding), signal);
    return hash(androidRegistrationFields(nonce, bindingHash), signal);
  }

  async function play(requestHash: string, signal: AbortSignal) {
    check(signal);
    const evidence = await call(
      () =>
        native.integrity.standardIntegrity(
          options.cloudProjectNumber,
          requestHash,
        ),
      signal,
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
    identitySchema: androidIdentitySchema,
    prepare: async (slot, context) => {
      const signal = context?.signal ?? new AbortController().signal;
      check(signal);
      const aliases = aliasesSchema.safeParse(await options.aliases(slot));
      if (!aliases.success)
        throw new FirstPartyClientError("invalid_configuration");
      check(signal);
      const existing = await call(
        () => native.integrity.inspectKey(aliases.data.dpopAlias),
        signal,
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
        await call(
          () =>
            native.integrity.createKey(
              aliases.data.dpopAlias,
              pending.attestationChallenge,
              options.securityLevel,
            ),
          signal,
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
      assertAdmissionBinding(binding, identity, {
        issuer,
        provider: "android-hardware",
        clientId: options.clientId,
        applicationId: options.applicationId,
        environment: options.environment,
      });
      await available(identity, context.signal);
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
          await call(
            () =>
              native.integrity.certificateChain(
                identity.dpopAlias,
                identity.dpopJkt,
              ),
            context.signal,
          ),
        );
        const requestHash = await registrationHash(
          binding,
          pending.attestationChallenge,
          context.signal,
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
