import { createPublicKey, verify } from "node:crypto";
import { z } from "zod";
import { decodeBase64Strict } from "./encoding/base64.js";
import { rejection } from "./errors.js";
import type { DeviceAttestationProvider } from "./types.js";

export const IOS_SIMULATOR_PROVIDER = "ios-simulator";

/** Additional fail-closed guard; hosts must omit this provider from production. */
export function simulatorPolicyAllowed(provider: string, environment: string) {
  return (
    provider !== IOS_SIMULATOR_PROVIDER ||
    (environment === "development" && process.env.NODE_ENV !== "production")
  );
}

const envelope = z.strictObject({
  version: z.literal(1),
  provider: z.literal(IOS_SIMULATOR_PROVIDER),
  operation: z.enum(["register", "assert"]),
  jwk: z.strictObject({
    kty: z.literal("EC"),
    crv: z.literal("P-256"),
    x: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
    y: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
  }),
  signature: z.string().regex(/^[A-Za-z0-9_-]{86}$/),
});

/** Development proof of software-key possession, NOT hardware/app attestation.
 * Omit from hosted production, even when NODE_ENV is not set to production. */
export function iosSimulator(options: {
  enabled: true;
  environment: "development";
  applicationIds: readonly string[];
}): DeviceAttestationProvider {
  if (
    options.enabled !== true ||
    !simulatorPolicyAllowed(IOS_SIMULATOR_PROVIDER, options.environment) ||
    !options.applicationIds.length ||
    new Set(options.applicationIds).size !== options.applicationIds.length ||
    options.applicationIds.some((id) => !id || id.length > 256)
  )
    throw new TypeError(
      "iOS Simulator requires explicit development opt-in and unique application IDs; omit it from production.",
    );
  const applications = new Set(options.applicationIds);
  const eligible = (applicationId?: string) => {
    if (
      !simulatorPolicyAllowed(IOS_SIMULATOR_PROVIDER, "development") ||
      (applicationId !== undefined && !applications.has(applicationId))
    )
      throw rejection("platform-policy", "simulator_not_allowed");
  };
  const decodeKeyId = (value: string) => {
    eligible();
    return decodeBase64Strict(value, {
      label: "simulator_key_id",
      maxBytes: 32,
      exactBytes: 32,
    });
  };
  function evidence(
    input: {
      keyId: Uint8Array;
      clientDataHash: Uint8Array;
      evidence: Uint8Array;
    },
    operation: "register" | "assert",
  ) {
    if (
      input.evidence.length > 4096 ||
      input.keyId.length !== 32 ||
      input.clientDataHash.length !== 32
    )
      throw rejection("signature", "invalid_simulator_evidence");
    try {
      const data = envelope.parse(
        JSON.parse(Buffer.from(input.evidence).toString("utf8")) as unknown,
      );
      if (data.operation !== operation) throw new Error();
      const key = createPublicKey({ key: data.jwk, format: "jwk" });
      const message = `fipa/ios-simulator/v1\n${operation}\n${Buffer.from(input.keyId).toString("base64")}\n${Buffer.from(input.clientDataHash).toString("base64")}`;
      const signature = Buffer.from(data.signature, "base64url");
      if (
        signature.toString("base64url") !== data.signature ||
        !verify(
          "sha256",
          Buffer.from(message),
          { key, dsaEncoding: "ieee-p1363" },
          signature,
        )
      )
        throw new Error();
      return key.export({ type: "spki", format: "der" }).toString("base64");
    } catch {
      throw rejection("signature", "invalid_simulator_evidence");
    }
  }
  return {
    id: IOS_SIMULATOR_PROVIDER,
    maxEvidenceBytes: 4096,
    decodeKeyId,
    verifyRegistration: (input) =>
      Promise.resolve().then(() => {
        eligible(input.applicationId);
        return {
          applicationId: input.applicationId,
          environment: "development",
          counter: 0,
          publicKey: evidence(input, "register"),
          extensionsPresent: false,
        };
      }),
    verifyAssertion: (input) =>
      Promise.resolve().then(() => {
        eligible(input.credential.applicationId);
        if (
          input.credential.provider !== IOS_SIMULATOR_PROVIDER ||
          input.credential.environment !== "development" ||
          evidence(input, "assert") !== input.credential.publicKey
        )
          throw rejection(
            "credential-binding",
            "simulator_credential_mismatch",
          );
        // The shared one-time challenge and counter CAS prevent replay. This is a
        // server sequence, not an Apple hardware monotonic counter.
        return {
          counter: input.credential.counter + 1,
          extensionsPresent: false,
        };
      }),
  };
}
