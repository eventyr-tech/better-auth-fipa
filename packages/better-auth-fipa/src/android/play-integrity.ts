import { z } from "zod";
import { DeviceAttestationError, rejection } from "../errors.js";

import { readBoundedGoogleJson } from "./google-response.js";
const digest = z
  .string()
  .regex(/^[A-Za-z0-9_-]{43}$/)
  .refine(
    (value) => Buffer.from(value, "base64url").toString("base64url") === value,
  );
const decimal = z.string().regex(/^(?:0|[1-9][0-9]{0,18})$/);
const signerSet = z
  .array(digest)
  .min(1)
  .max(8)
  .refine((values) => new Set(values).size === values.length);
const policySchema = z.strictObject({
  packageName: z
    .string()
    .max(255)
    .regex(/^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$/),
  policyVersion: z.string().min(1).max(128),
  // Each entry is a complete accepted signer set, not an any-of match.
  signingCertificateSets: z.array(signerSet).min(1).max(8),
  minimumVersionCode: decimal,
  maxAgeSeconds: z.number().int().min(1).max(300),
  clockSkewSeconds: z.number().int().min(0).max(30),
  requireStrongIntegrity: z.boolean(),
});

/** Internal until combined with hardware attestation of the actual DPoP key. */
export type PlayIntegrityPolicy = z.infer<typeof policySchema>;
export interface PlayIntegrityOptions extends PlayIntegrityPolicy {
  /** Host obtains a server credential with the playintegrity OAuth scope.
   * No service-account material belongs in the mobile client. */
  getAccessToken: (signal: AbortSignal) => Promise<string>;
  timeoutMs?: number;
}
export interface PlayIntegrityExpectation {
  /** SHA-256 of canonical server-issued admission bytes, from stored state. */
  requestHash: string;
  challengeIssuedAt: Date;
  challengeExpiresAt: Date;
}
export interface VerifiedPlayIntegrity {
  provider: "play-integrity";
  kind: "interaction-verdict";
  requestType: "standard";
  packageName: string;
  signingCertificateDigests: string[];
  versionCode: string;
  licensing: "LICENSED";
  deviceIntegrity: "MEETS_DEVICE_INTEGRITY" | "MEETS_STRONG_INTEGRITY";
  timestampMillis: number;
  verifiedAt: Date;
  expiresAt: Date;
  policyVersion: string;
}

const responseSchema = z.object({
  tokenPayloadExternal: z.object({
    requestDetails: z.object({
      requestPackageName: z.string(),
      requestHash: digest,
      // A classic request must not be interpreted as standard evidence.
      nonce: z.never().optional(),
      timestampMillis: decimal,
    }),
    appIntegrity: z.object({
      appRecognitionVerdict: z.literal("PLAY_RECOGNIZED"),
      packageName: z.string(),
      certificateSha256Digest: signerSet,
      versionCode: decimal,
    }),
    accountDetails: z.object({ appLicensingVerdict: z.literal("LICENSED") }),
    deviceIntegrity: z.object({
      deviceRecognitionVerdict: z.array(z.string().max(128)).min(1).max(16),
    }),
    testingDetails: z
      .object({ isTestingResponse: z.literal(false) })
      .optional(),
  }),
});

/** Decode only on Google's fixed server endpoint. No arbitrary decode callback,
 * local JWT parsing, verdict cache, retry, or classic-request fallback exists.
 * Caller must still atomically consume one-time server challenge state. */
export function createPlayIntegrityVerifier(
  options: PlayIntegrityOptions,
  runtime: { fetch?: typeof fetch; now?: () => Date } = {},
) {
  const { getAccessToken, timeoutMs = 10_000, ...input } = options;
  const parsed = policySchema.safeParse(input);
  if (
    !parsed.success ||
    typeof getAccessToken !== "function" ||
    !Number.isSafeInteger(timeoutMs) ||
    timeoutMs < 1 ||
    timeoutMs > 30_000
  )
    throw new TypeError("Invalid Play Integrity verification policy.");
  // Zod copies the nested policy arrays; later consumer mutations cannot relax it.
  const policy = parsed.data;
  const fetcher = runtime.fetch ?? globalThis.fetch;
  const now = runtime.now ?? (() => new Date());
  const url = `https://playintegrity.googleapis.com/v1/${policy.packageName}:decodeIntegrityToken`;
  return {
    async verify(
      token: string,
      expected: PlayIntegrityExpectation,
    ): Promise<VerifiedPlayIntegrity> {
      if (
        typeof token !== "string" ||
        token.length < 1 ||
        token.length > 32_768 ||
        !/^[A-Za-z0-9_.-]+$/.test(token)
      )
        throw rejection("request", "invalid_play_integrity_token");
      const start = now();
      validateExpectation(expected, start);
      // Retain immutable expectation values across external asynchronous work.
      const binding = {
        requestHash: expected.requestHash,
        challengeIssuedAt: new Date(expected.challengeIssuedAt),
        challengeExpiresAt: new Date(expected.challengeExpiresAt),
      };
      const controller = new AbortController();
      let timer: ReturnType<typeof setTimeout> | undefined;
      const deadline = new Promise<never>((_, reject) => {
        timer = setTimeout(() => {
          controller.abort();
          reject(unavailable());
        }, timeoutMs);
      });
      const decode = async () => {
        const accessToken = await getAccessToken(controller.signal);
        controller.signal.throwIfAborted();
        if (
          typeof accessToken !== "string" ||
          accessToken.length < 1 ||
          accessToken.length > 16_384 ||
          !/^[A-Za-z0-9._~+/-]+=*$/.test(accessToken)
        )
          throw unavailable();
        const response = await fetcher(url, {
          method: "POST",
          headers: {
            authorization: `Bearer ${accessToken}`,
            "content-type": "application/json",
            accept: "application/json",
          },
          body: JSON.stringify({ integrity_token: token }),
          redirect: "error",
          credentials: "omit",
          cache: "no-store",
          signal: controller.signal,
        });
        controller.signal.throwIfAborted();
        // Do not read provider error bodies: they may echo submitted evidence.
        if (!response.ok || response.redirected) {
          void response.body?.cancel().catch(() => {});
          if (response.status === 400 && !response.redirected)
            throw rejection("platform-policy", "play_integrity_token_rejected");
          throw unavailable();
        }
        const payload = await readBoundedGoogleJson(
          response,
          65_536,
          controller.signal,
        );
        controller.signal.throwIfAborted();
        return verifyVerdict(payload, policy, binding, now());
      };
      try {
        return await Promise.race([decode(), deadline]);
      } catch (error) {
        if (error instanceof DeviceAttestationError) throw error;
        throw unavailable();
      } finally {
        clearTimeout(timer);
        controller.abort();
      }
    },
  };
}

function verifyVerdict(
  input: unknown,
  policy: PlayIntegrityPolicy,
  expected: PlayIntegrityExpectation,
  now: Date,
): VerifiedPlayIntegrity {
  validateExpectation(expected, now);
  const parsed = responseSchema.safeParse(input);
  if (!parsed.success) throw rejected();
  const {
    requestDetails: request,
    appIntegrity: app,
    deviceIntegrity: device,
  } = parsed.data.tokenPayloadExternal;
  const timestamp = Number(request.timestampMillis);
  const skew = policy.clockSkewSeconds * 1000;
  const age = policy.maxAgeSeconds * 1000;
  const labels = device.deviceRecognitionVerdict;
  if (
    request.requestPackageName !== policy.packageName ||
    app.packageName !== policy.packageName ||
    request.requestHash !== expected.requestHash ||
    !Number.isSafeInteger(timestamp) ||
    timestamp > now.getTime() + skew ||
    timestamp < expected.challengeIssuedAt.getTime() - skew ||
    timestamp >= expected.challengeExpiresAt.getTime() ||
    now.getTime() - timestamp >= age ||
    BigInt(app.versionCode) < BigInt(policy.minimumVersionCode) ||
    !policy.signingCertificateSets.some(
      (accepted) =>
        accepted.length === app.certificateSha256Digest.length &&
        app.certificateSha256Digest.every((signer) =>
          accepted.includes(signer),
        ),
    ) ||
    !labels.includes("MEETS_DEVICE_INTEGRITY") ||
    (policy.requireStrongIntegrity &&
      !labels.includes("MEETS_STRONG_INTEGRITY"))
  )
    throw rejected();
  return {
    provider: "play-integrity",
    kind: "interaction-verdict",
    requestType: "standard",
    packageName: app.packageName,
    signingCertificateDigests: app.certificateSha256Digest,
    versionCode: app.versionCode,
    licensing: "LICENSED",
    deviceIntegrity: labels.includes("MEETS_STRONG_INTEGRITY")
      ? "MEETS_STRONG_INTEGRITY"
      : "MEETS_DEVICE_INTEGRITY",
    timestampMillis: timestamp,
    verifiedAt: new Date(now),
    // Future skew must not extend evidence authority beyond a full policy age.
    expiresAt: new Date(
      Math.min(
        expected.challengeExpiresAt.getTime(),
        Math.min(timestamp, now.getTime()) + age,
      ),
    ),
    policyVersion: policy.policyVersion,
  };
}
function validateExpectation(expected: PlayIntegrityExpectation, now: Date) {
  if (
    !digest.safeParse(expected.requestHash).success ||
    !Number.isSafeInteger(now.getTime()) ||
    !Number.isSafeInteger(expected.challengeIssuedAt.getTime()) ||
    !Number.isSafeInteger(expected.challengeExpiresAt.getTime()) ||
    expected.challengeIssuedAt > now ||
    expected.challengeExpiresAt <= now ||
    expected.challengeExpiresAt <= expected.challengeIssuedAt
  )
    throw rejection("challenge", "invalid_play_integrity_challenge");
}
function rejected() {
  return rejection("platform-policy", "play_integrity_policy_rejected");
}
function unavailable() {
  return new DeviceAttestationError({
    code: "DEVICE_ATTESTATION_RETRY",
    stage: "platform-policy",
    reason: "play_integrity_unavailable",
    retryable: true,
  });
}
