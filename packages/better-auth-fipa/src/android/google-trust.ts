import { X509Certificate } from "node:crypto";
import { z } from "zod";
import { DeviceAttestationError } from "../errors.js";
import { sha256 } from "../protocol/crypto.js";
import type { AndroidTrustSnapshot } from "./key-attestation.js";
import { readBoundedGoogleJson } from "./google-response.js";

const ROOT_URL = "https://android.googleapis.com/attestation/root";
const STATUS_URL = "https://android.googleapis.com/attestation/status";
// This pin authorizes the legacy factory-expiry exception only. The key must
// STILL be present in Google's currently valid root document to be trusted.
const FACTORY_ROOT = "_rLqdVHuMW7Uu0Q8gpO4hNv96kC2A-4-T0qJfkWA-64";
const rootsSchema = z.array(z.string().min(1).max(24_000)).min(1).max(16);
const statusSchema = z.strictObject({
  entries: z.record(
    z.string().regex(/^[1-9a-f][0-9a-f]{0,63}$/),
    z.object({ status: z.enum(["REVOKED", "SUSPENDED"]) }),
  ),
});
export interface GoogleTrustOptions {
  /** Total deadline for fetching/decoding both documents. Default 10 seconds. */
  timeoutMs?: number;
  /** Local retention cap, further limited by HTTP freshness. Default one hour. */
  maxCacheSeconds?: number;
}

/** Process-local, single-flight trust loader. No endpoint override, stale fallback,
 * disk seed, trust-on-first-use, device-provided roots or background retry exists.
 * HTTPS uses the runtime's normal authenticated transport. The runtime injection
 * is internal test support; this module is not a public package entry. */
export function createGoogleAttestationTrust(
  options: GoogleTrustOptions = {},
  runtime: { fetch?: typeof fetch; now?: () => Date } = {},
) {
  const timeoutMs = options.timeoutMs ?? 10_000;
  const maxCacheSeconds = options.maxCacheSeconds ?? 3600;
  if (
    !Number.isSafeInteger(timeoutMs) ||
    timeoutMs < 1 ||
    timeoutMs > 30_000 ||
    !Number.isSafeInteger(maxCacheSeconds) ||
    maxCacheSeconds < 1 ||
    maxCacheSeconds > 86_400
  )
    throw new TypeError("Invalid Google attestation trust cache policy.");
  const fetcher = runtime.fetch ?? globalThis.fetch;
  const now = runtime.now ?? (() => new Date());
  let cached: AndroidTrustSnapshot | undefined;
  let pending: Promise<AndroidTrustSnapshot> | undefined;

  async function refresh(): Promise<AndroidTrustSnapshot> {
    const started = clock(now);
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const deadline = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        controller.abort();
        reject(unavailable());
      }, timeoutMs);
    });
    const fetchDocument = async (url: string, maxBytes: number) => {
      const requestedAt = clock(now);
      const response = await fetcher(url, {
        method: "GET",
        headers: { accept: "application/json" },
        redirect: "error",
        credentials: "omit",
        cache: "no-store",
        signal: controller.signal,
      });
      controller.signal.throwIfAborted();
      if (
        response.status !== 200 ||
        response.redirected ||
        (response.url && response.url !== url)
      ) {
        void response.body?.cancel().catch(() => {});
        throw unavailable();
      }
      try {
        const receivedAt = clock(now);
        const expiresAt = freshness(
          response.headers,
          requestedAt,
          receivedAt,
          maxCacheSeconds,
        );
        const document = await readBoundedGoogleJson(
          response,
          maxBytes,
          controller.signal,
        );
        controller.signal.throwIfAborted();
        return { document, expiresAt };
      } catch (error) {
        void response.body?.cancel().catch(() => {});
        throw error;
      }
    };
    const load = async (): Promise<AndroidTrustSnapshot> => {
      const [rootsResponse, statusResponse] = await Promise.all([
        fetchDocument(ROOT_URL, 512_000),
        fetchDocument(STATUS_URL, 2_097_152),
      ]);
      controller.signal.throwIfAborted();
      const roots = parseRoots(rootsResponse.document);
      const status = statusSchema.safeParse(statusResponse.document);
      if (!status.success) throw unavailable();
      const revokedSerials = Object.keys(status.data.entries).sort();
      if (revokedSerials.length > 100_000) throw unavailable();
      const finished = clock(now);
      const expiresAt = Math.min(
        rootsResponse.expiresAt,
        statusResponse.expiresAt,
        started + maxCacheSeconds * 1000,
      );
      if (finished < started || finished >= expiresAt) throw unavailable();
      return {
        version: `google-v1:${sha256(Buffer.from(JSON.stringify([roots, revokedSerials]))).toString("base64url")}`,
        fetchedAt: new Date(started),
        expiresAt: new Date(expiresAt),
        roots,
        revokedSerials,
      };
    };
    try {
      return await Promise.race([load(), deadline]);
    } catch {
      throw unavailable();
    } finally {
      clearTimeout(timer);
      controller.abort();
    }
  }
  return {
    async get(): Promise<AndroidTrustSnapshot> {
      const current = clock(now);
      if (
        cached &&
        cached.fetchedAt.getTime() <= current &&
        cached.expiresAt.getTime() > current
      )
        return structuredClone(cached);
      if (!pending) {
        // Commit only the complete pair after all checks. Timed-out load work
        // cannot later replace the cache, even if a custom transport ignores abort.
        pending = refresh()
          .then((value) => {
            cached = value;
            return value;
          })
          .finally(() => {
            pending = undefined;
          });
      }
      const value = await pending;
      const checkedAt = clock(now);
      if (
        checkedAt < value.fetchedAt.getTime() ||
        checkedAt >= value.expiresAt.getTime()
      )
        throw unavailable();
      return structuredClone(value);
    },
  };
}

function parseRoots(input: unknown) {
  const parsed = rootsSchema.safeParse(input);
  if (!parsed.success) throw unavailable();
  const roots = parsed.data.map((pem) => {
    if (
      !/^-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+\r?\n-----END CERTIFICATE-----\s*$/.test(
        pem,
      )
    )
      throw unavailable();
    const certificate = new X509Certificate(pem);
    if (
      !certificate.ca ||
      certificate.subject !== certificate.issuer ||
      !certificate.verify(certificate.publicKey)
    )
      throw unavailable();
    const spkiSha256 = sha256(
      certificate.publicKey.export({ format: "der", type: "spki" }),
    ).toString("base64url");
    return { spkiSha256, allowFactoryExpiry: spkiSha256 === FACTORY_ROOT };
  });
  return [
    ...new Map(roots.map((entry) => [entry.spkiSha256, entry])).values(),
  ].sort((a, b) =>
    a.spkiSha256 < b.spkiSha256 ? -1 : a.spkiSha256 > b.spkiSha256 ? 1 : 0,
  );
}

/** Conservative HTTP freshness: never restart Google's max-age on a cached
 * response. Age, origin Date, request duration and local cap all constrain it. */
function freshness(
  headers: Headers,
  requestedAt: number,
  receivedAt: number,
  maxCacheSeconds: number,
) {
  const control = headers.get("cache-control");
  const age = headers.get("age");
  const date = Date.parse(headers.get("date") ?? "");
  if (
    !control ||
    !Number.isFinite(date) ||
    date > receivedAt + 30_000 ||
    receivedAt < requestedAt ||
    (age !== null && !/^\d{1,10}$/.test(age))
  )
    throw unavailable();
  const directives = control
    .split(",")
    .map((part) => part.trim().toLowerCase());
  if (
    directives.some((part) =>
      /^(?:no-store|no-cache|private)(?:\s*=|$)/.test(part),
    )
  )
    throw unavailable();
  const maxAges = directives.filter((part) => /^max-age(?:\s*=|$)/.test(part));
  const match =
    maxAges.length === 1
      ? /^max-age\s*=\s*(?:"(\d{1,10})"|(\d{1,10}))$/.exec(maxAges[0]!)
      : null;
  if (!match) throw unavailable();
  const lifetime = Number(match[1] ?? match[2]) * 1000;
  const responseDelay = receivedAt - requestedAt;
  const currentAge = Math.max(
    Math.max(0, receivedAt - date),
    Number(age ?? "0") * 1000 + responseDelay,
  );
  const remaining = Math.min(maxCacheSeconds * 1000, lifetime - currentAge);
  if (remaining <= 0) throw unavailable();
  return receivedAt + remaining;
}
function clock(now: () => Date) {
  const value = now().getTime();
  if (!Number.isSafeInteger(value)) throw unavailable();
  return value;
}
function unavailable() {
  return new DeviceAttestationError({
    code: "DEVICE_ATTESTATION_RETRY",
    stage: "certificate-chain",
    reason: "android_trust_unavailable",
    retryable: true,
  });
}
