import { readFileSync } from "node:fs";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  createGoogleAttestationTrust,
  type GoogleTrustOptions,
} from "./google-trust.js";

const rootUrl = "https://android.googleapis.com/attestation/root";
const statusUrl = "https://android.googleapis.com/attestation/status";
const time = Date.parse("2026-09-18T12:00:00Z");
const roots = JSON.parse(
  readFileSync(
    new URL("./fixtures/reference-roots.json", import.meta.url),
    "utf8",
  ),
) as string[];
const factoryHash = "_rLqdVHuMW7Uu0Q8gpO4hNv96kC2A-4-T0qJfkWA-64";
const rkpHash = "PuRFEqGvK-s5yIlJDGDqP4LkP11aVTL1q5QZ9nbNB-w";
const rejected = {
  code: "DEVICE_ATTESTATION_RETRY",
  reason: "android_trust_unavailable",
  retryable: true,
};
function response(
  payload: unknown,
  headers: Record<string, string> = {},
  now = time,
) {
  return Response.json(payload, {
    headers: {
      date: new Date(now).toUTCString(),
      "cache-control": "public, max-age=86400",
      ...headers,
    },
  });
}
function fixture(options: GoogleTrustOptions = {}) {
  let now = time;
  const fetcher = vi
    .fn<typeof fetch>()
    .mockImplementation((url) =>
      Promise.resolve(
        response(url === rootUrl ? roots : { entries: {} }, {}, now),
      ),
    );
  const loader = createGoogleAttestationTrust(options, {
    fetch: fetcher,
    now: () => new Date(now),
  });
  return {
    loader,
    fetcher,
    advance: (ms: number) => {
      now += ms;
    },
  };
}
afterEach(() => vi.useRealTimers());

describe("Google Android attestation trust loader", () => {
  it("retrieves only fixed authenticated endpoints and caches a complete bounded snapshot", async () => {
    const f = fixture();
    const snapshot = await f.loader.get();
    expect(snapshot).toEqual({
      version: expect.stringMatching(
        /^google-v1:[A-Za-z0-9_-]{43}$/,
      ) as unknown,
      fetchedAt: new Date(time),
      expiresAt: new Date(time + 3_600_000),
      roots: expect.arrayContaining([
        { spkiSha256: factoryHash, allowFactoryExpiry: true },
        { spkiSha256: rkpHash, allowFactoryExpiry: false },
      ]) as unknown,
      revokedSerials: [],
    });
    expect(f.fetcher).toHaveBeenCalledTimes(2);
    for (const url of [rootUrl, statusUrl]) {
      expect(f.fetcher).toHaveBeenCalledWith(
        url,
        expect.objectContaining({
          method: "GET",
          headers: { accept: "application/json" },
          redirect: "error",
          credentials: "omit",
          cache: "no-store",
          signal: expect.any(AbortSignal) as unknown,
        }),
      );
    }
    // Returned arrays and Date instances cannot mutate the shared cache.
    snapshot.expiresAt.setTime(time + 99_000_000);
    (snapshot.revokedSerials as string[]).push("abc");
    (
      snapshot.roots as { spkiSha256: string; allowFactoryExpiry: boolean }[]
    ).splice(0);
    const next = await f.loader.get();
    expect(next.expiresAt).toEqual(new Date(time + 3_600_000));
    expect(next.roots).toHaveLength(2);
    expect(next.revokedSerials).toEqual([]);
    expect(f.fetcher).toHaveBeenCalledTimes(2);
  });

  it("single-flights concurrent callers and refreshes exactly at expiry", async () => {
    const f = fixture({ maxCacheSeconds: 2 });
    const values = await Promise.all(
      Array.from({ length: 20 }, () => f.loader.get()),
    );
    expect(new Set(values.map((s) => s.version)).size).toBe(1);
    expect(f.fetcher).toHaveBeenCalledTimes(2);
    f.advance(1999);
    await f.loader.get();
    expect(f.fetcher).toHaveBeenCalledTimes(2);
    f.advance(1);
    await f.loader.get();
    expect(f.fetcher).toHaveBeenCalledTimes(4);
  });

  it.each([
    ["Age", { age: "86390" }, 10_000],
    [
      "origin Date",
      { date: new Date(time - 86_380_000).toUTCString() },
      20_000,
    ],
    ["quoted max-age", { "cache-control": 'public, max-age="15"' }, 15_000],
  ])(
    "honors %s instead of restarting remote freshness",
    async (_name, headers, ttl) => {
      const f = fixture();
      f.fetcher.mockImplementation((url) =>
        Promise.resolve(
          response(
            url === rootUrl ? roots : { entries: {} },
            url === statusUrl ? headers : {},
          ),
        ),
      );
      expect((await f.loader.get()).expiresAt.getTime()).toBe(time + ttl);
    },
  );

  it("subtracts response delay from reported Age", async () => {
    const f = fixture();
    f.fetcher.mockImplementation(async (url) => {
      await Promise.resolve();
      if (url === rootUrl) f.advance(2000);
      return response(url === rootUrl ? roots : { entries: {} }, {
        age: "86390",
      });
    });
    expect((await f.loader.get()).expiresAt.getTime()).toBe(time + 10_000);
  });

  it.each([
    { "cache-control": "public" },
    { "cache-control": "max-age=0" },
    { "cache-control": "max-age=20, max-age=20" },
    { "cache-control": 'max-age="20' },
    { "cache-control": 'max-age=20"' },
    { "cache-control": "max-age=-1" },
    { "cache-control": "max-age=60, no-store" },
    { "cache-control": "max-age=60, no-cache" },
    { "cache-control": 'max-age=60, private="Authorization"' },
    { age: "86400" },
    { age: "-1" },
    { age: "1.5" },
    { date: "invalid" },
    { date: new Date(time + 31_000).toUTCString() },
    { date: new Date(time - 86_400_000).toUTCString() },
  ])(
    "rejects missing, malformed or expired HTTP freshness: %j",
    async (headers) => {
      const f = fixture();
      f.fetcher.mockImplementation((url) =>
        Promise.resolve(
          response(url === rootUrl ? roots : { entries: {} }, headers),
        ),
      );
      await expect(f.loader.get()).rejects.toMatchObject(rejected);
    },
  );

  it("includes suspended entries and never discards a revocation based on metadata", async () => {
    const f = fixture();
    f.fetcher.mockImplementation((url) =>
      Promise.resolve(
        response(
          url === rootUrl
            ? [...roots].reverse().concat(roots)
            : {
                entries: {
                  ff: {
                    status: "REVOKED",
                    expires: "2000-01-01",
                    reason: "KEY_COMPROMISE",
                  },
                  a1: { status: "SUSPENDED", comment: "not persisted" },
                },
              },
        ),
      ),
    );
    const snapshot = await f.loader.get();
    expect(snapshot.roots).toHaveLength(2);
    expect(snapshot.revokedSerials).toEqual(["a1", "ff"]);
    const other = fixture();
    other.fetcher.mockImplementation((url) =>
      Promise.resolve(
        response(
          url === rootUrl
            ? roots
            : {
                entries: {
                  a1: { status: "REVOKED" },
                  ff: { status: "REVOKED" },
                },
              },
        ),
      ),
    );
    expect((await other.loader.get()).version).toBe(snapshot.version);
  });

  it("replaces roots and revocations together, including removal of the factory root", async () => {
    const f = fixture({ maxCacheSeconds: 1 });
    const initial = await f.loader.get();
    f.advance(1000);
    f.fetcher.mockImplementation((url) =>
      Promise.resolve(
        response(
          url === rootUrl
            ? [roots[1]]
            : { entries: { abc: { status: "REVOKED" } } },
        ),
      ),
    );
    const updated = await f.loader.get();
    expect(updated.roots).toEqual([
      { spkiSha256: rkpHash, allowFactoryExpiry: false },
    ]);
    expect(updated.revokedSerials).toEqual(["abc"]);
    expect(updated.version).not.toBe(initial.version);
  });

  it("never extends expired trust after a partial fetch failure and can retry cleanly", async () => {
    const f = fixture({ maxCacheSeconds: 1 });
    await f.loader.get();
    f.advance(1000);
    f.fetcher.mockImplementation((url) =>
      Promise.resolve(
        url === statusUrl
          ? new Response("private upstream error", { status: 503 })
          : response([roots[1]]),
      ),
    );
    await expect(f.loader.get()).rejects.toMatchObject(rejected);
    await expect(f.loader.get()).rejects.toMatchObject(rejected);
    f.fetcher.mockImplementation((url) =>
      Promise.resolve(response(url === rootUrl ? roots : { entries: {} })),
    );
    const recovered = await f.loader.get();
    expect(recovered.fetchedAt.getTime()).toBe(time + 1000);
    expect(recovered.roots).toHaveLength(2);
  });

  it.each([
    {},
    { entries: { abc: { status: "GOOD" } } },
    { entries: { abc: {} } },
    { entries: { "00ab": { status: "REVOKED" } } },
    { entries: { AB: { status: "REVOKED" } } },
    { entries: { "0": { status: "REVOKED" } } },
    { entries: {}, unexpected: true },
  ])("fails closed on unexpected revocation schema: %j", async (payload) => {
    const f = fixture();
    f.fetcher.mockImplementation((url) =>
      Promise.resolve(response(url === rootUrl ? roots : payload)),
    );
    await expect(f.loader.get()).rejects.toMatchObject(rejected);
  });

  it.each([
    [],
    ["invalid certificate"],
    Array.from({ length: 17 }, () => roots[0]),
    [roots.join("\n")],
  ])("rejects malformed or ambiguous roots", async (payload) => {
    const f = fixture();
    f.fetcher.mockImplementation((url) =>
      Promise.resolve(response(url === rootUrl ? payload : { entries: {} })),
    );
    await expect(f.loader.get()).rejects.toMatchObject(rejected);
  });

  it("rejects a valid leaf certificate presented as a trusted root", async () => {
    const leaf = readFileSync(
      new URL("./fixtures/akita-chain.pem", import.meta.url),
      "utf8",
    ).match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/)![0];
    const f = fixture();
    f.fetcher.mockImplementation((url) =>
      Promise.resolve(response(url === rootUrl ? [leaf] : { entries: {} })),
    );
    await expect(f.loader.get()).rejects.toMatchObject(rejected);
  });

  it.each([
    "redirect",
    "url",
    "html",
    "length",
    "stream",
    "json",
    "utf8",
    "http",
    "network",
  ])("rejects and redacts %s failures", async (failure) => {
    const f = fixture();
    f.fetcher.mockImplementation(() => {
      if (failure === "network")
        return Promise.reject(new Error("private upstream diagnostic"));
      const headers = {
        "content-type": "application/json",
        date: new Date(time).toUTCString(),
        "cache-control": "max-age=60",
      };
      let result = new Response("[]", { headers });
      if (failure === "redirect")
        Object.defineProperty(result, "redirected", { value: true });
      if (failure === "url")
        Object.defineProperty(result, "url", {
          value: "https://attacker.example/root",
        });
      if (failure === "html") result.headers.set("content-type", "text/html");
      if (failure === "length") result.headers.set("content-length", "3000000");
      if (failure === "stream")
        result = new Response(new Uint8Array(2_100_000), { headers });
      if (failure === "json")
        result = new Response("private upstream diagnostic", { headers });
      if (failure === "utf8")
        result = new Response(new Uint8Array([255]), { headers });
      if (failure === "http")
        result = new Response("private upstream diagnostic", {
          status: 503,
          headers,
        });
      return Promise.resolve(result);
    });
    await expect(f.loader.get()).rejects.toMatchObject({
      ...rejected,
      message: "The attestation operation must be retried.",
    });
  });

  it("bounds ignored aborts and prevents late responses from populating the cache", async () => {
    vi.useFakeTimers();
    const f = fixture({ timeoutMs: 10 });
    const deferred: Array<() => void> = [];
    f.fetcher.mockImplementation(
      (url) =>
        new Promise((resolve) => {
          deferred.push(() =>
            resolve(response(url === rootUrl ? roots : { entries: {} })),
          );
        }),
    );
    const failure = expect(f.loader.get()).rejects.toMatchObject(rejected);
    await vi.advanceTimersByTimeAsync(10);
    await failure;
    for (const complete of deferred) complete();
    await vi.advanceTimersByTimeAsync(0);
    f.fetcher.mockRejectedValue(new Error("unavailable"));
    await expect(f.loader.get()).rejects.toMatchObject(rejected);
    expect(f.fetcher).toHaveBeenCalledTimes(4);
  });

  it("bounds a stalled response body", async () => {
    vi.useFakeTimers();
    const f = fixture({ timeoutMs: 10 });
    const cancel = vi.fn();
    f.fetcher.mockImplementation((url) =>
      Promise.resolve(
        url === rootUrl
          ? response(roots)
          : new Response(new ReadableStream({ cancel }), {
              headers: {
                "content-type": "application/json",
                date: new Date(time).toUTCString(),
                "cache-control": "max-age=60",
              },
            }),
      ),
    );
    const failure = expect(f.loader.get()).rejects.toMatchObject(rejected);
    await vi.advanceTimersByTimeAsync(10);
    await failure;
    expect(cancel).toHaveBeenCalledOnce();
  });

  it("does not reuse cached trust when the wall clock moves before retrieval", async () => {
    const f = fixture();
    await f.loader.get();
    f.advance(-1000);
    f.fetcher.mockRejectedValue(new Error("offline"));
    await expect(f.loader.get()).rejects.toMatchObject(rejected);
    expect(f.fetcher).toHaveBeenCalledTimes(4);
  });

  it.each([
    { timeoutMs: 0 },
    { timeoutMs: 30_001 },
    { timeoutMs: NaN },
    { maxCacheSeconds: 0 },
    { maxCacheSeconds: 86_401 },
    { maxCacheSeconds: 1.5 },
  ])("rejects invalid local policy: %j", (options) => {
    expect(() => createGoogleAttestationTrust(options)).toThrow(TypeError);
  });
});
