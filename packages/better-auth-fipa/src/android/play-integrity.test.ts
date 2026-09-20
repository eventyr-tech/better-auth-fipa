import { afterEach, describe, expect, it, vi } from "vitest";
import {
  createPlayIntegrityVerifier,
  type PlayIntegrityOptions,
} from "./play-integrity.js";

const time = new Date("2026-09-18T12:00:00.000Z");
const signer = Buffer.alloc(32, 1).toString("base64url");
const rotatedSigner = Buffer.alloc(32, 2).toString("base64url");
const requestHash = Buffer.alloc(32, 3).toString("base64url");
const policy: PlayIntegrityOptions = {
  packageName: "io.example.mobile",
  policyVersion: "android-production-v1",
  signingCertificateSets: [[signer], [rotatedSigner]],
  minimumVersionCode: "42",
  maxAgeSeconds: 120,
  clockSkewSeconds: 5,
  requireStrongIntegrity: false,
  getAccessToken: () => Promise.resolve("private-google-token"),
};
const expectation = () => ({
  requestHash,
  challengeIssuedAt: new Date(time.getTime() - 10_000),
  challengeExpiresAt: new Date(time.getTime() + 110_000),
});
function verdict() {
  return {
    tokenPayloadExternal: {
      requestDetails: {
        requestPackageName: policy.packageName,
        requestHash,
        timestampMillis: String(time.getTime() - 1000),
      },
      appIntegrity: {
        appRecognitionVerdict: "PLAY_RECOGNIZED",
        packageName: policy.packageName,
        certificateSha256Digest: [signer],
        versionCode: "42",
      },
      accountDetails: { appLicensingVerdict: "LICENSED" },
      deviceIntegrity: { deviceRecognitionVerdict: ["MEETS_DEVICE_INTEGRITY"] },
    },
  };
}
function fixture(
  payload: unknown = verdict(),
  overrides: Partial<PlayIntegrityOptions> = {},
) {
  const fetcher = vi
    .fn<typeof fetch>()
    .mockImplementation(() => Promise.resolve(Response.json(payload)));
  const access = vi.fn(policy.getAccessToken);
  const verifier = createPlayIntegrityVerifier(
    { ...policy, getAccessToken: access, ...overrides },
    { fetch: fetcher, now: () => new Date(time) },
  );
  return {
    fetcher,
    access,
    verify: () => verifier.verify("opaque.encrypted.token", expectation()),
    verifier,
  };
}
afterEach(() => vi.useRealTimers());

describe("Play Integrity standard server verification", () => {
  it("decodes once at Google's fixed endpoint and returns only bounded interaction assurance", async () => {
    const f = fixture({ ...verdict(), ignored: "not persisted" });
    expect(await f.verify()).toEqual({
      provider: "play-integrity",
      kind: "interaction-verdict",
      requestType: "standard",
      packageName: policy.packageName,
      signingCertificateDigests: [signer],
      versionCode: "42",
      licensing: "LICENSED",
      deviceIntegrity: "MEETS_DEVICE_INTEGRITY",
      timestampMillis: time.getTime() - 1000,
      verifiedAt: time,
      expiresAt: expectation().challengeExpiresAt,
      policyVersion: policy.policyVersion,
    });
    expect(f.fetcher).toHaveBeenCalledOnce();
    expect(f.access).toHaveBeenCalledOnce();
    expect(f.fetcher).toHaveBeenCalledWith(
      "https://playintegrity.googleapis.com/v1/io.example.mobile:decodeIntegrityToken",
      expect.objectContaining({
        method: "POST",
        redirect: "error",
        credentials: "omit",
        cache: "no-store",
        body: JSON.stringify({ integrity_token: "opaque.encrypted.token" }),
        headers: {
          authorization: "Bearer private-google-token",
          "content-type": "application/json",
          accept: "application/json",
        },
      }),
    );
  });

  it.each([
    [
      "wrong request package",
      (v: ReturnType<typeof verdict>) => {
        v.tokenPayloadExternal.requestDetails.requestPackageName =
          "io.attacker.app";
      },
    ],
    [
      "wrong verified package",
      (v: ReturnType<typeof verdict>) => {
        v.tokenPayloadExternal.appIntegrity.packageName = "io.attacker.app";
      },
    ],
    [
      "wrong transaction",
      (v: ReturnType<typeof verdict>) => {
        v.tokenPayloadExternal.requestDetails.requestHash = signer;
      },
    ],
    [
      "unrecognized app",
      (v: ReturnType<typeof verdict>) => {
        v.tokenPayloadExternal.appIntegrity.appRecognitionVerdict =
          "UNRECOGNIZED_VERSION";
      },
    ],
    [
      "unlicensed",
      (v: ReturnType<typeof verdict>) => {
        v.tokenPayloadExternal.accountDetails.appLicensingVerdict =
          "UNLICENSED";
      },
    ],
    [
      "cleared replay verdict",
      (v: ReturnType<typeof verdict>) => {
        v.tokenPayloadExternal.deviceIntegrity.deviceRecognitionVerdict = [];
      },
    ],
    [
      "basic only",
      (v: ReturnType<typeof verdict>) => {
        v.tokenPayloadExternal.deviceIntegrity.deviceRecognitionVerdict = [
          "MEETS_BASIC_INTEGRITY",
        ];
      },
    ],
    [
      "virtual only",
      (v: ReturnType<typeof verdict>) => {
        v.tokenPayloadExternal.deviceIntegrity.deviceRecognitionVerdict = [
          "MEETS_VIRTUAL_INTEGRITY",
        ];
      },
    ],
    [
      "stale",
      (v: ReturnType<typeof verdict>) => {
        v.tokenPayloadExternal.requestDetails.timestampMillis = String(
          time.getTime() - 120_000,
        );
      },
    ],
    [
      "predates challenge",
      (v: ReturnType<typeof verdict>) => {
        v.tokenPayloadExternal.requestDetails.timestampMillis = String(
          time.getTime() - 15_001,
        );
      },
    ],
    [
      "future",
      (v: ReturnType<typeof verdict>) => {
        v.tokenPayloadExternal.requestDetails.timestampMillis = String(
          time.getTime() + 5001,
        );
      },
    ],
    [
      "unsafe timestamp",
      (v: ReturnType<typeof verdict>) => {
        v.tokenPayloadExternal.requestDetails.timestampMillis =
          "9007199254740993";
      },
    ],
    [
      "exponent timestamp",
      (v: ReturnType<typeof verdict>) => {
        v.tokenPayloadExternal.requestDetails.timestampMillis = "1e12";
      },
    ],
    [
      "old version",
      (v: ReturnType<typeof verdict>) => {
        v.tokenPayloadExternal.appIntegrity.versionCode = "41";
      },
    ],
    [
      "noncanonical version",
      (v: ReturnType<typeof verdict>) => {
        v.tokenPayloadExternal.appIntegrity.versionCode = "042";
      },
    ],
    [
      "unknown signer",
      (v: ReturnType<typeof verdict>) => {
        v.tokenPayloadExternal.appIntegrity.certificateSha256Digest = [
          requestHash,
        ];
      },
    ],
    [
      "extra signer",
      (v: ReturnType<typeof verdict>) => {
        v.tokenPayloadExternal.appIntegrity.certificateSha256Digest = [
          signer,
          rotatedSigner,
        ];
      },
    ],
    [
      "duplicate signer",
      (v: ReturnType<typeof verdict>) => {
        v.tokenPayloadExternal.appIntegrity.certificateSha256Digest = [
          signer,
          signer,
        ];
      },
    ],
    [
      "padded signer",
      (v: ReturnType<typeof verdict>) => {
        v.tokenPayloadExternal.appIntegrity.certificateSha256Digest = [
          signer + "=",
        ];
      },
    ],
  ])(
    "rejects %s without retrying or leaking evidence",
    async (_label, mutate) => {
      const value = verdict();
      mutate(value);
      const f = fixture(value);
      await expect(f.verify()).rejects.toMatchObject({
        code: "DEVICE_ATTESTATION_REJECTED",
        reason: "play_integrity_policy_rejected",
      });
      expect(f.fetcher).toHaveBeenCalledOnce();
    },
  );

  it("rejects classic, testing and missing verdict fields", async () => {
    const classic = verdict();
    Object.assign(classic.tokenPayloadExternal.requestDetails, {
      nonce: requestHash,
    });
    await expect(fixture(classic).verify()).rejects.toMatchObject({
      code: "DEVICE_ATTESTATION_REJECTED",
    });
    const testing = verdict();
    Object.assign(testing.tokenPayloadExternal, {
      testingDetails: { isTestingResponse: true },
    });
    await expect(fixture(testing).verify()).rejects.toMatchObject({
      code: "DEVICE_ATTESTATION_REJECTED",
    });
    await expect(
      fixture({ tokenPayloadExternal: {} }).verify(),
    ).rejects.toMatchObject({ code: "DEVICE_ATTESTATION_REJECTED" });
  });

  it("accepts configured rotation and exact multi-signer sets with order independence", async () => {
    const value = verdict();
    value.tokenPayloadExternal.appIntegrity.certificateSha256Digest = [
      rotatedSigner,
    ];
    expect((await fixture(value).verify()).signingCertificateDigests).toEqual([
      rotatedSigner,
    ]);
    value.tokenPayloadExternal.appIntegrity.certificateSha256Digest = [
      rotatedSigner,
      signer,
    ];
    expect(
      (
        await fixture(value, {
          signingCertificateSets: [[signer, rotatedSigner]],
        }).verify()
      ).signingCertificateDigests,
    ).toEqual([rotatedSigner, signer]);
  });

  it("requires strong integrity when configured and preserves precise large versions", async () => {
    await expect(
      fixture(verdict(), { requireStrongIntegrity: true }).verify(),
    ).rejects.toMatchObject({ code: "DEVICE_ATTESTATION_REJECTED" });
    const value = verdict();
    value.tokenPayloadExternal.deviceIntegrity.deviceRecognitionVerdict.push(
      "MEETS_STRONG_INTEGRITY",
    );
    value.tokenPayloadExternal.appIntegrity.versionCode = "9007199254740993";
    expect(
      await fixture(value, {
        requireStrongIntegrity: true,
        minimumVersionCode: "9007199254740993",
      }).verify(),
    ).toMatchObject({
      deviceIntegrity: "MEETS_STRONG_INTEGRITY",
      versionCode: "9007199254740993",
    });
    await expect(
      fixture(value, { minimumVersionCode: "9007199254740994" }).verify(),
    ).rejects.toMatchObject({ code: "DEVICE_ATTESTATION_REJECTED" });
  });

  it("caps lifetime at evidence freshness and does not extend it for future clock skew", async () => {
    const value = verdict();
    const f = fixture(value, { maxAgeSeconds: 10 });
    expect((await f.verify()).expiresAt).toEqual(
      new Date(time.getTime() + 9000),
    );
    value.tokenPayloadExternal.requestDetails.timestampMillis = String(
      time.getTime() + 5000,
    );
    expect((await f.verify()).expiresAt).toEqual(
      new Date(time.getTime() + 10_000),
    );
  });

  it("enforces evidence age independently of challenge age and rejects post-expiry timestamps", async () => {
    const value = verdict();
    value.tokenPayloadExternal.requestDetails.timestampMillis = String(
      time.getTime() - 120_000,
    );
    const f = fixture(value);
    await expect(
      f.verifier.verify("opaque", {
        ...expectation(),
        challengeIssuedAt: new Date(time.getTime() - 200_000),
      }),
    ).rejects.toMatchObject({ code: "DEVICE_ATTESTATION_REJECTED" });
    value.tokenPayloadExternal.requestDetails.timestampMillis = String(
      time.getTime() + 2000,
    );
    await expect(
      f.verifier.verify("opaque", {
        ...expectation(),
        challengeExpiresAt: new Date(time.getTime() + 1000),
      }),
    ).rejects.toMatchObject({ code: "DEVICE_ATTESTATION_REJECTED" });
  });

  it("validates local input before obtaining a service credential or making network calls", async () => {
    const f = fixture();
    for (const token of ["", "a".repeat(32_769), "secret\nvalue", "a/../b"]) {
      await expect(
        f.verifier.verify(token, expectation()),
      ).rejects.toMatchObject({ code: "DEVICE_ATTESTATION_REJECTED" });
    }
    for (const expected of [
      { ...expectation(), requestHash: "bad" },
      { ...expectation(), challengeExpiresAt: time },
      { ...expectation(), challengeIssuedAt: new Date(time.getTime() + 1) },
      { ...expectation(), challengeIssuedAt: new Date(NaN) },
    ])
      await expect(f.verifier.verify("opaque", expected)).rejects.toMatchObject(
        { stage: "challenge" },
      );
    expect(f.access).not.toHaveBeenCalled();
    expect(f.fetcher).not.toHaveBeenCalled();
  });

  it("rechecks challenge expiry after remote decoding and snapshots mutable expectations", async () => {
    let current = new Date(time);
    const expected = expectation();
    const payload = verdict();
    const fetcher = vi.fn<typeof fetch>().mockImplementation(() => {
      expected.requestHash = signer;
      return Promise.resolve(Response.json(payload));
    });
    const verifier = createPlayIntegrityVerifier(policy, {
      fetch: fetcher,
      now: () => current,
    });
    await expect(verifier.verify("opaque", expected)).resolves.toMatchObject({
      kind: "interaction-verdict",
    });
    fetcher.mockImplementation(() => {
      current = new Date(time.getTime() + 110_000);
      return Promise.resolve(Response.json(payload));
    });
    await expect(
      verifier.verify("opaque", expectation()),
    ).rejects.toMatchObject({ stage: "challenge" });
  });

  it.each([400, 401, 403, 429, 500, 302])(
    "fails closed for Google HTTP %i without exposing the response",
    async (status) => {
      const f = fixture();
      const response = new Response("private-secret-evidence", { status });
      const read = vi.spyOn(response, "text");
      f.fetcher.mockResolvedValue(response);
      const error: unknown = await f.verify().catch((error: unknown) => error);
      expect(error).toMatchObject({
        code:
          status === 400
            ? "DEVICE_ATTESTATION_REJECTED"
            : "DEVICE_ATTESTATION_RETRY",
      });
      expect(String(error)).not.toContain("private-secret");
      expect(read).not.toHaveBeenCalled();
      expect(f.fetcher).toHaveBeenCalledOnce();
    },
  );

  it("sanitizes credential-provider and network errors and invalid credentials", async () => {
    for (const getAccessToken of [
      () => Promise.reject(new Error("private-service-key")),
      () => Promise.resolve("token\r\ninjected"),
      () => Promise.resolve(""),
    ]) {
      const f = fixture(verdict(), { getAccessToken });
      await expect(f.verify()).rejects.toMatchObject({
        code: "DEVICE_ATTESTATION_RETRY",
        message: "The attestation operation must be retried.",
      });
      expect(f.fetcher).not.toHaveBeenCalled();
    }
    const f = fixture();
    f.fetcher.mockRejectedValue(new Error("private-network-data"));
    await expect(f.verify()).rejects.toMatchObject({
      code: "DEVICE_ATTESTATION_RETRY",
      message: "The attestation operation must be retried.",
    });
  });

  it("rejects invalid, non-JSON and oversized streamed responses and cancels reading", async () => {
    for (const response of [
      new Response("{}"),
      new Response("not JSON", {
        headers: { "content-type": "application/json" },
      }),
      new Response(new Uint8Array([0xff]), {
        headers: { "content-type": "application/json" },
      }),
      new Response("{}", {
        headers: {
          "content-type": "application/json",
          "content-length": "65537",
        },
      }),
      new Response("{}", {
        headers: {
          "content-type": "application/json",
          "content-length": "invalid",
        },
      }),
      new Response(null, { headers: { "content-type": "application/json" } }),
    ]) {
      const f = fixture();
      f.fetcher.mockResolvedValue(response);
      await expect(f.verify()).rejects.toMatchObject({
        code: "DEVICE_ATTESTATION_RETRY",
      });
    }
    const cancel = vi.fn();
    const f = fixture();
    f.fetcher.mockResolvedValue(
      new Response(
        new ReadableStream({
          start(controller) {
            controller.enqueue(new Uint8Array(65_537));
          },
          cancel,
        }),
        { headers: { "content-type": "application/json" } },
      ),
    );
    await expect(f.verify()).rejects.toMatchObject({
      code: "DEVICE_ATTESTATION_RETRY",
    });
    expect(cancel).toHaveBeenCalledOnce();
  });

  it("bounds credential acquisition and never starts a late decode after timeout", async () => {
    vi.useFakeTimers();
    let resolveToken: (token: string) => void = () => {};
    const f = fixture(verdict(), {
      timeoutMs: 20,
      getAccessToken: () =>
        new Promise((resolve) => {
          resolveToken = resolve;
        }),
    });
    const pending = expect(f.verify()).rejects.toMatchObject({
      code: "DEVICE_ATTESTATION_RETRY",
    });
    await vi.advanceTimersByTimeAsync(20);
    await pending;
    resolveToken("late-token");
    await vi.advanceTimersByTimeAsync(1);
    expect(f.fetcher).not.toHaveBeenCalled();
  });

  it("bounds hung decoding and aborts the outgoing request without retry", async () => {
    vi.useFakeTimers();
    const f = fixture(verdict(), { timeoutMs: 20 });
    f.fetcher.mockImplementation(() => new Promise(() => {}));
    const pending = expect(f.verify()).rejects.toMatchObject({
      code: "DEVICE_ATTESTATION_RETRY",
    });
    await vi.advanceTimersByTimeAsync(20);
    await pending;
    expect(f.fetcher).toHaveBeenCalledOnce();
    expect(f.fetcher.mock.calls[0]?.[1]?.signal?.aborted).toBe(true);
  });

  it("validates and copies immutable server policy", async () => {
    for (const override of [
      { packageName: "../attacker" },
      { signingCertificateSets: [] },
      { signingCertificateSets: [[signer, signer]] },
      { signingCertificateSets: [["bad"]] },
      { maxAgeSeconds: 301 },
      { clockSkewSeconds: 31 },
      { timeoutMs: 30_001 },
      { minimumVersionCode: "-1" },
      { policyVersion: "" },
    ])
      expect(() => fixture(verdict(), override)).toThrow(TypeError);
    const signingCertificateSets = [[signer]];
    const value = verdict();
    value.tokenPayloadExternal.appIntegrity.certificateSha256Digest = [
      rotatedSigner,
    ];
    const f = fixture(value, { signingCertificateSets });
    signingCertificateSets[0]?.push(rotatedSigner);
    signingCertificateSets.push([rotatedSigner]);
    await expect(f.verify()).rejects.toMatchObject({
      code: "DEVICE_ATTESTATION_REJECTED",
    });
  });
});
