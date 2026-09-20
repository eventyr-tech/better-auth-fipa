import "reflect-metadata";
import { beforeAll, describe, expect, it } from "vitest";
import { readFile } from "node:fs/promises";
import {
  X509CertificateGenerator,
  Extension,
  BasicConstraintsExtension,
  KeyUsagesExtension,
  KeyUsageFlags,
  type X509Certificate,
} from "@peculiar/x509";
import { createHash, X509Certificate as NodeCertificate } from "node:crypto";
import {
  createAndroidKeyAttestationVerifier,
  verifyAndroidCertificatePath,
  type AndroidTrustSnapshot,
} from "./key-attestation.js";
import {
  challenge,
  encode,
  model,
  policy,
} from "./fixtures/key-description.fixture.js";

const time = new Date("2026-09-18T00:00:00Z");
const before = new Date("2026-09-01T00:00:00Z");
const after = new Date("2026-10-01T00:00:00Z");
const KEY_DESCRIPTION = "1.3.6.1.4.1.11129.2.1.17";
const PROVISIONING = "1.3.6.1.4.1.11129.2.1.30";
let keys: CryptoKeyPair[];
let root: X509Certificate;
let factory: X509Certificate[];
let rkp: X509Certificate[];
let trust: AndroidTrustSnapshot;
function hash(bytes: Uint8Array | string) {
  return createHash("sha256").update(bytes).digest("base64url");
}
function keyExtension(bytes = encode()) {
  return new Extension(KEY_DESCRIPTION, false, Uint8Array.from(bytes).buffer);
}
function ca() {
  return [
    new BasicConstraintsExtension(true, undefined, true),
    new KeyUsagesExtension(KeyUsageFlags.keyCertSign, true),
  ];
}
async function certificate(
  subject: string,
  issuer: X509Certificate,
  issuerKey: CryptoKeyPair,
  target: CryptoKeyPair,
  serial: string,
  extensions: Extension[],
  dates = { notBefore: before, notAfter: after },
) {
  return X509CertificateGenerator.create({
    subject,
    issuer: issuer.subject,
    publicKey: target.publicKey,
    signingKey: issuerKey.privateKey,
    serialNumber: serial,
    ...dates,
    signingAlgorithm: {
      name: issuerKey.privateKey.algorithm.name,
      hash: "SHA-256",
    },
    extensions,
  });
}
const der = (chain: X509Certificate[]) =>
  chain.map((certificate) =>
    Uint8Array.from(new Uint8Array(certificate.rawData)),
  );
function thumbprint(certificate: X509Certificate) {
  const key = new NodeCertificate(
    Buffer.from(certificate.rawData),
  ).publicKey.export({ format: "jwk" });
  return hash(
    JSON.stringify({ crv: key.crv, kty: key.kty, x: key.x, y: key.y }),
  );
}
beforeAll(async () => {
  keys = await Promise.all(
    Array.from({ length: 6 }, () =>
      crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
        "sign",
        "verify",
      ]),
    ),
  );
  root = await X509CertificateGenerator.createSelfSigned({
    name: "CN=Test root",
    keys: keys[0]!,
    notBefore: before,
    notAfter: after,
    serialNumber: "100",
    signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
    extensions: ca(),
  });
  trust = {
    version: "test-trust-v1",
    fetchedAt: new Date(time.getTime() - 1000),
    expiresAt: new Date(time.getTime() + 60_000),
    roots: [
      {
        spkiSha256: hash(
          new NodeCertificate(Buffer.from(root.rawData)).publicKey.export({
            format: "der",
            type: "spki",
          }),
        ),
        allowFactoryExpiry: true,
      },
    ],
    revokedSerials: [],
  };
  const fIntermediate = await certificate(
    "2.5.4.5=example-factory",
    root,
    keys[0]!,
    keys[1]!,
    "101",
    ca(),
  );
  const fAttestation = await certificate(
    "CN=Factory attestation",
    fIntermediate,
    keys[1]!,
    keys[2]!,
    "102",
    ca(),
  );
  const fLeaf = await certificate(
    "CN=Android Keystore Key",
    fAttestation,
    keys[2]!,
    keys[3]!,
    "103",
    [
      new KeyUsagesExtension(KeyUsageFlags.digitalSignature, true),
      keyExtension(),
    ],
  );
  factory = [fLeaf, fAttestation, fIntermediate, root];
  const rIntermediate = await certificate(
    "O=Google LLC, CN=Droid CA2",
    root,
    keys[0]!,
    keys[1]!,
    "201",
    ca(),
  );
  const rServer = await certificate(
    "O=Google LLC, CN=Droid CA3",
    rIntermediate,
    keys[1]!,
    keys[2]!,
    "202",
    ca(),
  );
  const rAttestation = await certificate(
    "O=TEE, CN=Attestation",
    rServer,
    keys[2]!,
    keys[3]!,
    "203",
    [
      ...ca(),
      new Extension(PROVISIONING, false, new Uint8Array([0xa0]).buffer),
    ],
  );
  const rLeaf = await certificate(
    "CN=Android Keystore Key",
    rAttestation,
    keys[3]!,
    keys[4]!,
    "204",
    [
      new KeyUsagesExtension(KeyUsageFlags.digitalSignature, true),
      keyExtension(),
    ],
  );
  rkp = [rLeaf, rAttestation, rServer, rIntermediate, root];
});
const verify = createAndroidKeyAttestationVerifier(policy);
function input(chain = factory) {
  return {
    certificateChain: der(chain),
    expectedChallenge: challenge,
    expectedDpopJkt: thumbprint(chain[0]!),
    trust,
    now: time,
  };
}

describe("Android signed certificate evidence", () => {
  it.each([
    ["akita", "2024-09-12T00:00:00Z", "rkp"],
    ["frankel", "2026-09-03T00:00:00Z", "rkp"],
    ["blueline", "2026-09-18T00:00:00Z", "factory"],
  ])(
    "authenticates the published %s chain against independently pinned reference roots",
    async (name, date, provisioning) => {
      const pem = await readFile(
        new URL(`./fixtures/${name}-chain.pem`, import.meta.url),
        "utf8",
      );
      const roots: unknown = JSON.parse(
        await readFile(
          new URL("./fixtures/reference-roots.json", import.meta.url),
          "utf8",
        ),
      );
      if (
        !Array.isArray(roots) ||
        !roots.every((root): root is string => typeof root === "string")
      )
        throw new Error("Invalid reference roots");
      const pins = roots.map((pem) => {
        const certificate = new NodeCertificate(pem);
        return {
          spkiSha256: hash(
            certificate.publicKey.export({ format: "der", type: "spki" }),
          ),
          allowFactoryExpiry:
            certificate.subject === "serialNumber=f92009e853b6b045",
        };
      });
      const now = new Date(date);
      const snapshot = {
        version: "reference-only",
        fetchedAt: new Date(now.getTime() - 1000),
        expiresAt: new Date(now.getTime() + 60_000),
        roots: pins,
        revokedSerials: [],
      };
      const chain = (
        pem.match(
          /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g,
        ) ?? []
      ).map((value) => new NodeCertificate(value).raw);
      expect(verifyAndroidCertificatePath(chain, snapshot, now)).toMatchObject({
        provisioning,
      });
      expect(() =>
        verify({
          certificateChain: chain,
          expectedChallenge: challenge,
          expectedDpopJkt: hash("unrelated-key"),
          trust: snapshot,
          now,
        }),
      ).toThrow();
    },
  );
  it.each(["factory", "rkp"] as const)(
    "verifies a %s chain and binds the exact certified DPoP key",
    (kind) => {
      const chain = kind === "factory" ? factory : rkp;
      expect(verify(input(chain))).toMatchObject({
        provider: "android-key-attestation",
        kind: "credential-key",
        dpopJkt: thumbprint(chain[0]!),
        provisioning: kind,
        trustVersion: trust.version,
        properties: { algorithm: "ES256", keySecurityLevel: "tee" },
      });
    },
  );
  it("rejects substituted signing keys and challenges after authenticating the certificate", () => {
    expect(() =>
      verify({ ...input(), expectedDpopJkt: thumbprint(rkp[0]!) }),
    ).toThrow(
      expect.objectContaining({ reason: "android_attested_key_mismatch" }),
    );
    expect(() =>
      verify({ ...input(), expectedChallenge: Buffer.alloc(32) }),
    ).toThrow(
      expect.objectContaining({ reason: "android_key_policy_rejected" }),
    );
  });
  it("rejects wrong roots, corrupt signatures, reordering, truncation, duplicates and trailing bytes", () => {
    expect(() =>
      verify({
        ...input(),
        trust: {
          ...trust,
          roots: [{ spkiSha256: hash("not-root"), allowFactoryExpiry: true }],
        },
      }),
    ).toThrow();
    const corrupted = der(factory);
    corrupted[0]![corrupted[0]!.length - 1]! ^= 1;
    for (const chain of [
      corrupted,
      [...der(factory).reverse()],
      der(factory).slice(1),
      [...der(factory), der(factory)[3]!],
      [
        Buffer.concat([Buffer.from(factory[0]!.rawData), Buffer.from([0])]),
        ...der(factory).slice(1),
      ],
      [new Uint8Array(16_385), ...der(factory).slice(1)],
    ]) {
      expect(() => verify({ ...input(), certificateChain: chain })).toThrow();
    }
  });
  it("requires fresh bounded revocation/root state and checks every serial", () => {
    for (const serial of ["100", "101", "102", "103"]) {
      expect(() =>
        verify({ ...input(), trust: { ...trust, revokedSerials: [serial] } }),
      ).toThrow(
        expect.objectContaining({ reason: "android_certificate_revoked" }),
      );
    }
    for (const change of [
      { expiresAt: time },
      { fetchedAt: new Date(time.getTime() + 1) },
      { expiresAt: new Date(time.getTime() + 86_400_001) },
      { revokedSerials: ["00103"] },
      { roots: [] },
      { version: "" },
    ]) {
      expect(() =>
        verify({ ...input(), trust: { ...trust, ...change } }),
      ).toThrow(
        expect.objectContaining({ reason: "android_trust_unavailable" }),
      );
    }
  });
  it("rejects attacker-extended chains even when the forged leaf has a valid signature and extension", async () => {
    const forged = await certificate(
      "CN=Forged child",
      factory[0]!,
      keys[3]!,
      keys[5]!,
      "999",
      [
        new KeyUsagesExtension(KeyUsageFlags.digitalSignature, true),
        keyExtension(),
      ],
    );
    expect(() => verify(input([forged, ...factory]))).toThrow();
    const nonLeaf = await certificate(
      "CN=Factory attestation",
      factory[2]!,
      keys[1]!,
      keys[2]!,
      "102",
      [...ca(), keyExtension()],
    );
    const child = await certificate(
      "CN=Android Keystore Key",
      nonLeaf,
      keys[2]!,
      keys[3]!,
      "103",
      [
        new KeyUsagesExtension(KeyUsageFlags.digitalSignature, true),
        keyExtension(),
      ],
    );
    expect(() => verify(input([child, nonLeaf, factory[2]!, root]))).toThrow(
      expect.objectContaining({
        reason: "android_attestation_extension_position",
      }),
    );
  });
  it("does not use the factory-root expiry exception for RKP certificates under the same root", () => {
    const future = new Date("2027-01-01T00:00:00Z");
    const futureTrust = {
      ...trust,
      fetchedAt: new Date(future.getTime() - 1000),
      expiresAt: new Date(future.getTime() + 60_000),
    };
    expect(
      verify({ ...input(), now: future, trust: futureTrust }).provisioning,
    ).toBe("factory");
    expect(() =>
      verify({ ...input(rkp), now: future, trust: futureTrust }),
    ).toThrow(
      expect.objectContaining({
        reason: "android_certificate_outside_validity",
      }),
    );
    expect(() =>
      verify({
        ...input(),
        trust: {
          ...trust,
          roots: [{ ...trust.roots[0]!, allowFactoryExpiry: false }],
        },
      }),
    ).toThrow();
  });
  it("rechecks enrolled RKP signatures and current revocation at the server-recorded enrollment date", () => {
    const future = new Date("2027-01-01T00:00:00Z");
    const currentTrust = {
      ...trust,
      fetchedAt: new Date(future.getTime() - 1000),
      expiresAt: new Date(future.getTime() + 60_000),
    };
    const request = {
      ...input(rkp),
      now: future,
      trust: currentTrust,
      verifiedAtCreation: time,
    };
    expect(verify(request)).toMatchObject({
      provisioning: "rkp",
      verifiedAt: future,
    });
    expect(() => verify({ ...request, trust })).toThrow();
    expect(() =>
      verify({
        ...request,
        trust: { ...currentTrust, revokedSerials: ["203"] },
      }),
    ).toThrow();
    expect(() =>
      verify({ ...request, verifiedAtCreation: new Date("2028-01-01") }),
    ).toThrow();
    expect(() =>
      verify({ ...request, verifiedAtCreation: new Date("2026-08-01") }),
    ).toThrow();
  });
  it("rejects not-yet-valid factory intermediates but does not trust device-set leaf dates as freshness", async () => {
    const past = new Date("2026-08-01T00:00:00Z");
    expect(() =>
      verify({
        ...input(),
        now: past,
        trust: {
          ...trust,
          fetchedAt: new Date(past.getTime() - 1000),
          expiresAt: new Date(past.getTime() + 60_000),
        },
      }),
    ).toThrow(
      expect.objectContaining({
        reason: "android_certificate_outside_validity",
      }),
    );
    const leaf = await certificate(
      "CN=Android Keystore Key",
      rkp[1]!,
      keys[3]!,
      keys[4]!,
      "204",
      [
        new KeyUsagesExtension(KeyUsageFlags.digitalSignature, true),
        keyExtension(),
      ],
      { notBefore: new Date("1970-01-01"), notAfter: new Date("1970-01-02") },
    );
    expect(verify(input([leaf, ...rkp.slice(1)]))).toMatchObject({
      provisioning: "rkp",
    });
  });
  it("rejects a hardware security level inconsistent with the RKP issuer", async () => {
    const value = model();
    value.attestationLevel = 2;
    value.keyLevel = 2;
    const leaf = await certificate(
      "CN=Android Keystore Key",
      rkp[1]!,
      keys[3]!,
      keys[4]!,
      "204",
      [
        new KeyUsagesExtension(KeyUsageFlags.digitalSignature, true),
        keyExtension(encode(value)),
      ],
    );
    expect(() => verify(input([leaf, ...rkp.slice(1)]))).toThrow(
      expect.objectContaining({
        reason: "android_certificate_security_level_mismatch",
      }),
    );
  });
  it("rejects unexpected critical semantics, duplicate extensions, CA signing targets and non-P256 targets", async () => {
    const cases = [
      [
        new KeyUsagesExtension(KeyUsageFlags.digitalSignature, true),
        keyExtension(),
        new Extension("1.2.3.4", true, new Uint8Array([5, 0]).buffer),
      ],
      [
        new KeyUsagesExtension(KeyUsageFlags.digitalSignature, true),
        keyExtension(),
        keyExtension(),
      ],
      [
        new KeyUsagesExtension(
          KeyUsageFlags.digitalSignature | KeyUsageFlags.keyCertSign,
          true,
        ),
        keyExtension(),
      ],
      [
        new KeyUsagesExtension(KeyUsageFlags.digitalSignature, true),
        new BasicConstraintsExtension(true),
        keyExtension(),
      ],
      [keyExtension()],
      [new KeyUsagesExtension(KeyUsageFlags.digitalSignature, true)],
    ];
    for (const extensions of cases) {
      const leaf = await certificate(
        "CN=Android Keystore Key",
        factory[1]!,
        keys[2]!,
        keys[3]!,
        "103",
        extensions,
      );
      expect(() => verify(input([leaf, ...factory.slice(1)]))).toThrow();
    }
    const otherKey = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-384" },
      true,
      ["sign", "verify"],
    );
    const leaf = await certificate(
      "CN=Android Keystore Key",
      factory[1]!,
      keys[2]!,
      otherKey,
      "103",
      [
        new KeyUsagesExtension(KeyUsageFlags.digitalSignature, true),
        keyExtension(),
      ],
    );
    expect(() =>
      verifyAndroidCertificatePath(
        der([leaf, ...factory.slice(1)]),
        trust,
        time,
      ),
    ).toThrow(
      expect.objectContaining({ reason: "invalid_android_signing_key" }),
    );
  });

  it("enforces RKP CA constraints and path length", async () => {
    for (const extensions of [
      [
        new BasicConstraintsExtension(false),
        new KeyUsagesExtension(KeyUsageFlags.keyCertSign),
      ],
      [
        new BasicConstraintsExtension(true),
        new KeyUsagesExtension(KeyUsageFlags.digitalSignature),
      ],
      [
        new BasicConstraintsExtension(true, 0),
        new KeyUsagesExtension(KeyUsageFlags.keyCertSign),
      ],
    ]) {
      const server = await certificate(
        "O=Google LLC, CN=Droid CA3",
        rkp[3]!,
        keys[1]!,
        keys[2]!,
        "202",
        extensions,
      );
      expect(() =>
        verify(input([rkp[0]!, rkp[1]!, server, rkp[3]!, root])),
      ).toThrow(
        expect.objectContaining({ reason: "invalid_android_ca_constraints" }),
      );
    }
  });

  it("rejects cryptographically valid paths with weak issuer keys", async () => {
    const weak = await crypto.subtle.generateKey(
      {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 1024,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["sign", "verify"],
    );
    const server = await certificate(
      "O=Google LLC, CN=Droid CA3",
      rkp[3]!,
      keys[1]!,
      weak,
      "202",
      ca(),
    );
    const attestation = await certificate(
      "O=TEE, CN=Attestation",
      server,
      weak,
      keys[3]!,
      "203",
      ca(),
    );
    expect(() =>
      verify(input([rkp[0]!, attestation, server, rkp[3]!, root])),
    ).toThrow(expect.objectContaining({ reason: "weak_android_issuer_key" }));
  });

  it("rejects a provisioning marker on the wrong certificate", async () => {
    const leaf = await certificate(
      "CN=Android Keystore Key",
      rkp[1]!,
      keys[3]!,
      keys[4]!,
      "204",
      [
        new KeyUsagesExtension(KeyUsageFlags.digitalSignature, true),
        keyExtension(),
        new Extension(PROVISIONING, false, new Uint8Array([0xa0]).buffer),
      ],
    );
    expect(() => verify(input([leaf, ...rkp.slice(1)]))).toThrow(
      expect.objectContaining({
        reason: "android_provisioning_extension_position",
      }),
    );
  });

  it("rejects absent hardware issuer identity in RKP and inconsistent factory StrongBox claims", async () => {
    const attestation = await certificate(
      "CN=No hardware level",
      rkp[2]!,
      keys[2]!,
      keys[3]!,
      "203",
      ca(),
    );
    const leaf = await certificate(
      "CN=Android Keystore Key",
      attestation,
      keys[3]!,
      keys[4]!,
      "204",
      [
        new KeyUsagesExtension(KeyUsageFlags.digitalSignature, true),
        keyExtension(),
      ],
    );
    expect(() => verify(input([leaf, attestation, ...rkp.slice(2)]))).toThrow(
      expect.objectContaining({
        reason: "invalid_android_certificate_security_level",
      }),
    );
    const strong = await certificate(
      "CN=StrongBox attestation",
      factory[2]!,
      keys[1]!,
      keys[2]!,
      "102",
      ca(),
    );
    const target = await certificate(
      "CN=Android Keystore Key",
      strong,
      keys[2]!,
      keys[3]!,
      "103",
      [
        new KeyUsagesExtension(KeyUsageFlags.digitalSignature, true),
        keyExtension(),
      ],
    );
    expect(() => verify(input([target, strong, ...factory.slice(2)]))).toThrow(
      expect.objectContaining({
        reason: "android_certificate_security_level_mismatch",
      }),
    );
  });
});
