import { describe, expect, it } from "vitest";
import { readFile } from "node:fs/promises";
import { parseAndroidKeyDescription } from "./key-description.js";
import { createAndroidKeyPolicy } from "./key-policy.js";

import {
  challenge,
  signer,
  secondSigner,
  policy,
  der,
  sequence,
  set,
  octets,
  number,
  application,
  boot,
  model,
  encode,
  type Model,
} from "./fixtures/key-description.fixture.js";

const verify = createAndroidKeyPolicy(policy);

describe("Android KeyDescription and hardware policy", () => {
  it.each([
    ["akita", 300, 300, 1],
    ["frankel", 500, 500, 1],
    ["blueline", 3, 4, 2],
  ] as const)(
    "parses the published %s reference extension without accepting it as current evidence",
    async (name, attestationVersion, keymasterVersion, level) => {
      const encoded = await readFile(
        new URL(`./fixtures/${name}-key-description.base64`, import.meta.url),
        "utf8",
      );
      const bytes = Buffer.from(encoded.trim(), "base64");
      expect(parseAndroidKeyDescription(bytes)).toMatchObject({
        attestationVersion,
        keymasterVersion,
        keymasterSecurityLevel: level,
      });
      expect(() => verify(bytes, challenge)).toThrow();
    },
  );
  it("parses a KeyMint description and preserves enforcement locations and creation-time claims", () => {
    const result = verify(encode(), challenge);
    expect(result).toEqual({
      policyVersion: policy.policyVersion,
      attestationVersion: 300,
      keymasterVersion: 300,
      attestationSecurityLevel: "tee",
      keySecurityLevel: "tee",
      algorithm: "ES256",
      origin: "generated",
      packageName: policy.packageName,
      versionCodeAtCreation: "42",
      signingCertificateDigestsAtCreation: [signer.toString("base64url")],
      osVersionAtCreation: 150000,
      osPatchLevelAtCreation: 202609,
      vendorPatchLevelAtCreation: 20260905,
      bootPatchLevelAtCreation: 20260905,
      bootStateAtCreation: "verified-locked",
      unlockedDeviceRequired: "software",
    });
    expect(result).not.toHaveProperty("publicKey");
    expect(result).not.toHaveProperty("uniqueId");
  });

  it.each([
    [2, 3],
    [3, 4],
    [4, 41],
    [100, 100],
    [200, 200],
    [300, 300],
    [400, 400],
    [500, 500],
  ])(
    "accepts reviewed attestation/Keymaster version pair %i/%i",
    (version, keymaster) => {
      const value = model();
      value.version = version;
      value.keymaster = keymaster;
      expect(verify(encode(value), challenge).attestationVersion).toBe(version);
    },
  );
  it("accepts StrongBox only when both security levels satisfy policy", () => {
    const strong = createAndroidKeyPolicy({
      ...policy,
      allowedSecurityLevels: ["strongbox"],
    });
    expect(() => strong(encode(), challenge)).toThrow();
    const value = model();
    value.keyLevel = 2;
    expect(() => strong(encode(value), challenge)).toThrow();
    value.attestationLevel = 2;
    expect(strong(encode(value), challenge)).toMatchObject({
      keySecurityLevel: "strongbox",
      attestationSecurityLevel: "strongbox",
    });
  });

  it.each([
    [
      "software attestation",
      (v: Model) => {
        v.attestationLevel = 0;
      },
    ],
    [
      "software key",
      (v: Model) => {
        v.keyLevel = 0;
      },
    ],
    [
      "unknown security level",
      (v: Model) => {
        v.keyLevel = 3;
      },
    ],
    [
      "unknown version",
      (v: Model) => {
        v.version = 600;
        v.keymaster = 600;
      },
    ],
    [
      "mismatched version",
      (v: Model) => {
        v.keymaster = 4;
      },
    ],
    [
      "version without app identity",
      (v: Model) => {
        v.version = 1;
        v.keymaster = 2;
      },
    ],
    [
      "different challenge",
      (v: Model) => {
        v.challenge = Buffer.alloc(32, 1);
      },
    ],
    [
      "short challenge",
      (v: Model) => {
        v.challenge = Buffer.alloc(31);
      },
    ],
    [
      "device unique identifier",
      (v: Model) => {
        v.uniqueId = Buffer.from("device-id");
      },
    ],
    [
      "unique attestation",
      (v: Model) => {
        v.hardware.set(720, der(5, Buffer.alloc(0)));
      },
    ],
    [
      "all applications",
      (v: Model) => {
        v.software.set(600, der(5, Buffer.alloc(0)));
      },
    ],
    [
      "software algorithm",
      (v: Model) => {
        v.hardware.delete(2);
        v.software.set(2, number(3));
      },
    ],
    [
      "RSA",
      (v: Model) => {
        v.hardware.set(2, number(1));
      },
    ],
    [
      "wrong curve",
      (v: Model) => {
        v.hardware.set(10, number(2));
      },
    ],
    [
      "wrong key size",
      (v: Model) => {
        v.hardware.set(3, number(384));
      },
    ],
    [
      "imported key",
      (v: Model) => {
        v.hardware.set(702, number(2));
      },
    ],
    [
      "attestation signing key",
      (v: Model) => {
        v.hardware.set(1, set(number(7)));
      },
    ],
    [
      "encryption capability",
      (v: Model) => {
        v.hardware.set(1, set(number(0), number(2)));
      },
    ],
    [
      "weak digest",
      (v: Model) => {
        v.hardware.set(5, set(number(2)));
      },
    ],
    [
      "unhashed signing",
      (v: Model) => {
        v.hardware.set(5, set(number(0), number(4)));
      },
    ],
    [
      "missing boot state",
      (v: Model) => {
        v.hardware.delete(704);
      },
    ],
    [
      "software boot state",
      (v: Model) => {
        v.hardware.delete(704);
        v.software.set(704, boot());
      },
    ],
    [
      "unlocked bootloader",
      (v: Model) => {
        v.hardware.set(704, boot(false));
      },
    ],
    [
      "self-signed boot",
      (v: Model) => {
        v.hardware.set(704, boot(true, 1));
      },
    ],
    [
      "zero boot hash",
      (v: Model) => {
        v.hardware.set(704, boot(true, 0, Buffer.alloc(32)));
      },
    ],
    [
      "missing app identity",
      (v: Model) => {
        v.software.delete(709);
      },
    ],
    [
      "wrong package",
      (v: Model) => {
        v.software.set(
          709,
          application([{ name: "io.attacker.app", version: 42n }]),
        );
      },
    ],
    [
      "shared UID",
      (v: Model) => {
        v.software.set(
          709,
          application([
            { name: policy.packageName, version: 42n },
            { name: "io.other.app", version: 42n },
          ]),
        );
      },
    ],
    [
      "old app version",
      (v: Model) => {
        v.software.set(
          709,
          application([{ name: policy.packageName, version: 41n }]),
        );
      },
    ],
    [
      "wrong signer",
      (v: Model) => {
        v.software.set(709, application(undefined, [secondSigner]));
      },
    ],
    [
      "extra signer",
      (v: Model) => {
        v.software.set(709, application(undefined, [signer, secondSigner]));
      },
    ],
    [
      "old OS",
      (v: Model) => {
        v.hardware.set(705, number(120000));
      },
    ],
    [
      "missing OS",
      (v: Model) => {
        v.hardware.delete(705);
      },
    ],
    [
      "missing OS patch",
      (v: Model) => {
        v.hardware.delete(706);
      },
    ],
    [
      "old OS patch",
      (v: Model) => {
        v.hardware.set(706, number(202512));
      },
    ],
    [
      "invalid patch month",
      (v: Model) => {
        v.hardware.set(706, number(202613));
      },
    ],
    [
      "missing vendor patch",
      (v: Model) => {
        v.hardware.delete(718);
      },
    ],
    [
      "old vendor patch",
      (v: Model) => {
        v.hardware.set(718, number(20251231));
      },
    ],
    [
      "invalid vendor patch day",
      (v: Model) => {
        v.hardware.set(718, number(20260230));
      },
    ],
    [
      "missing boot patch",
      (v: Model) => {
        v.hardware.delete(719);
      },
    ],
    [
      "old boot patch",
      (v: Model) => {
        v.hardware.set(719, number(20251231));
      },
    ],
    [
      "invalid boot patch day",
      (v: Model) => {
        v.hardware.set(719, number(20260931));
      },
    ],
    [
      "no unlock restriction",
      (v: Model) => {
        v.software.delete(509);
      },
    ],
  ])("rejects %s", (_name, mutate) => {
    const value = model();
    mutate(value);
    expect(() => verify(encode(value), challenge)).toThrow(
      expect.objectContaining({ reason: "android_key_policy_rejected" }),
    );
  });

  it("keeps large version integers exact and accepts only complete configured signer sets", () => {
    const value = model();
    value.software.set(
      709,
      application(
        [{ name: policy.packageName, version: 9007199254740993n }],
        [signer, secondSigner],
      ),
    );
    const allowed = createAndroidKeyPolicy({
      ...policy,
      minimumVersionCode: "9007199254740993",
      signingCertificateSets: [
        [secondSigner.toString("base64url"), signer.toString("base64url")],
      ],
    });
    expect(allowed(encode(value), challenge).versionCodeAtCreation).toBe(
      "9007199254740993",
    );
  });

  it("reports hardware unlock enforcement without treating an absent flag as attested", () => {
    const value = model();
    value.software.delete(509);
    value.hardware.set(509, der(5, Buffer.alloc(0)));
    expect(verify(encode(value), challenge).unlockedDeviceRequired).toBe(
      "hardware",
    );
    value.hardware.delete(509);
    value.hardware.delete(718);
    value.hardware.delete(719);
    const lessRestrictive = { ...policy };
    delete lessRestrictive.minimumBootPatchLevel;
    delete lessRestrictive.minimumVendorPatchLevel;
    const check = createAndroidKeyPolicy({
      ...lessRestrictive,
      requireUnlockedDevice: false,
    });
    expect(check(encode(value), challenge)).toMatchObject({
      unlockedDeviceRequired: "not-attested",
    });
  });

  it.each([
    [
      "duplicate authorization across lists",
      (v: Model) => {
        v.software.set(2, number(3));
      },
    ],
    [
      "unknown authorization",
      (v: Model) => {
        v.hardware.set(999, number(1));
      },
    ],
    [
      "negative integer",
      (v: Model) => {
        v.hardware.set(3, der(2, Buffer.from([255])));
      },
    ],
    [
      "redundant integer zero",
      (v: Model) => {
        v.hardware.set(3, der(2, Buffer.from([0, 1])));
      },
    ],
    [
      "missing integer bytes",
      (v: Model) => {
        v.hardware.set(3, der(2, Buffer.alloc(0)));
      },
    ],
    [
      "oversized integer",
      (v: Model) => {
        v.hardware.set(3, number(1n << 65n));
      },
    ],
    [
      "wrong integer type",
      (v: Model) => {
        v.hardware.set(3, number(256, 10));
      },
    ],
    [
      "primitive sequence",
      (v: Model) => {
        v.hardware.set(704, der(0x10, Buffer.alloc(0)));
      },
    ],
    [
      "noncanonical boolean",
      (v: Model) => {
        v.hardware.set(
          704,
          sequence(
            octets(Buffer.alloc(32)),
            der(1, Buffer.from([1])),
            number(0, 10),
          ),
        );
      },
    ],
    [
      "nonempty null",
      (v: Model) => {
        v.hardware.set(503, der(5, Buffer.from([0])));
      },
    ],
    [
      "multiple explicit values",
      (v: Model) => {
        v.hardware.set(3, Buffer.concat([number(256), number(256)]));
      },
    ],
    [
      "empty set",
      (v: Model) => {
        v.hardware.set(1, set());
      },
    ],
    [
      "unsorted set",
      (v: Model) => {
        v.hardware.set(1, der(0x31, Buffer.concat([number(3), number(2)])));
      },
    ],
    [
      "duplicate purpose",
      (v: Model) => {
        v.hardware.set(1, set(number(2), number(2)));
      },
    ],
    [
      "bad signer size",
      (v: Model) => {
        v.software.set(709, application(undefined, [Buffer.alloc(31)]));
      },
    ],
    [
      "duplicate signer",
      (v: Model) => {
        v.software.set(709, application(undefined, [signer, signer]));
      },
    ],
    [
      "duplicate package",
      (v: Model) => {
        v.software.set(
          709,
          application([
            { name: policy.packageName, version: 42n },
            { name: policy.packageName, version: 43n },
          ]),
        );
      },
    ],
    [
      "non-ASCII package",
      (v: Model) => {
        v.software.set(
          709,
          application([{ name: "io.exämple.app", version: 42n }]),
        );
      },
    ],
  ])("rejects DER with %s", (_name, mutate) => {
    const value = model();
    mutate(value);
    expect(() => parseAndroidKeyDescription(encode(value))).toThrow(
      expect.objectContaining({ reason: "invalid_android_key_description" }),
    );
  });

  it("rejects truncation at every byte boundary, trailing bytes and unbounded structures", () => {
    const bytes = encode();
    for (let end = 0; end < bytes.length; end++)
      expect(() =>
        parseAndroidKeyDescription(bytes.subarray(0, end)),
      ).toThrow();
    for (const invalid of [
      Buffer.concat([bytes, Buffer.from([0])]),
      Buffer.alloc(16385),
      Buffer.from([0x30, 0x80, 0, 0]),
      Buffer.from([0x30, 0x81, 0]),
      Buffer.from([0x30, 0x82, 0, 128]),
      Buffer.from([0x3f, 0x10, 0]),
      Buffer.from([0x3f, 0x80, 0x10, 0]),
    ])
      expect(() => parseAndroidKeyDescription(invalid)).toThrow();
    let nested = der(5, Buffer.alloc(0));
    for (let i = 0; i < 10; i++) nested = sequence(nested);
    expect(() => parseAndroidKeyDescription(nested)).toThrow();
    expect(() =>
      parseAndroidKeyDescription(
        sequence(...Array.from({ length: 513 }, () => der(5, Buffer.alloc(0)))),
      ),
    ).toThrow();
  });

  it("requires reviewed bounded policy and protects it from later mutation", () => {
    for (const change of [
      { minimumOsPatchLevel: 202613 },
      { minimumBootPatchLevel: 20260230 },
      { signingCertificateSets: [] },
      { allowedSecurityLevels: [] },
      { minimumVersionCode: "-1" },
      { packageName: "io/attacker" },
    ])
      expect(() => createAndroidKeyPolicy({ ...policy, ...change })).toThrow(
        TypeError,
      );
    const config = structuredClone(policy);
    const check = createAndroidKeyPolicy(config);
    config.minimumOsVersion = 1;
    config.signingCertificateSets.push([secondSigner.toString("base64url")]);
    const value = model();
    value.software.set(709, application(undefined, [secondSigner]));
    expect(() => check(encode(value), challenge)).toThrow();
    expect(() => verify(encode(), Buffer.alloc(31))).toThrow();
  });
});
