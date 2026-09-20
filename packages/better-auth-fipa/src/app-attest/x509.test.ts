import { readFile } from "node:fs/promises";

import cbor from "cbor";
import { beforeAll, describe, expect, it } from "vitest";

import { DeviceAttestationError } from "../errors.js";
import { verifyAppAttestCertificateChain } from "./x509.js";

let officialChain: Buffer[];

beforeAll(async () => {
  const encoded = Buffer.from(
    (
      await readFile(
        new URL("./fixtures/apple-attestation-object.base64", import.meta.url),
        "utf8",
      )
    ).trim(),
    "base64",
  );
  const decoded = (await cbor.decodeFirst(encoded)) as {
    attStmt: { x5c: Uint8Array[] };
  };
  officialChain = decoded.attStmt.x5c.map((value) => Buffer.from(value));
});

describe("App Attest certificate chain", () => {
  it("verifies the official chain at its documented validation time", async () => {
    const result = await verifyAppAttestCertificateChain(
      officialChain,
      "ios",
      new Date("2026-04-21T18:13:12.153Z"),
    );

    expect(result.publicKeyRaw).toHaveLength(65);
    expect(result.publicKeySpki).toHaveLength(91);
    expect(result.nonce).toHaveLength(32);
  });

  it("rejects an iOS ACL Blob under the macOS platform policy", async () => {
    await expectFailureReason(
      () =>
        verifyAppAttestCertificateChain(
          officialChain,
          "macos",
          new Date("2026-04-21T18:13:12.153Z"),
        ),
      "macos_acl_policy_mismatch",
    );
  });

  it.each([
    { chain: [Buffer.from("one")], reason: "invalid_certificate_chain_length" },
    {
      chain: Array.from({ length: 5 }, () => Buffer.from("certificate")),
      reason: "invalid_certificate_chain_length",
    },
    {
      chain: [Buffer.from("leaf"), Buffer.from("issuer")],
      reason: "invalid_certificate_encoding",
    },
  ])("rejects malformed chain input: $reason", async ({ chain, reason }) => {
    await expectFailureReason(
      () => verifyAppAttestCertificateChain(chain, "ios"),
      reason,
    );
  });

  it("rejects certificates outside their validity period", async () => {
    await expectFailureReason(
      () =>
        verifyAppAttestCertificateChain(
          officialChain,
          "ios",
          new Date("2050-01-01T00:00:00.000Z"),
        ),
      "certificate_outside_validity",
    );
  });

  it("rejects a chain whose leaf signature bytes were mutated", async () => {
    const mutatedLeaf = Buffer.from(officialChain[0] ?? Buffer.alloc(0));
    const signatureIndex = mutatedLeaf.length - 1;
    mutatedLeaf[signatureIndex] = (mutatedLeaf[signatureIndex] ?? 0) ^ 1;

    await expectFailureReason(
      () =>
        verifyAppAttestCertificateChain(
          [mutatedLeaf, ...(officialChain.slice(1) ?? [])],
          "ios",
          new Date("2026-04-21T18:13:12.153Z"),
        ),
      "invalid_certificate_signature",
    );
  });
});

async function expectFailureReason(
  operation: () => Promise<unknown>,
  reason: string,
): Promise<void> {
  try {
    await operation();
  } catch (error) {
    expect(error).toBeInstanceOf(DeviceAttestationError);
    expect(error).toMatchObject({ reason });
    return;
  }
  expect.fail("Expected certificate verification to fail.");
}
