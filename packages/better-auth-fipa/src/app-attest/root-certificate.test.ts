import { X509Certificate } from "node:crypto";

import { describe, expect, it } from "vitest";

import { APPLE_APP_ATTESTATION_ROOT_CA_PEM } from "./root-certificate.js";

describe("Apple App Attestation trust anchor", () => {
  it("matches the intentionally pinned Apple root certificate", () => {
    const certificate = new X509Certificate(APPLE_APP_ATTESTATION_ROOT_CA_PEM);

    expect(certificate.fingerprint256).toBe(
      "1C:B9:82:3B:A2:8B:A6:AD:2D:33:A0:06:94:1D:E2:AE:4F:51:3E:F1:D4:E8:31:B9:F7:E0:FA:7B:62:42:C9:32",
    );
    expect(certificate.serialNumber).toBe("0BF3BE0EF1CDD2E0FB8C6E721F621798");
    expect(certificate.subject).toContain("CN=Apple App Attestation Root CA");
    expect(certificate.issuer).toBe(certificate.subject);
    expect(new Date(certificate.validFrom).toISOString()).toBe(
      "2020-03-18T18:32:53.000Z",
    );
    expect(new Date(certificate.validTo).toISOString()).toBe(
      "2045-03-15T00:00:00.000Z",
    );
  });
});
