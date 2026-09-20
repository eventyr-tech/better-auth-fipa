import { describe, expect, it } from "vitest";

import { MAX_APPLICATION_ID_LENGTH } from "./limits.js";
import { challengeBodySchema } from "./plugin-schemas.js";
import { deviceAttestationSchema } from "./schema.js";

describe("device attestation schema contract", () => {
  it("stores all UInt32 values without exposing sensitive fields", () => {
    const fields = deviceAttestationSchema.deviceAttestationCredential.fields;

    expect(fields.counter).toMatchObject({
      type: "number",
      bigint: true,
      input: false,
      returned: false,
    });
    expect(fields.validationCategory).toMatchObject({
      type: "number",
      bigint: true,
      input: false,
      returned: false,
    });
    expect(fields.publicKey.returned).toBe(false);
    expect(fields.lookupKey.returned).toBe(false);
    expect(fields.userId.returned).toBe(false);
  });

  it("keeps indexed application IDs within the portable schema bound", () => {
    const request = {
      provider: "test",
      applicationId: "a".repeat(MAX_APPLICATION_ID_LENGTH),
      operation: "register",
      keyId: "key",
      purpose: "credential-registration",
    } as const;

    expect(challengeBodySchema.safeParse(request).success).toBe(true);
    expect(
      challengeBodySchema.safeParse({
        ...request,
        applicationId: `${request.applicationId}a`,
      }).success,
    ).toBe(false);
  });
});
