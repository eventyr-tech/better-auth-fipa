import { describe, expect, it } from "vitest";
import { iosIdentitySchema } from "./ios-identity.ts";
import { androidIdentitySchema } from "./android-identity.ts";
import { assertRegistrationAdvance } from "./identity.ts";

const original = {
  version: 1 as const,
  dpopAlias: "existing-alias",
  dpopJkt: "a".repeat(43),
  providerKeyId: "existing-key",
  providerScope: "existing-scope",
  providerRegistration: "generated" as const,
};
const enrollment = {
  keyChallengeToken: "b".repeat(43),
  attestationChallenge: "c".repeat(43),
  issuedAt: "2026-09-20T00:00:00.000Z",
  expiresAt: "2026-09-20T00:02:00.000Z",
};
describe("provider-owned identity codecs", () => {
  it("reads existing v1 Apple and Android records without changing references or enrollment", () => {
    const apple = { ...original, providerStoragePrefix: "old-app-prefix" };
    const android = { ...original, androidEnrollment: enrollment };
    expect(iosIdentitySchema.parse(apple)).toEqual(apple);
    expect(androidIdentitySchema.parse(android)).toEqual(android);
    expect(iosIdentitySchema.parse(original)).toEqual(original);
  });
  it("rejects foreign provider state and unrecognized fields instead of silently dropping them", () => {
    expect(
      iosIdentitySchema.safeParse({
        ...original,
        androidEnrollment: enrollment,
      }).success,
    ).toBe(false);
    expect(
      androidIdentitySchema.safeParse({
        ...original,
        providerStoragePrefix: "apple",
      }).success,
    ).toBe(false);
    expect(
      androidIdentitySchema.safeParse({ ...original, enrollmentVersion: 99 })
        .success,
    ).toBe(false);
  });
  it("allows enrollment progress but never changes keys, enrollment challenges or lifecycle fences", () => {
    const before = androidIdentitySchema.parse({
      ...original,
      androidEnrollment: enrollment,
    });
    expect(() =>
      assertRegistrationAdvance(before, {
        ...before,
        providerRegistration: "attesting",
      }),
    ).not.toThrow();
    for (const change of [
      { dpopAlias: "replacement" },
      { account: { subject: "other", credentialId: "other" } },
      { retired: true as const },
      {
        androidEnrollment: { ...enrollment, keyChallengeToken: "d".repeat(43) },
      },
    ])
      expect(() =>
        assertRegistrationAdvance(before, { ...before, ...change }),
      ).toThrow();
    expect(() =>
      assertRegistrationAdvance(
        { ...before, providerRegistration: "registered" },
        before,
      ),
    ).toThrow();
  });
});
