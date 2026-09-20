import type { BetterAuthPlugin } from "better-auth";

export const deviceAttestationSchema = {
  deviceAttestationCredential: {
    fields: {
      lookupKey: {
        type: "string",
        required: true,
        unique: true,
        input: false,
        returned: false,
      },
      provider: {
        type: "string",
        required: true,
        index: true,
        input: false,
      },
      applicationId: {
        type: "string",
        required: true,
        index: true,
        input: false,
      },
      environment: {
        type: ["development", "production"],
        required: true,
        input: false,
      },
      publicKey: {
        type: "string",
        required: false,
        input: false,
        returned: false,
      },
      counter: {
        type: "number",
        bigint: true,
        required: true,
        input: false,
        returned: false,
      },
      userId: {
        type: "string",
        required: false,
        input: false,
        returned: false,
        references: {
          model: "user",
          field: "id",
          onDelete: "set null",
        },
        index: true,
      },
      externallyBound: {
        type: "boolean",
        required: true,
        defaultValue: false,
        input: false,
        returned: false,
      },
      bindingVersion: {
        type: "number",
        required: true,
        defaultValue: 0,
        input: false,
        returned: false,
      },
      status: {
        type: ["active", "expired", "revoked"],
        required: true,
        defaultValue: "active",
        input: false,
      },
      validationCategory: {
        type: "number",
        bigint: true,
        required: false,
        input: false,
        returned: false,
      },
      bundleVersion: {
        type: "string",
        required: false,
        input: false,
        returned: false,
      },
      extensionsPresent: {
        type: "boolean",
        required: true,
        input: false,
        returned: false,
      },
      createdAt: {
        type: "date",
        required: true,
        defaultValue: () => new Date(),
        input: false,
      },
      updatedAt: {
        type: "date",
        required: true,
        defaultValue: () => new Date(),
        onUpdate: () => new Date(),
        input: false,
      },
      boundAt: {
        type: "date",
        required: false,
        input: false,
      },
      unboundExpiresAt: {
        type: "date",
        required: false,
        input: false,
        returned: false,
      },
      revokedAt: {
        type: "date",
        required: false,
        input: false,
      },
      revocationReason: {
        type: ["user", "user_deleted", "counter_exhausted", "provider"],
        required: false,
        input: false,
        returned: false,
      },
      lastUsedAt: {
        type: "date",
        required: false,
        input: false,
      },
    },
  },
} as const satisfies NonNullable<BetterAuthPlugin["schema"]>;
