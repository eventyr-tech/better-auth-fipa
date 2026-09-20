import type { GenericEndpointContext } from "@better-auth/core";
import { ANDROID_KEY_MODEL, ANDROID_PROVIDER } from "./provider-credential.js";
import {
  retireLogicalCredentialInTransaction,
  type LogicalCredential,
} from "./authorization-store.js";
import { withFirstPartyTransaction } from "./transaction.js";

const eraseEvidence = {
  publicKey: null,
  certificateChain: null,
  attestationChallenge: null,
  keyEvidence: null,
  unboundExpiresAt: null,
};

/** Only a verified provider rejection of an existing server-owned record calls
 * this. Fetch failures and caller-supplied evidence never retire other keys. */
export async function retireAndroidProviderCredential(
  ctx: GenericEndpointContext,
  keyId: string,
) {
  await withFirstPartyTransaction(ctx, async (tx) => {
    const logical = await lockLogical(tx, keyId);
    if (logical)
      await retireLogicalCredentialInTransaction(tx, logical.id, "provider");
    await tx.context.adapter.incrementOne({
      model: ANDROID_KEY_MODEL,
      where: [
        { field: "id", value: keyId },
        { field: "provider", value: ANDROID_PROVIDER },
        { field: "status", value: "active" },
      ],
      increment: { bindingVersion: 1 },
      set: {
        status: "revoked",
        revokedAt: new Date(),
        revocationReason: "provider",
      },
    });
    // Also erase a key already retired by the common routine, retaining its
    // immutable ownership and lookup tombstone. Repeated calls are idempotent.
    await tx.context.adapter.updateMany({
      model: ANDROID_KEY_MODEL,
      where: [
        { field: "id", value: keyId },
        { field: "provider", value: ANDROID_PROVIDER },
        { field: "status", value: "revoked" },
      ],
      update: { ...eraseEvidence, updatedAt: new Date() },
    });
  });
}

/** Bounded opportunistic maintenance on key preparation. Can also be invoked
 * by a trusted host job. Only never-bound expired records are purgeable. */
export async function maintainAndroidUnboundCredentials(
  ctx: GenericEndpointContext,
  scope: { clientId: string; applicationId: string; retentionSeconds: number },
  batchSize = 25,
) {
  if (
    !Number.isSafeInteger(batchSize) ||
    batchSize < 1 ||
    batchSize > 100 ||
    !Number.isSafeInteger(scope.retentionSeconds) ||
    scope.retentionSeconds < 1 ||
    scope.retentionSeconds > 30 * 86_400
  )
    throw new TypeError("Invalid Android credential maintenance bounds.");
  const now = new Date();
  const common = [
    { field: "provider", value: ANDROID_PROVIDER },
    { field: "clientId", value: scope.clientId },
    { field: "applicationId", value: scope.applicationId },
    { field: "userId", value: null },
    { field: "externallyBound", value: false },
  ];
  const expired = await ctx.context.adapter.findMany<{ id: string }>({
    model: ANDROID_KEY_MODEL,
    where: [
      ...common,
      { field: "status", value: "active" },
      { field: "unboundExpiresAt", operator: "lte", value: now },
    ],
    sortBy: { field: "id", direction: "asc" },
    limit: batchSize,
  });
  let expiredCount = 0;
  for (const key of expired) {
    const changed = await withFirstPartyTransaction(ctx, async (tx) => {
      // Match issuance's lock order. A claim that committed first must survive.
      const logical = await lockLogical(tx, key.id);
      const record = await tx.context.adapter.incrementOne({
        model: ANDROID_KEY_MODEL,
        where: [
          ...common,
          { field: "id", value: key.id },
          { field: "status", value: "active" },
          { field: "unboundExpiresAt", operator: "lte", value: now },
        ],
        increment: { bindingVersion: 1 },
        set: { ...eraseEvidence, status: "expired", updatedAt: now },
      });
      if (!record) return false;
      if (logical)
        await retireLogicalCredentialInTransaction(tx, logical.id, "provider");
      return true;
    });
    if (changed) expiredCount++;
  }
  const purgeWhere = [
    ...common,
    { field: "status", value: "expired" },
    {
      field: "updatedAt",
      operator: "lte" as const,
      value: new Date(now.getTime() - scope.retentionSeconds * 1000),
    },
  ];
  const purge = await ctx.context.adapter.findMany<{ id: string }>({
    model: ANDROID_KEY_MODEL,
    where: purgeWhere,
    sortBy: { field: "id", direction: "asc" },
    limit: batchSize,
  });
  const purgedCount = purge.length
    ? await ctx.context.adapter.deleteMany({
        model: ANDROID_KEY_MODEL,
        where: [
          ...purgeWhere,
          { field: "id", operator: "in", value: purge.map((key) => key.id) },
        ],
      })
    : 0;
  return { expired: expiredCount, purged: purgedCount };
}

async function lockLogical(ctx: GenericEndpointContext, keyId: string) {
  const logical = await ctx.context.adapter.findOne<LogicalCredential>({
    model: "firstPartyCredential",
    where: [
      { field: "provider", value: ANDROID_PROVIDER },
      { field: "providerCredentialId", value: keyId },
    ],
  });
  if (!logical) return null;
  return ctx.context.adapter.incrementOne<LogicalCredential>({
    model: "firstPartyCredential",
    where: [
      { field: "id", value: logical.id },
      { field: "provider", value: ANDROID_PROVIDER },
      { field: "providerCredentialId", value: keyId },
    ],
    increment: { revision: 1 },
  });
}
