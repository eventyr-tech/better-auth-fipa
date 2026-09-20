import {
  getCurrentAdapter,
  runWithTransaction,
} from "@better-auth/core/context";
import type { RuntimeContext } from "../credential-store.js";
import {
  retireLogicalCredentialInTransaction,
  type LogicalCredential,
} from "./authorization-store.js";
import { requireFirstPartyTransactions } from "./transaction.js";

/** Bridge existing public lifecycle operations to the same retirement primitive
 * used by the native endpoint. Lock logical credentials before provider keys. */
export async function retireFirstPartyForUser(
  context: RuntimeContext,
  userId: string,
): Promise<void> {
  requireFirstPartyTransactions(context.adapter);
  await runWithTransaction(context.adapter, async () => {
    const adapter = await getCurrentAdapter(context.adapter);
    const ids = new Set<string>();
    // Pending authorizations can precede the first committed user/key binding.
    for (const model of ["firstPartyCredential", "firstPartyAuthorization"]) {
      for (let offset = 0; ; offset += 100) {
        const rows = await adapter.findMany<{
          id: string;
          credentialId?: string;
        }>({
          model,
          where: [{ field: "userId", value: userId }],
          sortBy: { field: "id", direction: "asc" },
          limit: 100,
          offset,
        });
        for (const row of rows)
          ids.add(
            model === "firstPartyCredential" ? row.id : row.credentialId!,
          );
        if (rows.length < 100) break;
      }
    }
    for (const id of [...ids].sort()) {
      const credential = await adapter.findOne<LogicalCredential>({
        model: "firstPartyCredential",
        where: [{ field: "id", value: id }],
      });
      if (credential && (!credential.userId || credential.userId === userId))
        await retireLogicalCredentialInTransaction(
          {
            context: {
              ...context,
              adapter: { ...adapter, transaction: async (fn) => fn(adapter) },
            },
          },
          id,
          "user_deleted",
        );
    }
    // Preserve the low-level user-deletion contract after the shared primitive
    // has already changed these rows from active to revoked.
    if (
      context.options.plugins?.some(
        (plugin) => plugin.id === "device-attestation",
      )
    )
      await adapter.updateMany({
        model: "deviceAttestationCredential",
        where: [
          { field: "userId", value: userId },
          { field: "revocationReason", value: "user_deleted" },
        ],
        update: {
          publicKey: null,
          validationCategory: null,
          bundleVersion: null,
          unboundExpiresAt: null,
        },
      });
  });
}

export async function retireFirstPartyForProvider(
  context: RuntimeContext,
  providerCredentialId: string,
  userId: string,
): Promise<boolean> {
  requireFirstPartyTransactions(context.adapter);
  return runWithTransaction(context.adapter, async () => {
    const adapter = await getCurrentAdapter(context.adapter);
    const provider = await adapter.findOne<{ userId: string; status: string }>({
      model: "deviceAttestationCredential",
      where: [{ field: "id", value: providerCredentialId }],
    });
    if (provider?.userId !== userId || provider.status !== "active")
      return false;
    const logical = await adapter.findOne<LogicalCredential>({
      model: "firstPartyCredential",
      where: [{ field: "providerCredentialId", value: providerCredentialId }],
    });
    if (!logical) return false;
    await retireLogicalCredentialInTransaction(
      {
        context: {
          ...context,
          adapter: { ...adapter, transaction: async (fn) => fn(adapter) },
        },
      },
      logical.id,
    );
    await adapter.updateMany({
      model: "deviceAttestationCredential",
      where: [{ field: "id", value: providerCredentialId }],
      update: {
        publicKey: null,
        validationCategory: null,
        bundleVersion: null,
      },
    });
    return true;
  });
}
