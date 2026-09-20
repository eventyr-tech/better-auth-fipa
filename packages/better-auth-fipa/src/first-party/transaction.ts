import type { GenericEndpointContext } from "@better-auth/core";
import {
  getCurrentAdapter,
  runWithTransaction,
} from "@better-auth/core/context";

/** Better Auth's transaction method may silently execute without a transaction. */
export function requireFirstPartyTransactions(
  adapter: Pick<GenericEndpointContext["context"]["adapter"], "options">,
): void {
  if (typeof adapter.options?.adapterConfig.transaction !== "function") {
    throw new TypeError(
      "First-party authentication requires an adapter with database transactions enabled.",
    );
  }
}

/**
 * Bind provider and plugin writes to the same transaction without changing the
 * shared auth context. Release an issuance response only after this resolves.
 */
export async function withFirstPartyTransaction<T>(
  context: GenericEndpointContext,
  operation: (transactionContext: GenericEndpointContext) => Promise<T>,
): Promise<T> {
  requireFirstPartyTransactions(context.context.adapter);
  return runWithTransaction(context.context.adapter, async () => {
    const adapter = await getCurrentAdapter(context.context.adapter);
    return operation({
      ...context,
      context: {
        ...context.context,
        adapter: {
          ...adapter,
          // Already within a transaction: nested provider work must use it.
          transaction: async (fn) => fn(adapter),
        },
      },
    });
  });
}
