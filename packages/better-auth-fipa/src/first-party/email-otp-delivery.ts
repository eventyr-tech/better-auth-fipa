import type { GenericEndpointContext } from "@better-auth/core";
import { APIError } from "better-auth/api";
import { z } from "zod";
import { hmacSha256 } from "../protocol/crypto.js";
import { sendEmailOTP, type EmailOTPDelivery } from "./email-otp-method.js";
import { withFirstPartyTransaction } from "./transaction.js";
import { FIRST_PARTY_PROFILE } from "./wire.js";

export interface EmailDeliveryLimit {
  maxRequests: number;
  windowSeconds: number;
  minimumIntervalSeconds: number;
}
export interface EmailDeliveryPolicy {
  recipient: EmailDeliveryLimit;
  credential: EmailDeliveryLimit;
}
export interface EmailDeliveryConfiguration extends EmailDeliveryPolicy {
  /** Optional host-routed sender. Called only after durable admission/budgets. */
  delivery?: EmailOTPDelivery;
}
export type EmailDeliveryResult = {
  kind: "requested" | "rejected" | "unknown";
};

/** These values come from the reserved server step, never from a request body.
 * Reuse the same operation ID when retrying that step. A deliberate resend
 * needs a newly reserved operation and remains subject to both budgets.
 */
export interface EmailDeliveryOperation {
  profile: typeof FIRST_PARTY_PROFILE | "legacy-v1";
  operationId: string;
  providerCredentialId: string;
  expiresAt: Date;
  email: string;
}

interface Delivery {
  id: string;
  keyHash: string;
  bindingHash: string;
  outcome: "dispatching" | EmailDeliveryResult["kind"];
  expiresAt: Date;
}
interface Budget {
  id: string;
  keyHash: string;
  revision: number;
  requests: number;
  windowExpiresAt: Date;
  nextRequestAt: Date;
}

/** Shared internal coordinator, not an HTTP endpoint or an authentication
 * result. authorize must recheck and lock the admitted/reserved step and its
 * active credential in this transaction, including for duplicate requests.
 * It may be retried after DB contention and must have no external side effects.
 * DPoP verification/replay reservation belongs before this call, outside the
 * retried transaction. The caller must recheck authority before advancing an
 * authentication step after this returns.
 */
export async function requestEmailOTPDelivery(
  ctx: GenericEndpointContext,
  policy: EmailDeliveryConfiguration,
  input: EmailDeliveryOperation,
  authorize: (tx: GenericEndpointContext) => Promise<void>,
): Promise<EmailDeliveryResult> {
  validateEmailDeliveryPolicy(policy);
  const parsed = z
    .string()
    .trim()
    .toLowerCase()
    .pipe(z.email().max(320))
    .safeParse(input.email);
  if (!parsed.success) throw invalidRequest();
  if (
    ![FIRST_PARTY_PROFILE, "legacy-v1"].includes(input.profile) ||
    !input.operationId ||
    input.operationId.length > 256 ||
    !input.providerCredentialId ||
    input.providerCredentialId.length > 256 ||
    !Number.isFinite(input.expiresAt.getTime())
  )
    throw invalidRequest();
  const issuer = ctx.context.baseURL;
  const hash = (domain: string, ...values: string[]) =>
    hmacSha256(ctx.context.secret, JSON.stringify([domain, issuer, ...values]));
  const keyHash = hash(
    "first-party-email-operation",
    input.profile,
    input.operationId,
  );
  const bindingHash = hash(
    "first-party-email-binding",
    input.profile,
    input.operationId,
    input.providerCredentialId,
    input.expiresAt.toISOString(),
    parsed.data,
  );
  // Recipient limits span clients, credentials, sessions and protocol profiles.
  // Credential limits span recipient addresses, preventing email rotation from
  // giving one attested installation an unbounded delivery budget.
  const limits = [
    {
      keyHash: hash("first-party-email-recipient", parsed.data),
      limit: policy.recipient,
    },
    {
      keyHash: hash("first-party-email-credential", input.providerCredentialId),
      limit: policy.credential,
    },
  ].sort((a, b) => a.keyHash.localeCompare(b.keyHash));

  const claim = await retryContention(() =>
    withFirstPartyTransaction(ctx, async (tx) => {
      await authorize(tx);
      const now = new Date();
      if (input.expiresAt <= now) throw invalidRequest();
      const previous = await tx.context.adapter.findOne<Delivery>({
        model: "firstPartyEmailDelivery",
        where: [{ field: "keyHash", value: keyHash }],
      });
      if (previous) {
        if (previous.bindingHash !== bindingHash || previous.expiresAt <= now)
          throw invalidRequest();
        return {
          duplicate:
            previous.outcome === "dispatching"
              ? ("unknown" as const)
              : previous.outcome,
        };
      }
      // Claim this operation before reading its shared budgets. Under read
      // committed isolation another transaction can commit after our missing
      // ledger read. Its unique operation claim must trigger a whole-transaction
      // retry before its newly charged cooldown can be mistaken for a new send.
      // Budget failure rolls this insert back with both debits.
      const delivery = await tx.context.adapter.create<Delivery>({
        model: "firstPartyEmailDelivery",
        data: {
          keyHash,
          bindingHash,
          outcome: "dispatching",
          expiresAt: input.expiresAt,
        },
      });
      for (const { keyHash: budgetKey, limit } of limits)
        await debit(tx, budgetKey, limit, now);
      return { delivery };
    }),
  );
  if ("duplicate" in claim) return { kind: claim.duplicate };

  // This is deliberately outside the reservation transaction. Never redeliver
  // automatically after a timeout, process crash or uncertain commit. A stored
  // dispatching outcome is unknown on retry; no worker takes its lease over.
  const result = await sendEmailOTP(ctx, {
    email: parsed.data,
    ...(policy.delivery ? { delivery: policy.delivery } : {}),
  }).then(
    (value) => ({ ok: true as const, value }),
    (error: unknown) => ({ ok: false as const, error }),
  );
  const updated = await ctx.context.adapter.updateMany({
    model: "firstPartyEmailDelivery",
    where: [
      { field: "id", value: claim.delivery.id },
      { field: "outcome", value: "dispatching" },
    ],
    update: { outcome: result.ok ? result.value.kind : "unknown" },
  });
  if (updated !== 1) throw unavailable();
  if (!result.ok) throw result.error;
  return result.value;
}

export function validateEmailDeliveryPolicy(policy: EmailDeliveryPolicy): void {
  for (const limit of [policy.recipient, policy.credential]) {
    if (
      !Number.isSafeInteger(limit.maxRequests) ||
      limit.maxRequests < 1 ||
      limit.maxRequests > 1000 ||
      !Number.isSafeInteger(limit.windowSeconds) ||
      limit.windowSeconds < 1 ||
      limit.windowSeconds > 86400 ||
      !Number.isSafeInteger(limit.minimumIntervalSeconds) ||
      limit.minimumIntervalSeconds < 1 ||
      limit.minimumIntervalSeconds > limit.windowSeconds
    )
      throw new TypeError(
        "Email delivery requires explicit bounded request, window and resend limits.",
      );
  }
}

async function debit(
  ctx: GenericEndpointContext,
  keyHash: string,
  limit: EmailDeliveryLimit,
  now: Date,
) {
  const existing = await ctx.context.adapter.findOne<Budget>({
    model: "firstPartyEmailBudget",
    where: [{ field: "keyHash", value: keyHash }],
  });
  const reset = !existing || existing.windowExpiresAt <= now;
  const requests = reset ? 0 : existing.requests;
  // Changing the policy never replenishes a live window or clears cooldown.
  const retryAt = Math.max(
    existing?.nextRequestAt.getTime() ?? 0,
    requests >= limit.maxRequests ? existing!.windowExpiresAt.getTime() : 0,
  );
  if (retryAt > now.getTime())
    throw new APIError(
      "TOO_MANY_REQUESTS",
      { error: "slow_down" },
      {
        "retry-after": String(
          Math.max(1, Math.ceil((retryAt - now.getTime()) / 1000)),
        ),
      },
    );
  const data = {
    requests: requests + 1,
    revision: (existing?.revision ?? -1) + 1,
    windowExpiresAt: reset
      ? new Date(now.getTime() + limit.windowSeconds * 1000)
      : existing.windowExpiresAt,
    nextRequestAt: new Date(
      now.getTime() + limit.minimumIntervalSeconds * 1000,
    ),
  };
  if (!existing) {
    await ctx.context.adapter.create({
      model: "firstPartyEmailBudget",
      data: { keyHash, ...data },
    });
    return;
  }
  if (
    (await ctx.context.adapter.updateMany({
      model: "firstPartyEmailBudget",
      where: [
        { field: "id", value: existing.id },
        { field: "revision", value: existing.revision },
      ],
      update: data,
    })) !== 1
  )
    throw new Contention();
}

class Contention extends Error {}
async function retryContention<T>(operation: () => Promise<T>): Promise<T> {
  for (let attempt = 0; attempt < 4; attempt++) {
    try {
      return await operation();
    } catch (error) {
      // A simultaneous first insert can lose the unique index race. Retry the
      // whole rolled-back transaction, not individual writes in an aborted one.
      if (!(error instanceof Contention) && !uniqueConflict(error)) throw error;
    }
  }
  throw unavailable();
}
function uniqueConflict(error: unknown): boolean {
  if (!error || typeof error !== "object") return false;
  const code = "code" in error ? error.code : undefined;
  return (
    code === "23505" ||
    code === "SQLITE_CONSTRAINT_UNIQUE" ||
    // Node's built-in SQLite exposes the extended unique-constraint number.
    (code === "ERR_SQLITE_ERROR" &&
      "errcode" in error &&
      error.errcode === 2067) ||
    ("cause" in error && error.cause !== error && uniqueConflict(error.cause))
  );
}
function invalidRequest() {
  return new APIError("BAD_REQUEST", { error: "invalid_request" });
}
function unavailable() {
  return new APIError("INTERNAL_SERVER_ERROR", { error: "server_error" });
}
