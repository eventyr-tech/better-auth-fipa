import type { GenericEndpointContext } from "@better-auth/core";
import type { BetterAuthPlugin } from "better-auth";
import {
  APIError,
  createAuthEndpoint,
  createAuthMiddleware,
} from "better-auth/api";
import { emailOTP } from "better-auth/plugins";
import { getTestInstance } from "./fixtures/auth-instance.js";
import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { z } from "zod";
import {
  requestEmailOTPDelivery,
  type EmailDeliveryOperation,
  type EmailDeliveryPolicy,
} from "./first-party/email-otp-delivery.js";
import { firstPartyStateSchema } from "./first-party/state-schema.js";
import { FIRST_PARTY_PROFILE } from "./first-party/wire.js";
import { withFirstPartyTransaction } from "./first-party/transaction.js";

const policy: EmailDeliveryPolicy = {
  recipient: {
    maxRequests: 2,
    windowSeconds: 3600,
    minimumIntervalSeconds: 60,
  },
  credential: {
    maxRequests: 3,
    windowSeconds: 3600,
    minimumIntervalSeconds: 10,
  },
};

// Database contract fixture for the shared gate. Actual protocol admission and
// reserved-step checks belong to native/legacy coordinators; this fixture only
// supplies a server-side authority callback and does not claim attestation.
async function fixture(testWith: "sqlite" | "postgres") {
  const operations = new Map<
    string,
    (ctx: GenericEndpointContext) => Promise<unknown>
  >();
  const observed = {
    sent: [] as { email: string; otp: string }[],
    authorized: 0,
    writeAuthorization: false,
    denied: false,
    failAfterSend: false,
    reject: false,
    wait: undefined as Promise<void> | undefined,
    started: undefined as (() => void) | undefined,
  };
  const otp: BetterAuthPlugin = emailOTP({
    disableSignUp: false,
    storeOTP: "hashed",
    sendVerificationOTP: async (value) => {
      observed.sent.push(value);
      observed.started?.();
      if (observed.wait) await observed.wait;
    },
  });
  const { auth, testUser } = await getTestInstance(
    {
      plugins: [
        otp,
        {
          id: "email-delivery-test",
          schema: firstPartyStateSchema,
          hooks: {
            before: [
              {
                matcher: (ctx) =>
                  ctx.path === "/email-otp/send-verification-otp",
                handler: createAuthMiddleware(() => {
                  if (observed.reject)
                    throw new APIError("BAD_REQUEST", {
                      message: "host policy",
                    });
                  return Promise.resolve();
                }),
              },
            ],
            after: [
              {
                matcher: (ctx) =>
                  ctx.path === "/email-otp/send-verification-otp",
                handler: createAuthMiddleware(() => {
                  if (observed.failAfterSend)
                    throw new APIError("INTERNAL_SERVER_ERROR", {
                      message: "private sender failure",
                    });
                  return Promise.resolve();
                }),
              },
            ],
          },
          endpoints: {
            executeDelivery: createAuthEndpoint(
              "/test-only/delivery",
              {
                method: "POST",
                body: z.object({ id: z.string() }),
              },
              async (ctx) => {
                const operation = operations.get(ctx.body.id);
                if (!operation) throw new Error("Unknown fixture operation");
                return operation(ctx);
              },
            ),
          },
        },
      ],
    },
    { testWith, transaction: true },
  );
  const context = await auth.$context;
  const run = async <T>(
    operation: (ctx: GenericEndpointContext) => Promise<T>,
  ): Promise<T> => {
    const id = randomUUID();
    operations.set(id, operation);
    try {
      return (await auth.api.executeDelivery({ body: { id } })) as T;
    } finally {
      operations.delete(id);
    }
  };
  const input = (
    overrides: Partial<EmailDeliveryOperation> = {},
  ): EmailDeliveryOperation => ({
    profile: FIRST_PARTY_PROFILE,
    operationId: randomUUID(),
    providerCredentialId: "attested-installation-1",
    expiresAt: new Date(Date.now() + 600_000),
    email: testUser.email,
    ...overrides,
  });
  const authorize = async (tx: GenericEndpointContext) => {
    observed.authorized++;
    // A real write demonstrates that admission-related writes roll back with
    // budget/ledger failure, without changing a production authorization table.
    if (observed.writeAuthorization)
      await tx.context.adapter.updateMany({
        model: "user",
        where: [{ field: "email", value: testUser.email }],
        update: { name: "authorized delivery" },
      });
    if (observed.denied)
      throw new APIError("FORBIDDEN", { error: "invalid_session" });
  };
  const send = (value = input(), limits = policy) =>
    run((ctx) => requestEmailOTPDelivery(ctx, limits, value, authorize));
  const cooldown = () =>
    context.adapter.updateMany({
      model: "firstPartyEmailBudget",
      where: [],
      update: { nextRequestAt: new Date(0) },
    });
  const counts = async () => ({
    delivery: await context.adapter.count({ model: "firstPartyEmailDelivery" }),
    budget: await context.adapter.count({ model: "firstPartyEmailBudget" }),
  });
  return { context, testUser, observed, run, input, send, cooldown, counts };
}

for (const database of ["sqlite", "postgres"] as const) {
  describe.runIf(
    database === "sqlite"
      ? process.env.TEST_POSTGRES !== "true" &&
          Number(process.versions.node.split(".")[0]) >= 22
      : process.env.TEST_POSTGRES === "true",
  )(`First-party email delivery (${database})`, () => {
    it("deduplicates completed operations and stores only keyed recipient/operation hashes", async () => {
      const f = await fixture(database);
      const operation = f.input({
        email: `  ${f.testUser.email.toUpperCase()}  `,
      });
      expect(await f.send(operation)).toEqual({ kind: "requested" });
      expect(await f.send({ ...operation, email: f.testUser.email })).toEqual({
        kind: "requested",
      });
      expect(f.observed.sent).toHaveLength(1);
      expect(f.observed.authorized).toBe(2);
      expect(await f.counts()).toEqual({ delivery: 1, budget: 2 });
      const rows = [
        ...(await f.context.adapter.findMany<Record<string, unknown>>({
          model: "firstPartyEmailDelivery",
        })),
        ...(await f.context.adapter.findMany<Record<string, unknown>>({
          model: "firstPartyEmailBudget",
        })),
      ];
      const serialized = JSON.stringify(rows);
      for (const sensitive of [
        f.testUser.email,
        operation.operationId,
        operation.providerCredentialId,
      ])
        expect(serialized).not.toContain(sensitive);
      for (const row of rows)
        expect(Object.values(row)).not.toContain(f.observed.sent[0]!.otp);
    });
    it("requires current authority for initial and duplicate requests and rolls back failed admission", async () => {
      const f = await fixture(database);
      f.observed.writeAuthorization = true;
      const operation = f.input();
      f.observed.denied = true;
      await expect(f.send(operation)).rejects.toMatchObject({
        statusCode: 403,
      });
      expect(await f.counts()).toEqual({ delivery: 0, budget: 0 });
      expect(
        await f.context.adapter.findOne({
          model: "user",
          where: [{ field: "email", value: f.testUser.email }],
        }),
      ).toMatchObject({ name: f.testUser.name });
      f.observed.denied = false;
      await f.send(operation);
      f.observed.denied = true;
      await expect(f.send(operation)).rejects.toMatchObject({
        statusCode: 403,
      });
      expect(f.observed.sent).toHaveLength(1);
    });
    it("rejects expired operations and changed recipient or credential on the same operation", async () => {
      const f = await fixture(database);
      const operation = f.input();
      await f.send(operation);
      for (const change of [
        { email: "different@example.test" },
        { providerCredentialId: "another-installation" },
        { expiresAt: new Date(0) },
      ])
        await expect(f.send({ ...operation, ...change })).rejects.toMatchObject(
          { statusCode: 400 },
        );
      const expired = f.input({ expiresAt: new Date(0) });
      await expect(f.send(expired)).rejects.toMatchObject({ statusCode: 400 });
      expect(f.observed.sent).toHaveLength(1);
      expect(await f.counts()).toEqual({ delivery: 1, budget: 2 });
    });
    it("shares recipient cooldown and budget across installations, sessions and protocol profiles", async () => {
      const f = await fixture(database);
      await f.send();
      const legacy = f.input({
        profile: "legacy-v1",
        providerCredentialId: "legacy-installation",
      });
      await expect(f.send(legacy)).rejects.toMatchObject({
        statusCode: 429,
        headers: { "retry-after": expect.any(String) as unknown },
      });
      expect(await f.counts()).toEqual({ delivery: 1, budget: 2 });
      await f.cooldown();
      expect(await f.send(legacy)).toEqual({ kind: "requested" });
      await f.cooldown();
      await expect(
        f.send(f.input({ providerCredentialId: "third-installation" })),
      ).rejects.toMatchObject({ statusCode: 429 });
      expect(f.observed.sent).toHaveLength(2);
      expect(await f.counts()).toEqual({ delivery: 2, budget: 3 });
    });
    it("limits one credential across recipients and resets only after its window expires", async () => {
      const f = await fixture(database);
      for (let index = 0; index < 3; index++) {
        await f.cooldown();
        await f.send(f.input({ email: `recipient-${index}@example.test` }));
      }
      await f.cooldown();
      const operation = f.input({ email: "recipient-3@example.test" });
      await expect(f.send(operation)).rejects.toMatchObject({
        statusCode: 429,
      });
      expect(await f.counts()).toEqual({ delivery: 3, budget: 4 });
      await f.context.adapter.updateMany({
        model: "firstPartyEmailBudget",
        where: [],
        update: { windowExpiresAt: new Date(0) },
      });
      expect(await f.send(operation)).toEqual({ kind: "requested" });
      expect(f.observed.sent).toHaveLength(4);
    });
    it("does not reset live budgets when a caller changes limit configuration", async () => {
      const f = await fixture(database);
      await f.send();
      await f.cooldown();
      await expect(
        f.send(f.input(), {
          ...policy,
          recipient: {
            ...policy.recipient,
            maxRequests: 1,
            windowSeconds: 10,
            minimumIntervalSeconds: 1,
          },
        }),
      ).rejects.toMatchObject({ statusCode: 429 });
      expect(f.observed.sent).toHaveLength(1);
    });
    it("claims a simultaneous operation once without holding a transaction during delivery", async () => {
      const f = await fixture(database);
      const operation = f.input();
      let release!: () => void;
      f.observed.wait = new Promise<void>((resolve) => {
        release = resolve;
      });
      const started = new Promise<void>((resolve) => {
        f.observed.started = resolve;
      });
      const first = f.send(operation);
      try {
        await started;
        // Completes while sender is paused: reservation is committed and the
        // slow sender does not monopolize the transaction/SQLite connection.
        await f.run((ctx) =>
          withFirstPartyTransaction(ctx, async (tx) => {
            expect(
              await tx.context.adapter.count({
                model: "firstPartyEmailDelivery",
              }),
            ).toBe(1);
          }),
        );
        expect(await f.send(operation)).toEqual({ kind: "unknown" });
        expect(f.observed.sent).toHaveLength(1);
      } finally {
        release();
      }
      expect(await first).toEqual({ kind: "requested" });
      expect(await f.send(operation)).toEqual({ kind: "requested" });
    });
    it("enforces atomic recipient admission under competing new operations", async () => {
      const f = await fixture(database);
      const results = await Promise.allSettled(
        Array.from({ length: 6 }, (_, index) =>
          f.send(f.input({ providerCredentialId: `installation-${index}` })),
        ),
      );
      expect(
        results.filter((result) => result.status === "fulfilled"),
      ).toHaveLength(1);
      const errors = results.filter((result) => result.status === "rejected");
      for (const result of errors)
        expect(result.reason).toMatchObject({ statusCode: 429 });
      expect(f.observed.sent).toHaveLength(1);
      expect(await f.counts()).toEqual({ delivery: 1, budget: 2 });
    });
    it("deduplicates concurrent first submissions before any ledger row exists", async () => {
      const f = await fixture(database);
      const operation = f.input();
      const results = await Promise.all(
        Array.from({ length: 6 }, () => f.send(operation)),
      );
      expect(
        results.every(
          (result) => result.kind === "requested" || result.kind === "unknown",
        ),
      ).toBe(true);
      expect(f.observed.sent).toHaveLength(1);
      expect(await f.counts()).toEqual({ delivery: 1, budget: 2 });
      expect(await f.send(operation)).toEqual({ kind: "requested" });
    });
    it("deduplicates a stale missing-ledger read after the winner commits its budgets", async () => {
      const f = await fixture(database);
      const operation = f.input();
      expect(await f.send(operation)).toEqual({ kind: "requested" });
      const transaction = f.context.adapter.transaction;
      let stale = true;
      // Reproduce the read-committed interleaving deterministically: the loser
      // read no ledger, then the winner committed its ledger and budgets before
      // the loser's next SQL statement. Keep all writes/constraints real.
      f.context.adapter.transaction = (run) =>
        transaction((adapter) =>
          run({
            ...adapter,
            findOne: (input) => {
              if (stale && input.model === "firstPartyEmailDelivery") {
                stale = false;
                return Promise.resolve(null);
              }
              return adapter.findOne(input);
            },
          }),
        );
      try {
        expect(await f.send(operation)).toEqual({ kind: "requested" });
        expect(f.observed.sent).toHaveLength(1);
        expect(await f.counts()).toEqual({ delivery: 1, budget: 2 });
        expect(
          await f.context.adapter.findMany({ model: "firstPartyEmailBudget" }),
        ).toMatchObject([{ requests: 1 }, { requests: 1 }]);
      } finally {
        f.context.adapter.transaction = transaction;
      }
    });
    it("keeps uncertain dispatches charged and never repeats them automatically", async () => {
      const f = await fixture(database);
      const operation = f.input();
      f.observed.failAfterSend = true;
      await expect(f.send(operation)).rejects.toMatchObject({
        statusCode: 500,
      });
      f.observed.failAfterSend = false;
      expect(await f.send(operation)).toEqual({ kind: "unknown" });
      expect(f.observed.sent).toHaveLength(1);
      await expect(f.send()).rejects.toMatchObject({ statusCode: 429 });
      await f.cooldown();
      expect(await f.send()).toEqual({ kind: "requested" });
      expect(f.observed.sent).toHaveLength(2);
    });
    it("persists host rejection and does not retry it with a duplicate operation", async () => {
      const f = await fixture(database);
      const operation = f.input();
      f.observed.reject = true;
      expect(await f.send(operation)).toEqual({ kind: "rejected" });
      f.observed.reject = false;
      expect(await f.send(operation)).toEqual({ kind: "rejected" });
      expect(f.observed.sent).toHaveLength(0);
      await expect(f.send()).rejects.toMatchObject({ statusCode: 429 });
    });
    it.each(["ledger", "second-budget"])(
      "rolls back admission, ledger and budgets after %s persistence fails",
      async (failure) => {
        const f = await fixture(database);
        f.observed.writeAuthorization = true;
        const transaction = f.context.adapter.transaction;
        let budgetWrites = 0;
        f.context.adapter.transaction = (operation) =>
          transaction((tx) =>
            operation({
              ...tx,
              create: async (args) => {
                if (
                  (failure === "ledger" &&
                    args.model === "firstPartyEmailDelivery") ||
                  (failure === "second-budget" &&
                    args.model === "firstPartyEmailBudget" &&
                    ++budgetWrites === 2)
                )
                  throw new Error("injected persistence failure");
                return tx.create(args);
              },
            }),
          );
        try {
          await expect(f.send()).rejects.toThrow(
            "injected persistence failure",
          );
        } finally {
          f.context.adapter.transaction = transaction;
        }
        expect(await f.counts()).toEqual({ delivery: 0, budget: 0 });
        expect(f.observed.sent).toHaveLength(0);
        expect(
          await f.context.adapter.findOne({
            model: "user",
            where: [{ field: "email", value: f.testUser.email }],
          }),
        ).toMatchObject({ name: f.testUser.name });
        expect(await f.send()).toEqual({ kind: "requested" });
      },
    );
    it("does not repeat a dispatch after failure to persist its outcome", async () => {
      const f = await fixture(database);
      const operation = f.input();
      const updateMany = f.context.adapter.updateMany;
      f.context.adapter.updateMany = (args) => {
        if (args.model === "firstPartyEmailDelivery")
          return Promise.reject(new Error("injected outcome failure"));
        return updateMany(args);
      };
      try {
        await expect(f.send(operation)).rejects.toThrow(
          "injected outcome failure",
        );
      } finally {
        f.context.adapter.updateMany = updateMany;
      }
      expect(await f.send(operation)).toEqual({ kind: "unknown" });
      expect(f.observed.sent).toHaveLength(1);
    });
  });
}
