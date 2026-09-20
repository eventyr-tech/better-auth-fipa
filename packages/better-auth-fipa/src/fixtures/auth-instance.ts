import { createHash, randomUUID } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { betterAuth, type Auth, type BetterAuthOptions } from "better-auth";
import {
  createAuthClient,
  type BetterAuthClientOptions,
} from "better-auth/client";
import { getMigrations } from "better-auth/db/migration";
import { bearer } from "better-auth/plugins";
import { Kysely, PostgresDialect, sql } from "kysely";
import { Pool } from "pg";
import { onTestFinished } from "vitest";

// Own each fixture's database lifetime. Better Auth's test helper retains all
// PostgreSQL schemas until afterAll, so migration introspection grows with every
// test and cleanup eventually exceeds the hook budget. Never share fixture data.
export async function getTestInstance<
  O extends Partial<BetterAuthOptions>,
  C extends BetterAuthClientOptions,
>(
  options: O,
  config: {
    testWith: "sqlite" | "postgres";
    transaction?: boolean;
    clientOptions?: C;
  },
) {
  let postgresPool: Pool | undefined;
  let postgresSchema: string | undefined;
  let database:
    | DatabaseSync
    | {
        db: Kysely<unknown>;
        type: "postgres";
        transaction: boolean | undefined;
      };
  if (config.testWith === "postgres") {
    const schema = `fipa_test_${randomUUID().replaceAll("-", "_")}`;
    postgresSchema = schema;
    const pool = new Pool({
      application_name: schema,
      connectionString:
        process.env.TEST_DATABASE_URL ??
        "postgres://user:password@127.0.0.1:5432/better_auth",
      options: `-c search_path=${schema},public`,
    });
    postgresPool = pool;
    const db = new Kysely({ dialect: new PostgresDialect({ pool }) });
    // Register before setup, so even a failed migration releases the database.
    onTestFinished(async () => {
      try {
        await sql.raw(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`).execute(db);
      } finally {
        await db.destroy();
      }
    });
    await sql.raw(`CREATE SCHEMA "${schema}"`).execute(db);
    database = { db, type: "postgres", transaction: config.transaction };
  } else {
    const db = new DatabaseSync(":memory:");
    onTestFinished(() => db.close());
    database = db;
  }
  const hash = (password: string) =>
    `$test$sha256$${createHash("sha256").update(password.normalize("NFKC")).digest("hex")}`;
  const authOptions = {
    baseURL: "http://localhost:3000",
    secret: "better-auth-secret-that-is-long-enough-for-validation-test",
    socialProviders: {
      github: { clientId: "test", clientSecret: "test" },
      google: { clientId: "test", clientSecret: "test" },
    },
    rateLimit: { enabled: false },
    advanced: { cookies: {} },
    logger: { level: "debug" },
    ...options,
    database,
    emailAndPassword: {
      enabled: true,
      ...options.emailAndPassword,
      password: options.emailAndPassword?.password ?? {
        hash: (password: string) => Promise.resolve(hash(password)),
        verify: (input: { hash: string; password: string }) =>
          Promise.resolve(input.hash === hash(input.password)),
      },
    },
    plugins: [bearer(), ...(options.plugins ?? [])],
  } satisfies BetterAuthOptions;
  const runtimeOptions: BetterAuthOptions = authOptions;
  if (process.env.TEST_ADAPTER === "drizzle") {
    const { createDrizzlePostgresFixture } =
      await import("./drizzle-postgres.js");
    if (!postgresPool || !postgresSchema)
      throw new Error("Drizzle contract requires PostgreSQL");
    runtimeOptions.database = await createDrizzlePostgresFixture(
      postgresPool,
      runtimeOptions,
      postgresSchema,
    );
  } else {
    await (await getMigrations(runtimeOptions)).runMigrations();
  }
  const auth = betterAuth(runtimeOptions);
  const testUser = {
    email: "test@test.com",
    password: "test123456",
    name: "test user",
  };
  await auth.api.signUpEmail({ body: testUser });
  const client = createAuthClient({
    ...(config.clientOptions as C),
    baseURL: "http://localhost:3000/api/auth",
    fetchOptions: {
      customFetchImpl: (url: string | URL | Request, init?: RequestInit) =>
        auth.handler(new Request(url, init)),
    },
  });
  return {
    postgres:
      postgresPool && postgresSchema
        ? { pool: postgresPool, schema: postgresSchema }
        : undefined,
    auth: auth as unknown as Auth<O>,
    client,
    testUser,
    signInWithTestUser: () => auth.api.signInEmail({ body: testUser }),
  };
}
