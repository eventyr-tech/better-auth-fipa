import { generateDrizzleSchema } from "auth/api";
import type { BetterAuthOptions } from "better-auth";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import { generateDrizzleJson, generateMigration } from "drizzle-kit/api";
import { drizzle } from "drizzle-orm/node-postgres";
import { pgSchema } from "drizzle-orm/pg-core";
import { mkdir, writeFile } from "node:fs/promises";
import type { Pool } from "pg";
import { ModuleKind, transpileModule } from "typescript";

/** Use the public auth CLI generator and Drizzle migration engine, not a
 * handwritten approximation of the plugin schema. Plural model exports and
 * snake_case SQL columns match Eventyr's adapter conventions. */
export async function createDrizzlePostgresFixture(
  pool: Pool,
  options: BetterAuthOptions,
  schemaName: string,
) {
  const adapterOptions = {
    provider: "pg" as const,
    usePlural: true,
    transaction: true,
    schemaName,
  };
  const generationAdapter = drizzleAdapter(
    drizzle(pool),
    adapterOptions,
  )(options);
  const generated = await generateDrizzleSchema({
    options,
    adapter: generationAdapter,
    file: "schema.ts",
  });
  const code = generated.code;
  if (generated.unsafeChanges?.length || generated.schemaProblems?.length) {
    throw new Error(
      "Auth CLI reported an unsafe or incompatible consumer schema",
    );
  }
  if (!code) throw new Error("Auth CLI did not generate a Drizzle schema");
  const directory = new URL("../../.artifacts/drizzle/", import.meta.url);
  await mkdir(directory, { recursive: true });
  const path = new URL(`${schemaName}.mjs`, directory);
  await writeFile(
    path,
    transpileModule(code, {
      compilerOptions: { module: ModuleKind.ESNext },
    }).outputText,
  );
  const schema = (await import(/* @vite-ignore */ path.href)) as Record<
    string,
    unknown
  >;
  const statements = await generateMigration(
    generateDrizzleJson({ namespace: pgSchema(schemaName) }),
    generateDrizzleJson(schema),
  );
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    for (const statement of statements) await client.query(statement);
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
  // Eventyr supplies schema to the adapter, not to the Drizzle instance.
  return drizzleAdapter(drizzle(pool), {
    ...adapterOptions,
    schema,
  });
}
