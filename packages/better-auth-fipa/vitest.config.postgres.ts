import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Better Auth's schema check introspects every schema. Another test file's
    // DROP SCHEMA can race has_schema_privilege(name) during that inspection.
    // Keep files sequential while retaining the explicit concurrent DB tests.
    fileParallelism: false,
    // Match the PostgreSQL budget in the default coverage configuration:
    // schema migrations and the 101-family case retain their complete workload.
    testTimeout: 30_000,
    include: [
      "src/adapter.integration.test.ts",
      "src/consumer-compatibility.integration.test.ts",
      "src/first-party-feasibility.integration.test.ts",
      "src/first-party-state.integration.test.ts",
      "src/first-party-admission.integration.test.ts",
      "src/first-party-android.integration.test.ts",
      "src/first-party-methods.integration.test.ts",
      "src/first-party-email-delivery.integration.test.ts",
      "src/first-party-continuation.integration.test.ts",
      "src/first-party-legacy.integration.test.ts",
    ],
    env: {
      TEST_POSTGRES: "true",
    },
  },
});
