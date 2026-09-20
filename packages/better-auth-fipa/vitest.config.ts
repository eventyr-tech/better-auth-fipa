import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // PostgreSQL schema inspection and per-file teardown must not overlap.
    ...(process.env.TEST_POSTGRES === "true"
      ? {
          fileParallelism: false,
          // Includes per-test schema migration and >100 serial proof-bound
          // issuances in the pagination test. Five seconds is not a throughput
          // requirement and intermittently expires under Node 20 + coverage.
          testTimeout: 30_000,
        }
      : {}),
    coverage: {
      provider: "v8",
      include: ["src/**/*.ts"],
      exclude: [
        "src/**/*.test.ts",
        "src/**/fixtures/**",
        "src/app-attest/root-certificate.ts",
        "src/index.ts",
      ],
      reporter: ["text", "json-summary"],
      reportsDirectory: "coverage",
      thresholds: {
        statements: 85,
        branches: 75,
        functions: 90,
        lines: 85,
      },
    },
  },
});
