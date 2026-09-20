import { defineConfig, mergeConfig } from "vitest/config";
import postgres from "./vitest.config.postgres.js";

export default mergeConfig(
  postgres,
  defineConfig({
    test: { env: { TEST_ADAPTER: "drizzle" } },
  }),
);
