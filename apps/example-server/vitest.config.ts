import { defineConfig } from "vitest/config";
export default defineConfig({
  test: {
    coverage: {
      provider: "v8",
      include: ["src/app.ts"],
      reporter: ["text", "json-summary"],
    },
  },
});
