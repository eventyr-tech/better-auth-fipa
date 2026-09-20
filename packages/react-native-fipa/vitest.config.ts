import { defineConfig } from "vitest/config";
export default defineConfig({
  test: {
    coverage: {
      provider: "v8",
      include: ["src/**/*.ts"],
      exclude: [
        "src/**/*.test.ts",
        "src/test-fixtures/**",
        "src/index.ts",
        "src/NativeDeviceAttestation.ts",
        "src/NativeSessionVault.ts",
        "src/NativeFirstPartyTransport.ts",
        "src/NativeAndroidIntegrity.ts",
        "src/types.ts",
        "src/core.ts",
      ],
      reporter: ["text", "json-summary"],
      thresholds: { statements: 85, branches: 75, functions: 90, lines: 85 },
    },
  },
});
