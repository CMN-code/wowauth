import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    globals: true,
    testTimeout: 15_000,
    hookTimeout: 60_000, // globalSetup covers `cargo build`, which can be slow cold
    // All test files share one wowauth instance and one SQLite file (see
    // global-setup.ts) -- run files sequentially rather than racing concurrent
    // writers against WAL's busy_timeout.
    fileParallelism: false,
    reporters: process.env.CI ? ["default", "github-actions", "junit"] : ["default"],
    outputFile: process.env.CI ? { junit: "./results.xml" } : undefined,
    globalSetup: ["./src/global-setup.ts"],
  },
});
