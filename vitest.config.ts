import { defineConfig } from "vitest/config";
import { resolve } from "node:path";

export default defineConfig({
  resolve: {
    alias: {
      // Plain-vitest unit tests of SPA modules (app/**) import with Nuxt's aliases.
      "~": resolve(import.meta.dirname, "app"),
      "@": resolve(import.meta.dirname, "app"),
      "~~": import.meta.dirname,
      "#shared": resolve(import.meta.dirname, "shared"),
    },
  },
  test: {
    include: ["test/**/*.test.ts"],
    testTimeout: 30_000,
    hookTimeout: 60_000,
    // Integration tests spawn the built Nitro server (.output/server/index.mjs) on random ports; keep files serial-safe.
    fileParallelism: false,
    // `nuxt build` runs here once per `vitest run` when .output is missing or older than the sources (skipped for unit-only runs).
    globalSetup: ["./test/globalSetup.ts"],
    reporters: ["verbose"],
  },
});
