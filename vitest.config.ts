import { defineConfig } from "vitest/config";
import { resolve } from "node:path";
import LongFirstSequencer from "./test/sequencer.js";

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
    // Each integration file spawns its own Nitro server, sidecar and fake IMAP server (own temp dir, random ports), so
    // files run in parallel. 3 workers keep CPU headroom on a 4-vCPU CI runner for the timing-bounded tests.
    fileParallelism: true,
    maxWorkers: 3,
    sequence: { sequencer: LongFirstSequencer },
    // `nuxt build` runs here once per `vitest run` when .output is missing or older than the sources (skipped for unit-only runs).
    globalSetup: ["./test/globalSetup.ts"],
    reporters: ["verbose"],
  },
});
