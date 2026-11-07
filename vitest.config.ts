import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    testTimeout: 30_000,
    hookTimeout: 60_000,
    // Integration tests spawn real server processes on random ports; keep files serial-safe.
    fileParallelism: false,
    reporters: ["verbose"],
  },
});
