import { defineConfig } from "vitest/config";
import { resolve } from "node:path";

// Docker-based smoke tests. Deliberately NOT part of `npm test` (files are *.smoke.ts, not *.test.ts).
// Run with: npm run smoke   (scripts/smoke.sh)
export default defineConfig({
  root: resolve(import.meta.dirname, "../.."),
  test: {
    include: ["test/smoke/**/*.smoke.ts"],
    testTimeout: 120_000,
    hookTimeout: 900_000, // image build
    fileParallelism: false,
    reporters: ["verbose"],
  },
});
