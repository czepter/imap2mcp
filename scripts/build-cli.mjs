#!/usr/bin/env node
// Bundles the audit export CLI (server/core/audit/cli.ts) into one standalone ESM file, dist/audit/cli.js.
// The Nuxt/Nitro build does not emit it, and the production image has no TypeScript tooling.
// better-sqlite3 stays external (native addon): it resolves from node_modules next to the file or above it.
// Usage: node scripts/build-cli.mjs   (also: npm run build:cli)
import { build } from "esbuild";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

await build({
  entryPoints: [resolve(root, "server/core/audit/cli.ts")],
  outfile: resolve(root, "dist/audit/cli.js"),
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node22",
  external: ["better-sqlite3"],
  // Some bundled CommonJS dependencies call require(); give them one.
  banner: { js: 'import { createRequire as __createRequire } from "node:module"; const require = __createRequire(import.meta.url);' },
  logLevel: "info",
});
