import { ensureBuild } from "./helpers/build.js";

/**
 * Builds the Nitro server once per `vitest run` (only when stale), before any test file starts, so no test pays
 * the build time inside its own timeout. Skipped when the run is restricted to test/unit (those never start a server).
 */
export default async function setup(): Promise<void> {
  const filters = process.argv.slice(2).filter((a) => !a.startsWith("-") && a !== "run" && a !== "watch" && a !== "dev");
  if (filters.length > 0 && filters.every((f) => /(^|\/)unit(\/|$)|\/unit\//.test(f) || f.startsWith("test/unit"))) return;
  await ensureBuild();
}
