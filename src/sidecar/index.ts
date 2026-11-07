import { join } from "node:path";
import { config } from "../config.js";
import { SidecarService } from "./service.js";

export * from "./errors.js";
export { SidecarClient } from "./client.js";
export { Supervisor } from "./supervisor.js";
export { SidecarService, defaultOpenParams } from "./service.js";

let instance: SidecarService | null = null;

export function sidecarEnabled(): boolean { return !config.sidecarDisabled; }

/** The process-wide sidecar. Throws if SIDECAR_DISABLED is set (callers check sidecarEnabled first). */
export function getSidecar(): SidecarService {
  if (config.sidecarDisabled) throw new Error("Sidecar is disabled");
  if (!instance) instance = createSidecarFromConfig();
  return instance;
}

/** Test hook. */
export function setSidecarForTests(s: SidecarService | null): void { instance = s; }

export function createSidecarFromConfig(): SidecarService {
  const env: Record<string, string> = {};
  if (process.env.SIDECAR_EXTRA_CA_FILE) env.SIDECAR_EXTRA_CA_FILE = process.env.SIDECAR_EXTRA_CA_FILE;
  for (const k of ["SYNC_RECONCILE_SECS", "SIDECAR_AUTOSYNC_SECS"]) {
    const v = process.env[k];
    if (v) env[k] = v;
  }
  return new SidecarService({ bin: config.sidecarBin, socketPath: join(config.dataDir, "sidecar.sock"), env });
}

/** Start at app boot. Never throws: tools return UPSTREAM_ERROR while the sidecar is down; supervision keeps retrying. */
export async function startSidecar(): Promise<void> {
  if (config.sidecarDisabled) { console.warn("SIDECAR_DISABLED is set: using the v0 direct IMAP read path (debug only)"); return; }
  const s = getSidecar();
  try { await s.start(); }
  catch (e) { console.error(`Sidecar failed to start (${(e as Error).message}); retrying in the background`); }
}

export async function stopSidecar(): Promise<void> {
  const s = instance;
  instance = null;
  if (s) await s.stop();
}
