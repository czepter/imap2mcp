import { join } from "node:path";
import { config } from "../config.js";
import { log } from "../log.js";
import { getDb } from "../db/database.js";
import { SidecarService } from "./service.js";
import { StatusPoller } from "./status.js";

export * from "./errors.js";
export { SidecarClient } from "./client.js";
export { Supervisor } from "./supervisor.js";
export { SidecarService, defaultOpenParams } from "./service.js";
export { StatusPoller, toMailboxStatus, type SidecarStatus, type MailboxStatus } from "./status.js";

let instance: SidecarService | null = null;
let poller: StatusPoller | null = null;

/** Environment knobs forwarded to the sidecar child (the supervisor does not inherit the parent environment). */
export const SIDECAR_ENV_KNOBS = [
  "SYNC_RECONCILE_SECS", "SIDECAR_AUTOSYNC_SECS",
  "IDLE_RENEW_SECS", "IDLE_POLL_SECS", "SIDECAR_FOLDER_IDLE_SECS",
  "RECONNECT_INITIAL_MS", "RECONNECT_MAX_MS", "RECONNECT_HEALTHY_MS", // tests only
] as const;

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
  for (const k of SIDECAR_ENV_KNOBS) {
    const v = process.env[k];
    if (v) env[k] = v;
  }
  return new SidecarService({ bin: config.sidecarBin, socketPath: join(config.dataDir, "sidecar.sock"), env });
}

/** Start at app boot. Never throws: tools return UPSTREAM_ERROR while the sidecar is down; supervision keeps retrying. */
export async function startSidecar(): Promise<void> {
  if (config.sidecarDisabled) { log.warn("SIDECAR_DISABLED is set: using the v0 direct IMAP read path (debug only)"); return; }
  const s = getSidecar();
  try { await s.start(); }
  catch (e) { log.error("Sidecar failed to start; retrying in the background", { err: e }); }
  if (!poller) {
    poller = new StatusPoller({ source: s, db: getDb });
    poller.start();
  }
}

/**
 * Operator pressed "Retry" or edited a mailbox's credentials: lift the sidecar's auth-failure latch.
 * Best effort and never throws (the sidecar may be disabled or down; it then has nothing latched).
 */
export async function retryMailbox(mailboxId: string): Promise<void> {
  if (config.sidecarDisabled || !instance) return;
  try { await instance.retryMailbox(mailboxId); }
  catch (e) { log.warn("sidecar retry failed", { mailboxId, err: e }); }
}

export async function stopSidecar(): Promise<void> {
  poller?.stop();
  poller = null;
  const s = instance;
  instance = null;
  if (s) await s.stop();
}
