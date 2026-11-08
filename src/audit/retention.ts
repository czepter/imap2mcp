import type Database from "better-sqlite3";
import { getDb } from "../db/database.js";
import { log } from "../log.js";

const DAY_MS = 86_400_000;

/** AUDIT_RETENTION_DAYS: default 90, 0 = keep forever. Invalid values fall back to 90. */
export function retentionDays(env: NodeJS.ProcessEnv = process.env): number {
  const raw = env.AUDIT_RETENTION_DAYS?.trim();
  if (!raw) return 90;
  const n = Number(raw);
  return Number.isInteger(n) && n >= 0 ? n : 90;
}

/** Delete events older than `days`. Returns rows removed. No-op when days is 0. */
export function pruneAudit(days = retentionDays(), now = Date.now(), db: Database.Database = getDb()): number {
  if (days <= 0) return 0;
  const cutoff = new Date(now - days * DAY_MS).toISOString();
  return db.prepare("DELETE FROM audit_events WHERE ts < ?").run(cutoff).changes;
}

let timer: NodeJS.Timeout | undefined;

function safePrune(): void {
  try {
    const n = pruneAudit();
    if (n) log.info("audit.pruned", { removed: n });
  } catch (e) {
    log.error("audit.prune_failed", { errorName: (e as Error).name });
  }
}

/** Prune now, then every 24 h. Idempotent. Call from index.ts after migrations. */
export function startAuditPruner(): void {
  if (timer) return;
  safePrune();
  timer = setInterval(safePrune, DAY_MS);
  timer.unref();
}

export function stopAuditPruner(): void {
  if (timer) clearInterval(timer);
  timer = undefined;
}
