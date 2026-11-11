import { randomUUID } from "crypto";
import type Database from "better-sqlite3";
import { getDb } from "../db/database.js";
import type { AuditRef } from "./context.js";

export const MAX_AUDIT_UIDS = 5000;
export type AuditOutcome = "ok" | "denied" | "failed" | "unknown_outcome";

/** One row of audit_events (camelCase view). Contains identifiers only, never mail content. */
export interface AuditEvent {
  id: string;
  ts: string;
  requestId: string;
  clientId: string | null;
  mailboxId: string | null;
  folder: string | null;
  uidValidity: number | null;
  uid: number | null;
  uids: number[] | null;
  /** Per-folder breakdown for multi-folder results (null for single-folder events). `uids` is then the flat union. */
  refs: AuditRef[] | null;
  uidsTruncated: boolean;
  tool: string;
  outcome: AuditOutcome;
  errorCode: string | null;
  cached: boolean;
  reconciled: boolean;
  durationMs: number | null;
}

export type NewAuditEvent = Partial<Pick<AuditEvent, "id" | "ts">> &
  Omit<AuditEvent, "id" | "ts" | "uids" | "refs" | "uidsTruncated" | "uid" | "cached" | "reconciled"> & {
    uids?: number[] | null; refs?: AuditRef[] | null; uid?: number | null; cached?: boolean; reconciled?: boolean;
  };

const INSERT = `INSERT INTO audit_events
  (id, ts, request_id, client_id, mailbox_id, folder, uid_validity, uid, uids, uids_truncated, tool, outcome, error_code, cached, reconciled, duration_ms)
  VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`;

/** Synchronous insert (better-sqlite3). Throws on failure; callers decide fail-closed/open. */
export function insertAuditEvent(e: NewAuditEvent, db: Database.Database = getDb()): string {
  const id = e.id ?? randomUUID();
  let uid = e.uid ?? null;
  let uids: string | null = null;
  let truncated = 0;
  if (e.refs && e.refs.length) {
    // Multi-folder result: store the per-folder breakdown (still JSON in `uids`; readers detect object entries).
    let budget = MAX_AUDIT_UIDS;
    const list: AuditRef[] = [];
    for (const r of e.refs) {
      if (budget <= 0) { truncated = 1; break; }
      const u = r.uids.slice(0, budget);
      if (u.length < r.uids.length) truncated = 1;
      budget -= u.length;
      list.push({ folder: r.folder, uidValidity: r.uidValidity, uids: u });
    }
    uids = JSON.stringify(list);
  } else if (e.uids && e.uids.length) {
    if (e.uids.length === 1 && uid === null) uid = e.uids[0];
    else {
      const list = e.uids.slice(0, MAX_AUDIT_UIDS);
      truncated = e.uids.length > MAX_AUDIT_UIDS ? 1 : 0;
      uids = JSON.stringify(list);
    }
  }
  db.prepare(INSERT).run(
    id, e.ts ?? new Date().toISOString(), e.requestId, e.clientId, e.mailboxId, e.folder, e.uidValidity, uid, uids, truncated,
    e.tool, e.outcome, e.errorCode, e.cached ? 1 : 0, e.reconciled ? 1 : 0, e.durationMs,
  );
  return id;
}

/** Cheap check that the audit table exists and the DB accepts writes (used before write tools run). */
export function auditStoreReady(db: Database.Database = getDb()): boolean {
  try {
    if (db.readonly || !db.open) return false;
    db.prepare("SELECT 1 FROM audit_events LIMIT 1").get();
    return true;
  } catch {
    return false;
  }
}

const ROLLBACK = Symbol("audit-probe-rollback");

/**
 * Fail-closed pre-flight: prove an audit row can actually be INSERTed (table exists, DB writable, constraints/triggers
 * accept it, disk not full) by inserting a probe row inside a transaction that is always rolled back.
 */
export function auditInsertProbe(db: Database.Database = getDb()): boolean {
  if (!auditStoreReady(db)) return false;
  try {
    db.transaction(() => {
      insertAuditEvent({
        requestId: "probe", clientId: null, mailboxId: null, folder: null, uidValidity: null,
        tool: "probe", outcome: "ok", errorCode: null, durationMs: 0,
      }, db);
      throw ROLLBACK;
    })();
    return false;
  } catch (e) {
    return e === ROLLBACK;
  }
}

export interface AuditFilter {
  clientId?: string;
  mailboxId?: string;
  tool?: string;
  outcome?: AuditOutcome;
  /** inclusive ISO lower bound */
  from?: string;
  /** exclusive ISO upper bound */
  to?: string;
}

function where(f: AuditFilter): { sql: string; args: unknown[] } {
  const c: string[] = [];
  const a: unknown[] = [];
  if (f.clientId) { c.push("client_id = ?"); a.push(f.clientId); }
  if (f.mailboxId) { c.push("mailbox_id = ?"); a.push(f.mailboxId); }
  if (f.tool) { c.push("tool = ?"); a.push(f.tool); }
  if (f.outcome) { c.push("outcome = ?"); a.push(f.outcome); }
  if (f.from) { c.push("ts >= ?"); a.push(f.from); }
  if (f.to) { c.push("ts < ?"); a.push(f.to); }
  return { sql: c.length ? " WHERE " + c.join(" AND ") : "", args: a };
}

function fromRow(r: any): AuditEvent {
  const parsed = r.uids ? JSON.parse(r.uids) : null;
  const refs: AuditRef[] | null = Array.isArray(parsed) && parsed.length && typeof parsed[0] === "object" ? parsed : null;
  const flat: number[] | null = refs ? refs.flatMap((x) => x.uids) : parsed;
  return {
    id: r.id, ts: r.ts, requestId: r.request_id, clientId: r.client_id, mailboxId: r.mailbox_id, folder: r.folder,
    uidValidity: r.uid_validity, uid: r.uid, uids: flat, refs, uidsTruncated: !!r.uids_truncated,
    tool: r.tool, outcome: r.outcome, errorCode: r.error_code, cached: !!r.cached, reconciled: !!r.reconciled, durationMs: r.duration_ms,
  };
}

export function queryAudit(f: AuditFilter, opts: { limit?: number; offset?: number } = {}, db: Database.Database = getDb()): AuditEvent[] {
  const w = where(f);
  const rows = db.prepare(`SELECT * FROM audit_events${w.sql} ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?`)
    .all(...w.args, Math.min(Math.max(opts.limit ?? 50, 1), 100_000), Math.max(opts.offset ?? 0, 0));
  return rows.map(fromRow);
}

export function countAudit(f: AuditFilter, db: Database.Database = getDb()): number {
  const w = where(f);
  return (db.prepare(`SELECT COUNT(*) AS n FROM audit_events${w.sql}`).get(...w.args) as { n: number }).n;
}

/** Streaming iterator (oldest first) for exports; avoids loading everything into memory. */
export function* iterateAudit(f: AuditFilter, db: Database.Database = getDb()): Generator<AuditEvent> {
  const w = where(f);
  for (const r of db.prepare(`SELECT * FROM audit_events${w.sql} ORDER BY ts ASC, id ASC`).iterate(...w.args)) yield fromRow(r);
}

export function distinctValues(col: "tool" | "client_id" | "mailbox_id", db: Database.Database = getDb()): string[] {
  return (db.prepare(`SELECT DISTINCT ${col} AS v FROM audit_events WHERE ${col} IS NOT NULL ORDER BY v`).all() as { v: string }[]).map((r) => r.v);
}
