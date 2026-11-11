import type { AuditEvent as AuditEventDto, AuditOutcome } from "../../shared/types/api";
import type Database from "better-sqlite3";
import { getDb } from "../core/db/database.js";
import { iterateAudit, type AuditEvent, type AuditFilter } from "../core/audit/store.js";
import { isoTs } from "./dto-common";
import { csvHeader, parseTime, toCsvLine, toJsonlLine } from "../core/audit/export.js";

export const AUDIT_PAGE_SIZE = 50;
export const AUDIT_OUTCOMES: AuditOutcome[] = ["ok", "denied", "failed", "unknown_outcome"];

/** Old `q()`: trimmed, capped string query value; anything else is "". */
export const queryString = (v: unknown, max = 128): string => (typeof v === "string" ? v.trim().slice(0, max) : "");

/** Same filter semantics as the old audit routes, incl. the inclusive bare-date `to`. */
export function auditFilterFrom(query: Record<string, unknown>): AuditFilter {
  const raw = {
    client: queryString(query.client), mailbox: queryString(query.mailbox), tool: queryString(query.tool), outcome: queryString(query.outcome, 32),
    from: queryString(query.from, 40), to: queryString(query.to, 40),
  };
  const f: AuditFilter = {};
  if (raw.client) f.clientId = raw.client;
  if (raw.mailbox) f.mailboxId = raw.mailbox;
  if (raw.tool) f.tool = raw.tool;
  if ((AUDIT_OUTCOMES as string[]).includes(raw.outcome)) f.outcome = raw.outcome as AuditOutcome;
  const from = parseTime(raw.from);
  if (from) f.from = from;
  const to = parseTime(raw.to);
  // a bare date in "to" means "through the end of that day"
  if (to) f.to = /^\d{4}-\d{2}-\d{2}$/.test(raw.to) ? new Date(Date.parse(to) + 86_400_000).toISOString() : to;
  return f;
}

/** Wire shape: the per-folder `refs` breakdown stays internal (`uids` is the flat union). */
export function toAuditEventDto(e: AuditEvent): AuditEventDto {
  return {
    id: e.id, ts: isoTs(e.ts), requestId: e.requestId, clientId: e.clientId, mailboxId: e.mailboxId, folder: e.folder,
    uidValidity: e.uidValidity, uid: e.uid, uids: e.uids, uidsTruncated: e.uidsTruncated, tool: e.tool, outcome: e.outcome,
    errorCode: e.errorCode, cached: e.cached, reconciled: e.reconciled, durationMs: e.durationMs,
  };
}

/**
 * Export lines in the same order and format as `exportLines` (oldest first, header row for CSV), produced in
 * bounded chunks. better-sqlite3 refuses every write ("database connection is busy") while an `.iterate()` cursor is
 * open, so a cursor must never stay open across event-loop turns while the response is flushed. Each chunk therefore
 * drains its own cursor completely, and the next chunk resumes after the last emitted (ts, id) pair.
 */
export function* auditExportLines(format: "jsonl" | "csv", f: AuditFilter, db: Database.Database = getDb(), chunkSize = 500): Generator<string[]> {
  if (format === "csv") yield [csvHeader()];
  let lastTs: string | undefined;
  let lastId: string | undefined;
  for (;;) {
    const chunkFilter: AuditFilter = lastTs === undefined || (f.from && f.from > lastTs) ? f : { ...f, from: lastTs };
    const lines: string[] = [];
    let n = 0;
    let nextTs = lastTs;
    let nextId = lastId;
    for (const e of iterateAudit(chunkFilter, db)) {
      if (lastTs !== undefined && (e.ts < lastTs || (e.ts === lastTs && lastId !== undefined && e.id <= lastId))) continue; // already sent
      lines.push(format === "csv" ? toCsvLine(e) : toJsonlLine(e));
      nextTs = e.ts;
      nextId = e.id;
      if (++n >= chunkSize) break; // leaving the loop closes the cursor
    }
    if (n === 0) return;
    yield lines;
    if (n < chunkSize) return;
    lastTs = nextTs;
    lastId = nextId;
  }
}
