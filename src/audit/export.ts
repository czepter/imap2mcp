import type { AuditEvent, AuditFilter } from "./store.js";
import { iterateAudit } from "./store.js";
import type Database from "better-sqlite3";

export const CSV_COLUMNS = [
  "id", "ts", "requestId", "clientId", "mailboxId", "folder", "uidValidity", "uid", "uids", "uidsTruncated",
  "tool", "outcome", "errorCode", "cached", "reconciled", "durationMs",
] as const;

/** Plain JSON object per event (ISO timestamps, booleans). */
export function eventToJson(e: AuditEvent): Record<string, unknown> {
  const o: Record<string, unknown> = {};
  for (const c of CSV_COLUMNS) o[c] = (e as unknown as Record<string, unknown>)[c];
  return o;
}

export function toJsonlLine(e: AuditEvent): string {
  return JSON.stringify(eventToJson(e));
}

/** RFC 4180 quoting plus spreadsheet formula neutralisation (leading = + - @ tab CR). */
export function csvCell(v: unknown): string {
  if (v === null || v === undefined) return "";
  let s = Array.isArray(v) ? JSON.stringify(v) : String(v);
  if (/^[=+\-@\t\r]/.test(s) && typeof v === "string") s = "'" + s;
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export const csvHeader = (): string => CSV_COLUMNS.join(",");
export function toCsvLine(e: AuditEvent): string {
  const o = eventToJson(e);
  return CSV_COLUMNS.map((c) => csvCell(o[c])).join(",");
}

/** Stream an export as lines (no trailing newline included). */
export function* exportLines(format: "jsonl" | "csv", f: AuditFilter, db?: Database.Database): Generator<string> {
  if (format === "csv") yield csvHeader();
  for (const e of db ? iterateAudit(f, db) : iterateAudit(f)) yield format === "csv" ? toCsvLine(e) : toJsonlLine(e);
}

/** Normalise a user-supplied date/time to ISO UTC ms, or undefined when invalid/empty. */
export function parseTime(v: unknown): string | undefined {
  if (typeof v !== "string" || !v.trim()) return undefined;
  const t = Date.parse(/^\d{4}-\d{2}-\d{2}$/.test(v.trim()) ? v.trim() + "T00:00:00.000Z" : v.trim());
  return Number.isNaN(t) ? undefined : new Date(t).toISOString();
}
