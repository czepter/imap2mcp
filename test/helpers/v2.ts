/**
 * v2 (production hardening) helpers: stacks with scaled reconnect timers, raw tool calls that expose HTTP headers,
 * audit/mailbox DB accessors, structured-error and leakage assertions, UI actions (Retry / credential edit).
 */
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect } from "vitest";
import { createStack, sleep, type Stack, type ToolResult } from "./stack.js";
import { REPO } from "./server.js";
import { SIDECAR_BIN, haveSidecar } from "./v1.js";
import type { FakeImapServer } from "./fakeImap.js";
import { makeSelfSignedCert } from "./certs.js";

export { haveSidecar, SIDECAR_BIN };
export const canRunV2 = !!makeSelfSignedCert() && haveSidecar;
export const ALICE = "alice@example.test";
export const BOB = "bob@example.test";

/** Scaled timers so recovery tests run in seconds instead of minutes (documented test-only knobs, DESIGN_V2). */
export const FAST_ENV = { RECONNECT_INITIAL_MS: "200", RECONNECT_MAX_MS: "2000", SYNC_RECONCILE_SECS: "600" };

export async function createV2Stack(o: { env?: Record<string, string | undefined>; fake?: (f: FakeImapServer) => void; fast?: boolean } = {}): Promise<Stack> {
  return createStack({
    env: { SIDECAR_BIN, ...(o.fast === false ? { SYNC_RECONCILE_SECS: "600" } : FAST_ENV), ...o.env },
    fake: o.fake,
  });
}

// ------------------------------------------------------------------ raw tool call (headers + request id)
export interface RawToolResult { status: number; headers: Headers; isError: boolean; data: any; text: string; requestId: string | null }

export async function rawToolCall(base: string, token: string, name: string, args: Record<string, unknown> = {}, headers: Record<string, string> = {}): Promise<RawToolResult> {
  const res = await fetch(`${base}/mcp`, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${token}`, ...headers },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }),
  });
  const raw = await res.text();
  let rpc: any = null;
  const sse = /^data: (.*)$/m.exec(raw);
  try { rpc = JSON.parse(sse ? sse[1] : raw); } catch { /* non-JSON (401 etc.) */ }
  const text: string = rpc?.result?.content?.[0]?.text ?? "";
  let data: any = text;
  try { data = JSON.parse(text); } catch { /* keep */ }
  return { status: res.status, headers: res.headers, isError: !!rpc?.result?.isError, data, text, requestId: res.headers.get("x-request-id") };
}

// ------------------------------------------------------------------ DB accessors (live DB, short-lived handles)
export function dbAll<T = any>(s: Stack, sql: string, ...params: unknown[]): T[] {
  const db = s.srv.db();
  try {
    db.pragma("busy_timeout = 5000");
    return db.prepare(sql).all(...params) as T[];
  } finally {
    db.close();
  }
}
export function dbRun(s: Stack, sql: string, ...params: unknown[]): void {
  const db = s.srv.db();
  try {
    db.pragma("busy_timeout = 5000");
    db.prepare(sql).run(...params);
  } finally {
    db.close();
  }
}
export function dbExec(s: Stack, sql: string): void {
  const db = s.srv.db();
  try {
    db.pragma("busy_timeout = 5000");
    db.exec(sql);
  } finally {
    db.close();
  }
}
export interface AuditRow {
  id: string; ts: string; request_id: string; client_id: string | null; mailbox_id: string | null; folder: string | null;
  uid_validity: number | null; uid: number | null; uids: string | null; uids_truncated: number; tool: string; outcome: string;
  error_code: string | null; cached: number; reconciled: number; duration_ms: number | null;
}
export const auditRows = (s: Stack): AuditRow[] => dbAll<AuditRow>(s, "SELECT * FROM audit_events ORDER BY ts, rowid");
export const auditCount = (s: Stack): number => dbAll<{ n: number }>(s, "SELECT COUNT(*) n FROM audit_events")[0].n;
export const uidsOf = (r: AuditRow): number[] => (r.uids ? (JSON.parse(r.uids) as number[]) : []);
export interface MailboxStatusRow { status: string; last_error_code: string | null; last_ok_at: string | null; next_retry_at: string | null }
export const mailboxStatus = (s: Stack, id: string): MailboxStatusRow =>
  dbAll<MailboxStatusRow>(s, "SELECT status, last_error_code, last_ok_at, next_retry_at FROM mailboxes WHERE id = ?", id)[0];

/** Runs `fn` and returns the audit rows it appended (written before the tool result is returned: no waiting). */
export async function newAuditRows<T>(s: Stack, fn: () => Promise<T>): Promise<{ result: T; rows: AuditRow[] }> {
  const before = new Set(auditRows(s).map((r) => r.id));
  const result = await fn();
  return { result, rows: auditRows(s).filter((r) => !before.has(r.id)) };
}

// ------------------------------------------------------------------ admin API actions
/** Admin "Retry" on a mailbox: POST /api/mailboxes/:id/retry (204). */
export async function uiRetry(s: Stack, mailboxId: string): Promise<Response> {
  return s.admin.postWithCsrf(`/api/mailboxes/${mailboxId}/retry`);
}
/** Admin credential edit (same call the SPA's mailbox form makes): PATCH /api/mailboxes/:id (200 + Mailbox). */
export async function uiEditCredentials(s: Stack, mailboxId: string, user: string, pass: string): Promise<Response> {
  return s.admin.patchWithCsrf(`/api/mailboxes/${mailboxId}`, { label: `Box ${user.split("@")[0]}`, host: "localhost", port: s.fake.port, username: user, password: pass });
}

// ------------------------------------------------------------------ assertions
const ERROR_CODES = ["FORBIDDEN", "NOT_FOUND", "STALE_REFERENCE", "INVALID_INPUT", "UNSUPPORTED", "UPSTREAM_ERROR", "UNKNOWN_OUTCOME", "AUTH_FAILED", "TIMEOUT", "QUOTA_EXCEEDED", "FOLDER_UNAVAILABLE", "PROTOCOL_ERROR", "UNAVAILABLE"];
const REQUEST_ID = /^[A-Za-z0-9_-]{8,64}$/;
const KNOWN_KEYS = new Set(["code", "message", "requestId", "retryable", "operatorAction", "messageId", "likelyNotApplied", "reconciled"]);

/** Documented tool-error shape: {code,message,requestId,retryable,operatorAction?}. */
export function expectStructuredError(r: { isError: boolean; data: any; text: string }, code: string | string[], o: { retryable?: boolean; operatorAction?: boolean } = {}): void {
  expect(r.isError, `expected an error, got ${r.text.slice(0, 300)}`).toBe(true);
  const d = r.data;
  expect(typeof d, r.text).toBe("object");
  const codes = Array.isArray(code) ? code : [code];
  expect(codes, `error code ${d.code}: ${r.text}`).toContain(d.code);
  expect(ERROR_CODES).toContain(d.code);
  expect(typeof d.message).toBe("string");
  expect(d.message.length).toBeGreaterThan(0);
  expect(typeof d.requestId).toBe("string");
  expect(d.requestId).toMatch(REQUEST_ID);
  expect(typeof d.retryable).toBe("boolean");
  if (o.retryable !== undefined) expect(d.retryable, r.text).toBe(o.retryable);
  if (o.operatorAction === true) expect(typeof d.operatorAction === "string" && d.operatorAction.length > 0, r.text).toBe(true);
  for (const k of Object.keys(d)) expect(KNOWN_KEYS.has(k), `undocumented error field ${k}`).toBe(true);
}

/** Strings that must never appear in anything the client (or a log) sees. */
export function secretNeedles(s: Stack, extra: string[] = []): string[] {
  return [
    ...Object.values(s.imapPasswords), s.work.keyHex, s.work.sessionSecret, ...extra,
  ];
}
/** Extra needles for error TEXT shown to MCP clients: infrastructure identifiers and raw server text. */
export function errorLeakNeedles(s: Stack, serverTexts: string[] = []): string[] {
  return [
    ...secretNeedles(s), "localhost", "127.0.0.1", "::1", `:${s.fake.port}`, ...s.accounts, "example.test",
    ...serverTexts, "node_modules", "imapflow", "ECONN", "ETIMEDOUT", "ENOTFOUND", "EPIPE", "socket hang up", ".ts:", ".js:", "    at ",
    "better-sqlite3", "SQLITE_",
  ];
}
export function expectNoLeak(text: string, needles: string[], what = "output"): void {
  for (const n of needles) expect(text.includes(n), `${what} leaks ${JSON.stringify(n)}: ${text.slice(0, 400)}`).toBe(false);
}

/** Poll an async condition (tests that wait on Node's 5 s status poller etc.). */
export async function until<T>(fn: () => T | null | undefined | false | Promise<T | null | undefined | false>, ms: number, what: string, every = 100): Promise<T> {
  const end = Date.now() + ms;
  for (;;) {
    const v = await fn();
    if (v) return v as T;
    if (Date.now() > end) throw new Error(`timed out after ${ms} ms waiting for: ${what}`);
    await sleep(every);
  }
}

export const isoMs = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

/** Commands the fake server saw that mutate state, for "exactly one APPEND/MOVE/STORE" assertions. */
export const WRITE_RE = /^(APPEND|UID MOVE|MOVE|UID COPY|COPY|UID STORE|STORE|UID EXPUNGE|EXPUNGE)\b/i;
export const writeCommands = (f: FakeImapServer): string[] => f.commands.filter((c) => WRITE_RE.test(c.line)).map((c) => c.line.split(" ").slice(0, 2).join(" "));

/** Runs the audit export CLI (server/core/audit/cli.ts, what `npm run audit:export` wraps) against the stack's data dir. */
export function runAuditExport(s: Stack, args: string[], env: Record<string, string> = {}): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const p = spawn(process.execPath, [join(REPO, "node_modules/tsx/dist/cli.mjs"), join(REPO, "server/core/audit/cli.ts"), ...args], {
      cwd: REPO,
      env: { PATH: process.env.PATH, HOME: process.env.HOME, NODE_ENV: "test", DATA_DIR: s.work.dataDir, ENCRYPTION_KEY_FILE: s.work.keyFile, SESSION_SECRET: s.work.sessionSecret, BASE_URL: s.base, ...env } as NodeJS.ProcessEnv,
    });
    let stdout = "", stderr = "";
    p.stdout.on("data", (d) => (stdout += d));
    p.stderr.on("data", (d) => (stderr += d));
    p.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}
export const dbFileBytes = (s: Stack): string => {
  // main file + WAL: latin1 keeps byte-for-byte substring search honest
  let out = readFileSync(join(s.work.dataDir, "bridge.db")).toString("latin1");
  try { out += readFileSync(join(s.work.dataDir, "bridge.db-wal")).toString("latin1"); } catch { /* no wal */ }
  return out;
};
export type { ToolResult };
