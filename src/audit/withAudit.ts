import { randomUUID } from "crypto";
import type Database from "better-sqlite3";
import { runWithAudit, type AuditNote } from "./context.js";
import { auditInsertProbe, insertAuditEvent, type AuditOutcome } from "./store.js";
import { log } from "../log.js";
import { getDb } from "../db/database.js";

export type AuditFailMode = "closed" | "open";

/** AUDIT_FAIL_MODE: `closed` (default) or `open`. Anything else is treated as closed. */
export function auditFailMode(env: NodeJS.ProcessEnv = process.env): AuditFailMode {
  return env.AUDIT_FAIL_MODE?.trim().toLowerCase() === "open" ? "open" : "closed";
}

/** Test seam: override the DB used for audit writes. */
let dbOverride: (() => Database.Database) | undefined;
export function setAuditDb(f: (() => Database.Database) | undefined): void { dbOverride = f; }
const db = () => (dbOverride ? dbOverride() : getDb());

export interface ToolResult { [k: string]: unknown; isError?: boolean; content: { type: "text"; text: string }[] }

function parsePayload(r: ToolResult): Record<string, unknown> | undefined {
  const t = r?.content?.[0]?.text;
  if (typeof t !== "string") return undefined;
  try { const v = JSON.parse(t); return v && typeof v === "object" && !Array.isArray(v) ? v : undefined; } catch { return undefined; }
}

/**
 * Map a tool result to an audit outcome. FORBIDDEN is always "denied". NOT_FOUND is "denied" only when the tool
 * flagged `note.denied === true` (policy-masked folder: the client sees NOT_FOUND, the owner sees the truth);
 * a genuinely missing folder/message is "failed".
 */
export function classifyResult(r: ToolResult, note: AuditNote = {}): { outcome: AuditOutcome; errorCode: string | null } {
  if (!r?.isError) return { outcome: "ok", errorCode: null };
  const code = String(parsePayload(r)?.code ?? "UNKNOWN");
  if (code === "UNKNOWN_OUTCOME") return { outcome: "unknown_outcome", errorCode: code };
  if (code === "FORBIDDEN" || note.denied === true) return { outcome: "denied", errorCode: code };
  return { outcome: "failed", errorCode: code };
}

const num = (v: unknown): number | undefined => (typeof v === "number" && Number.isInteger(v) ? v : undefined);
const sstr = (v: unknown, max = 512): string | undefined => (typeof v === "string" && v.length <= max ? v : undefined);

/** Identifiers only (never content) taken from tool arguments, as a fallback when the tool noted nothing. */
function argFallback(args: unknown): AuditNote {
  const a = (args ?? {}) as Record<string, any>;
  const out: AuditNote = {};
  const ref = a.ref && typeof a.ref === "object" ? a.ref : undefined;
  out.mailboxId = sstr(ref?.mailbox) ?? sstr(a.mailbox, 128);
  out.folder = sstr(ref?.folder) ?? sstr(a.folder);
  out.uidValidity = num(ref?.uidValidity);
  if (num(ref?.uid) !== undefined) out.uids = [ref.uid];
  if (Array.isArray(a.refs) && a.refs.length) {
    const refs = a.refs.filter((r: any) => r && typeof r === "object");
    const first = refs[0];
    if (first && refs.every((r: any) => r.mailbox === first.mailbox && r.folder === first.folder && r.uidValidity === first.uidValidity)) {
      out.mailboxId = sstr(first.mailbox, 128);
      out.folder = sstr(first.folder);
      out.uidValidity = num(first.uidValidity);
    } else if (first) out.mailboxId = refs.every((r: any) => r.mailbox === first.mailbox) ? sstr(first.mailbox, 128) : undefined;
    out.uids = refs.map((r: any) => r.uid).filter((u: unknown) => num(u) !== undefined);
  }
  return out;
}

export interface WithAuditOptions {
  tool: string;
  clientId?: string | null;
  requestId: string;
  mutating?: boolean;
}

function unavailable(requestId: string, performed: boolean): ToolResult {
  return {
    isError: true,
    content: [{ type: "text" as const, text: JSON.stringify({
      code: "UNAVAILABLE",
      message: performed
        ? "The audit store is unavailable. The operation may have been applied but could not be recorded."
        : "The audit store is unavailable; no operation was performed.",
      requestId, retryable: !performed && true,
      operatorAction: "Check disk space and database health, /readyz and the bridge logs for this requestId. Set AUDIT_FAIL_MODE=open only if you accept unaudited access.",
    }) }],
  };
}

/**
 * Run one tool attempt inside an audit scope and persist exactly ONE audit row before returning.
 * `fn` receives nothing; it should call tools (which call auditNote()). Never throws.
 */
export async function withAudit(opts: WithAuditOptions, args: unknown, fn: () => Promise<ToolResult>): Promise<ToolResult> {
  const mode = auditFailMode();
  const { requestId } = opts;
  if (mode === "closed" && !auditInsertProbe(db())) {
    log.error("audit.unavailable", { requestId, tool: opts.tool, phase: "preflight" });
    return unavailable(requestId, false);
  }
  const note: AuditNote = {};
  const started = Date.now();
  let result: ToolResult;
  try {
    result = await runWithAudit({ requestId, note }, fn);
  } catch {
    result = { isError: true, content: [{ type: "text" as const, text: JSON.stringify({ code: "UPSTREAM_ERROR", message: "Operation failed", requestId, retryable: false }) }] };
  }
  const durationMs = Date.now() - started;

  // Make sure the error payload always carries the request id.
  if (result.isError) {
    const p = parsePayload(result);
    if (p && p.requestId !== requestId) {
      result = { ...result, content: [{ type: "text", text: JSON.stringify({ ...p, requestId }) }, ...result.content.slice(1)] };
    }
  }

  const { outcome, errorCode } = classifyResult(result, note);
  if (result.isError) log.warn("tool call failed", { requestId, tool: opts.tool, errorCode, outcome });
  const fb = argFallback(args);
  const uids = note.uids?.length ? note.uids : fb.uids;
  try {
    insertAuditEvent({
      requestId,
      clientId: opts.clientId ?? null,
      mailboxId: note.mailboxId ?? fb.mailboxId ?? null,
      folder: note.folder ?? fb.folder ?? null,
      uidValidity: note.uidValidity ?? fb.uidValidity ?? null,
      uids: uids ?? null,
      refs: note.refs ?? null,
      tool: opts.tool,
      outcome,
      errorCode,
      cached: note.cached === true,
      reconciled: note.reconciled === true,
      durationMs,
    }, db());
  } catch (e) {
    log.error("audit.write_failed", { requestId, tool: opts.tool, outcome, errorName: (e as Error).name, mode });
    if (mode === "closed") return unavailable(requestId, !!opts.mutating);
  }
  return result;
}

export function newRequestId(): string { return randomUUID(); }
