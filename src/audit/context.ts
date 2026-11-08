import { AsyncLocalStorage } from "node:async_hooks";

/**
 * Per-tool-call audit scratchpad (DESIGN_V2). Tools call `auditNote()` to describe what they touched;
 * the audit wrapper in src/mcp/server.ts reads it after the call and persists ONE event per attempt.
 * Never put bodies, header text, tokens or credentials here.
 */
export interface AuditNote {
  mailboxId?: string;
  folder?: string;
  uidValidity?: number;
  /** Exact UIDs returned/affected (multi-message reads/searches record the full returned set). */
  uids?: number[];
  /** Per-hit folders for multi-folder results (search across folders); stored in place of the flat uid list. */
  refs?: AuditRef[];
  /** True only when the call was refused by policy (incl. a policy-masked NOT_FOUND). A genuine miss leaves it unset. */
  denied?: boolean;
  /** Served from the sidecar's in-memory cache (no upstream round trip for this data). */
  cached?: boolean;
  /** Set when a write was reconciled against server state after an ambiguous failure. */
  reconciled?: boolean;
}

export interface AuditRef { folder: string; uidValidity: number; uids: number[] }

export interface AuditScope {
  requestId: string;
  note: AuditNote;
}

const als = new AsyncLocalStorage<AuditScope>();

export function runWithAudit<T>(scope: AuditScope, fn: () => Promise<T>): Promise<T> {
  return als.run(scope, fn);
}

/** Merge facts into the current call's audit note. No-op outside a call. */
export function auditNote(patch: AuditNote): void {
  const s = als.getStore();
  if (!s) return;
  const n = s.note;
  if (patch.refs) n.refs = [...(n.refs ?? []), ...patch.refs];
  if (patch.uids) n.uids = [...(n.uids ?? []), ...patch.uids];
  if (patch.cached !== undefined) n.cached = (n.cached ?? true) && patch.cached; // cached only if ALL data was
  const { uids: _u, cached: _c, refs: _r, ...rest } = patch;
  Object.assign(n, rest);
}

export function currentRequestId(): string | undefined {
  return als.getStore()?.requestId;
}
