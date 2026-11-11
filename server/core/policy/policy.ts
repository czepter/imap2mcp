import type Database from "better-sqlite3";
import { getDb } from "../db/database.js";
import { PolicyError, type Capability, type TokenContext } from "../types.js";
import { OP_CAPABILITY, PRESET_OPS, folderMatches, isOperation, isValidSelector, type Operation } from "./rules.js";

export type { Operation } from "./rules.js";
export { OPERATIONS, OP_CAPABILITY, PRESET_OPS } from "./rules.js";

/**
 * Policy v1. Effective access for (client, mailbox, folder, op) =
 *   token scopes include the op's capability  AND  no matching deny rule  AND  some matching allow rule.
 * Default deny, invalid selectors never match, no caching: every call reads the DB. `db` is injectable for tests.
 */
interface Rule { folder: string; operation: string; effect: string }

const validCtx = (ctx: TokenContext | undefined): ctx is TokenContext =>
  !!ctx && typeof ctx.clientId === "string" && ctx.clientId !== "" && Array.isArray(ctx.scopes);

function loadRules(db: Database.Database, clientId: string, mailboxId: string): Rule[] {
  return db
    .prepare("SELECT folder, operation, effect FROM policy_rules WHERE client_id = ? AND mailbox_id = ?")
    .all(clientId, mailboxId) as Rule[];
}

function decide(rules: Rule[], folder: string, op: Operation): boolean {
  let allow = false;
  for (const r of rules) {
    if (r.operation !== op || !folderMatches(r.folder, folder)) continue;
    if (r.effect === "deny") return false;
    if (r.effect === "allow") allow = true;
  }
  return allow;
}

function inCeiling(ctx: TokenContext, op: Operation): boolean {
  return ctx.scopes.includes(OP_CAPABILITY[op]);
}

export function isOpAllowed(
  ctx: TokenContext, mailboxId: string, folder: string, op: Operation, db: Database.Database = getDb(),
): boolean {
  if (!validCtx(ctx) || !isOperation(op) || !inCeiling(ctx, op)) return false;
  if (typeof mailboxId !== "string" || mailboxId === "" || typeof folder !== "string" || folder === "") return false;
  return decide(loadRules(db, ctx.clientId, mailboxId), folder, op);
}

export function assertOp(
  ctx: TokenContext, mailboxId: string, folder: string, op: Operation, db: Database.Database = getDb(),
): void {
  if (!isOpAllowed(ctx, mailboxId, folder, op, db)) throw new PolicyError();
}

/** Folders (from `folders`) where ANY of `ops` is allowed. Order preserved; a single DB read. */
export function filterAllowedFolders(
  ctx: TokenContext, mailboxId: string, ops: Operation[], folders: string[], db: Database.Database = getDb(),
): string[] {
  if (!validCtx(ctx) || typeof mailboxId !== "string" || mailboxId === "" || !Array.isArray(folders)) return [];
  const usable = (Array.isArray(ops) ? ops : []).filter((o) => isOperation(o) && inCeiling(ctx, o));
  if (usable.length === 0) return [];
  const rules = loadRules(db, ctx.clientId, mailboxId);
  return folders.filter((f) => typeof f === "string" && f !== "" && usable.some((o) => decide(rules, f, o)));
}

/** Mailboxes where the client has at least one valid allow rule for an operation within the token's scopes. */
export function anyAllowedMailboxes(ctx: TokenContext, db: Database.Database = getDb()): string[] {
  if (!validCtx(ctx)) return [];
  const rows = db
    .prepare("SELECT mailbox_id, folder, operation FROM policy_rules WHERE client_id = ? AND effect = 'allow'")
    .all(ctx.clientId) as { mailbox_id: string; folder: string; operation: string }[];
  const set = new Set<string>();
  for (const r of rows) {
    if (isOperation(r.operation) && inCeiling(ctx, r.operation) && isValidSelector(r.folder)) set.add(r.mailbox_id);
  }
  return [...set].sort();
}

/** Does the client hold any valid allow rule on this mailbox for one of `ops` within the token's scopes? (folder-agnostic) */
export function mailboxHasAllow(ctx: TokenContext, mailboxId: string, ops: Operation[], db: Database.Database = getDb()): boolean {
  if (!validCtx(ctx) || typeof mailboxId !== "string" || mailboxId === "") return false;
  const rows = db
    .prepare("SELECT folder, operation FROM policy_rules WHERE client_id = ? AND mailbox_id = ? AND effect = 'allow'")
    .all(ctx.clientId, mailboxId) as { folder: string; operation: string }[];
  return rows.some((r) => isOperation(r.operation) && ops.includes(r.operation) && inCeiling(ctx, r.operation) && isValidSelector(r.folder));
}

// ---- v0 compatibility shims (remove at end of v1 once all callers use the v1 API) ----

/**
 * Capability-level check with v0 semantics: allowed iff every operation of the capability has an allow rule on
 * folder '*' and the mailbox has no deny rule for any of those operations (conservative: any deny blocks).
 */
function capAllowed(db: Database.Database, clientId: string, mailboxId: string, cap: Capability): boolean {
  const ops = PRESET_OPS[cap];
  const rules = loadRules(db, clientId, mailboxId).filter((r) => (ops as readonly string[]).includes(r.operation));
  if (rules.some((r) => r.effect === "deny")) return false;
  return ops.every((op) => rules.some((r) => r.operation === op && r.effect === "allow" && r.folder === "*"));
}

export function assertAllowed(
  ctx: TokenContext, mailboxId: string, cap: Capability, db: Database.Database = getDb(),
): void {
  if (!validCtx(ctx) || !ctx.scopes.includes(cap)) throw new PolicyError();
  if (typeof mailboxId !== "string" || mailboxId === "") throw new PolicyError();
  if (!capAllowed(db, ctx.clientId, mailboxId, cap)) throw new PolicyError();
}

export function allowedMailboxes(ctx: TokenContext, cap: Capability, db: Database.Database = getDb()): string[] {
  if (!validCtx(ctx) || !ctx.scopes.includes(cap)) return [];
  const ids = db.prepare("SELECT DISTINCT mailbox_id FROM policy_rules WHERE client_id = ? ORDER BY mailbox_id").all(ctx.clientId) as { mailbox_id: string }[];
  return ids.map((r) => r.mailbox_id).filter((m) => capAllowed(db, ctx.clientId, m, cap));
}
