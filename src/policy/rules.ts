import type Database from "better-sqlite3";
import { randomUUID } from "crypto";
import type { Capability } from "../types.js";

export type Operation = "search" | "read_headers" | "read_body" | "draft" | "move" | "flag";
export type Effect = "allow" | "deny";

export const OPERATIONS: readonly Operation[] = ["search", "read_headers", "read_body", "draft", "move", "flag"];

/** Token-ceiling capability required for each operation (OAuth scopes are unchanged from v0). */
export const OP_CAPABILITY: Record<Operation, Capability> = {
  search: "read",
  read_headers: "read",
  read_body: "read",
  draft: "draft",
  move: "organize",
  flag: "organize",
};

/** v0 preset -> v1 rules (all on folder '*'). */
export const PRESET_OPS: Record<Capability, readonly Operation[]> = {
  read: ["search", "read_headers", "read_body"],
  draft: ["draft"],
  organize: ["move", "flag"],
};

export function isOperation(v: unknown): v is Operation {
  return typeof v === "string" && (OPERATIONS as readonly string[]).includes(v);
}

const CONTROL = /[\x00-\x1f\x7f]/;

/**
 * Valid selectors: '*' (all folders), 'prefix/*' (strictly the sub-folders under "prefix/", at any depth; not "prefix"
 * itself), or an exact IMAP path without wildcards. Case-sensitive. Anything else is invalid and never matches.
 */
export function isValidSelector(sel: unknown): sel is string {
  if (typeof sel !== "string" || sel.length === 0 || sel.length > 255 || CONTROL.test(sel)) return false;
  if (sel === "*") return true;
  if (sel.endsWith("/*")) {
    const prefix = sel.slice(0, -2);
    return prefix.length > 0 && !prefix.includes("*");
  }
  return !sel.includes("*");
}

/** Does a rule selector match a concrete folder path? Invalid selectors/folders never match (fail closed). */
export function folderMatches(selector: string, folder: string): boolean {
  if (!isValidSelector(selector)) return false;
  if (typeof folder !== "string" || folder.length === 0 || CONTROL.test(folder)) return false;
  if (selector === "*") return true;
  if (selector.endsWith("/*")) {
    const prefix = selector.slice(0, -1); // keeps trailing '/'
    return folder.length > prefix.length && folder.startsWith(prefix);
  }
  return selector === folder;
}

export interface RuleRow { id: string; client_id: string; mailbox_id: string; folder: string; operation: Operation; effect: Effect; created_at: string }

export function listRules(db: Database.Database, clientId: string): RuleRow[] {
  return db
    .prepare("SELECT id, client_id, mailbox_id, folder, operation, effect, created_at FROM policy_rules WHERE client_id = ? ORDER BY mailbox_id, folder, operation, effect")
    .all(clientId) as RuleRow[];
}

/** Insert or flip a rule (unique per client/mailbox/folder/operation). Caller validates the selector. */
export function setRule(db: Database.Database, clientId: string, mailboxId: string, folder: string, op: Operation, effect: Effect): void {
  db.prepare(
    `INSERT INTO policy_rules (id, client_id, mailbox_id, folder, operation, effect) VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT (client_id, mailbox_id, folder, operation) DO UPDATE SET effect = excluded.effect`
  ).run(randomUUID(), clientId, mailboxId, folder, op, effect);
}

/** Consent: add the preset's allow rules on '*'. Never overrides an existing rule (an existing deny stays). */
export function grantPreset(db: Database.Database, clientId: string, mailboxId: string, cap: Capability): void {
  const ins = db.prepare(
    "INSERT OR IGNORE INTO policy_rules (id, client_id, mailbox_id, folder, operation, effect) VALUES (?, ?, ?, '*', ?, 'allow')"
  );
  for (const op of PRESET_OPS[cap]) ins.run(randomUUID(), clientId, mailboxId, op);
}

export function presetActive(db: Database.Database, clientId: string, mailboxId: string, cap: Capability): boolean {
  const n = (db
    .prepare(`SELECT COUNT(*) n FROM policy_rules WHERE client_id = ? AND mailbox_id = ? AND folder = '*' AND effect = 'allow' AND operation IN (${PRESET_OPS[cap].map(() => "?").join(",")})`)
    .get(clientId, mailboxId, ...PRESET_OPS[cap]) as { n: number }).n;
  return n === PRESET_OPS[cap].length;
}

export function revokePreset(db: Database.Database, clientId: string, mailboxId: string, cap: Capability): void {
  db.prepare(`DELETE FROM policy_rules WHERE client_id = ? AND mailbox_id = ? AND folder = '*' AND effect = 'allow' AND operation IN (${PRESET_OPS[cap].map(() => "?").join(",")})`)
    .run(clientId, mailboxId, ...PRESET_OPS[cap]);
}

/** Display helper: (client, mailbox, capability) triples that have at least one allow rule (for dashboards). */
export function capabilityRows(db: Database.Database, where: { clientId?: string; mailboxId?: string } = {}): Array<{ client_id: string; mailbox_id: string; capability: Capability }> {
  const rows = db
    .prepare("SELECT DISTINCT client_id, mailbox_id, operation FROM policy_rules WHERE effect = 'allow' AND (? IS NULL OR client_id = ?) AND (? IS NULL OR mailbox_id = ?)")
    .all(where.clientId ?? null, where.clientId ?? null, where.mailboxId ?? null, where.mailboxId ?? null) as Array<{ client_id: string; mailbox_id: string; operation: Operation }>;
  const seen = new Set<string>();
  const out: Array<{ client_id: string; mailbox_id: string; capability: Capability }> = [];
  for (const r of rows) {
    const capability = OP_CAPABILITY[r.operation];
    const k = `${r.client_id}|${r.mailbox_id}|${capability}`;
    if (capability && !seen.has(k)) { seen.add(k); out.push({ client_id: r.client_id, mailbox_id: r.mailbox_id, capability }); }
  }
  return out;
}
