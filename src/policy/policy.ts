import type Database from "better-sqlite3";
import { getDb } from "../db/database.js";
import { PolicyError, type Capability, type TokenContext } from "../types.js";

/**
 * Effective access = token scopes (ceiling) ∩ live grant rows for (client, mailbox) ∩ requested op.
 * Default deny; no caching; every call reads the DB. `db` is injectable for tests.
 */
function hasGrant(db: Database.Database, clientId: string, mailboxId: string, cap: Capability): boolean {
  const row = db
    .prepare("SELECT 1 FROM grants WHERE client_id = ? AND mailbox_id = ? AND capability = ?")
    .get(clientId, mailboxId, cap);
  return row !== undefined;
}

export function assertAllowed(
  ctx: TokenContext,
  mailboxId: string,
  cap: Capability,
  db: Database.Database = getDb(),
): void {
  if (!ctx || !Array.isArray(ctx.scopes) || !ctx.scopes.includes(cap)) throw new PolicyError();
  if (typeof mailboxId !== "string" || mailboxId === "") throw new PolicyError();
  if (!hasGrant(db, ctx.clientId, mailboxId, cap)) throw new PolicyError();
}

export function allowedMailboxes(
  ctx: TokenContext,
  cap: Capability,
  db: Database.Database = getDb(),
): string[] {
  if (!ctx || !Array.isArray(ctx.scopes) || !ctx.scopes.includes(cap)) return [];
  const rows = db
    .prepare("SELECT mailbox_id FROM grants WHERE client_id = ? AND capability = ? ORDER BY mailbox_id")
    .all(ctx.clientId, cap) as { mailbox_id: string }[];
  return rows.map((r) => r.mailbox_id);
}

/** Mailboxes with any grant that is also within the token's scopes. */
export function anyAllowedMailboxes(ctx: TokenContext, db: Database.Database = getDb()): string[] {
  const set = new Set<string>();
  for (const cap of ["read", "draft", "organize"] as Capability[]) {
    for (const id of allowedMailboxes(ctx, cap, db)) set.add(id);
  }
  return [...set].sort();
}
