import type { Capability, Mailbox, MailboxStatus, MailboxStatusValue } from "../../shared/types/api";
import { getDb } from "../core/db/database.js";
import { clearMailboxAuthFailure } from "../core/imap/client.js";
import { retryMailbox } from "../core/sidecar/index.js";
import type { Mailbox as MailboxRow } from "../core/imap/mailboxes.js";
import { CAPABILITIES } from "../core/oauth/common.js";
import { capabilityRows } from "../core/policy/rules.js";
import { trimmedString, clientDisplayName, isoTs } from "./dto-common";

export function toMailboxDto(m: MailboxRow): Mailbox {
  return { id: m.id, label: m.label, host: m.imap_host, port: m.imap_port, username: m.imap_username, draftsFolder: m.drafts_folder, createdAt: isoTs(m.created_at) };
}

interface StatusRow { status: string; last_error_code: string | null; last_ok_at: string | null; next_retry_at: string | null }
const UNKNOWN: StatusRow = { status: "unknown", last_error_code: null, last_ok_at: null, next_retry_at: null };

/** Same query (and the same fail-soft fallback) as the old `mailboxStatus()`. */
export function mailboxStatusOf(id: string): MailboxStatus {
  let r: StatusRow;
  try {
    r = (getDb().prepare("SELECT status, last_error_code, last_ok_at, next_retry_at FROM mailboxes WHERE id = ?").get(id) as StatusRow | undefined) ?? UNKNOWN;
  } catch { r = UNKNOWN; }
  const known = r.status === "ok" || r.status === "degraded" || r.status === "auth_failed";
  return { status: (known ? r.status : "unknown") as MailboxStatusValue, lastErrorCode: r.last_error_code, lastOkAt: isoTs(r.last_ok_at), nextRetryAt: isoTs(r.next_retry_at) };
}

/** Resets status to 'unknown' and clears both auth-failure latches (Node pool and sidecar). */
export async function resetMailboxStatus(id: string): Promise<void> {
  getDb().prepare("UPDATE mailboxes SET status = 'unknown', last_error_code = NULL, next_retry_at = NULL WHERE id = ?").run(id);
  clearMailboxAuthFailure(id);
  await retryMailbox(id); // never throws
}

/** Body of POST/PATCH /api/mailboxes, normalised exactly like the old form handler (trim + length caps, integer port). */
export function parseMailboxBody(b: Record<string, unknown>): { label: string; host: string; port: number; username: string; password: string } {
  const port = typeof b.port === "number" ? b.port : parseInt(trimmedString(b.port, 6), 10);
  return {
    label: trimmedString(b.label, 100),
    host: trimmedString(b.host, 253),
    port,
    username: trimmedString(b.username, 320),
    password: typeof b.password === "string" ? b.password : "",
  };
}

/** Clients that hold at least one grant on a mailbox. */
export function mailboxReach(mailboxId: string): { clientId: string; clientName: string; capabilities: Capability[] }[] {
  const db = getDb();
  const byClient = new Map<string, Set<string>>();
  for (const r of capabilityRows(db, { mailboxId })) {
    if (!byClient.has(r.client_id)) byClient.set(r.client_id, new Set());
    byClient.get(r.client_id)!.add(r.capability);
  }
  const names = new Map((db.prepare("SELECT client_id, client_name FROM oauth_clients").all() as { client_id: string; client_name: string | null }[]).map((c) => [c.client_id, clientDisplayName(c.client_name)]));
  return [...byClient].map(([clientId, caps]) => ({
    clientId, clientName: names.get(clientId) ?? clientId, capabilities: CAPABILITIES.filter((c) => caps.has(c)),
  }));
}
