import type { Capability, ClientKind, ClientSummary } from "../../shared/types/api";
import { getDb } from "../core/db/database.js";

/**
 * Wire timestamp: ISO-8601 stays as is; SQLite's "YYYY-MM-DD HH:MM:SS[.fff]" (UTC) becomes "YYYY-MM-DDTHH:MM:SS.fffZ".
 * Anything else is passed through unchanged.
 */
export function isoTs(v: string): string;
export function isoTs(v: string | null): string | null;
export function isoTs(v: string | null): string | null {
  if (v === null || /^\d{4}-\d{2}-\d{2}T/.test(v)) return v;
  const m = /^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})(?:\.(\d+))?$/.exec(v);
  return m ? `${m[1]}T${m[2]}.${(m[3] ?? "").padEnd(3, "0").slice(0, 3)}Z` : v;
}

/** Old `str()`: trimmed string, capped at `max`; anything else becomes "". */
export function trimmedString(v: unknown, max = 500): string {
  return typeof v === "string" ? v.trim().slice(0, max) : "";
}

export interface ClientRow { client_id: string; client_name: string | null; redirect_uris: string; disabled: number; created_at: string }

export function getClientRow(clientId: string): ClientRow | undefined {
  return getDb().prepare("SELECT client_id, client_name, redirect_uris, disabled, created_at FROM oauth_clients WHERE client_id = ?").get(clientId) as ClientRow | undefined;
}

/** Name shown for a client: the old UI printed "(unnamed)" when the client registered without a name. */
export const clientDisplayName = (name: string | null): string => name || "(unnamed)";

export function toClientSummary(c: ClientRow): ClientSummary {
  return { clientId: c.client_id, clientName: clientDisplayName(c.client_name), createdAt: isoTs(c.created_at), disabled: !!c.disabled, kind: clientKind(c.redirect_uris) };
}

/**
 * OAuth registration (dynamic or by the admin) requires at least one redirect URI, so a client without any can only
 * be the one behind an API token. It also means such a client can never start an authorization request.
 */
export const clientKind = (redirectUrisRaw: string): ClientKind => (parseRedirectUris(redirectUrisRaw).length ? "oauth" : "api");

/**
 * API-token clients whose token was revoked or has expired. Nothing can ever act as them again, so lists and reach
 * counts leave them out; the row stays so that audit entries keep pointing at a client.
 */
export function deadApiClientIds(): Set<string> {
  const rows = getDb().prepare(
    `SELECT c.client_id FROM oauth_clients c
      WHERE c.redirect_uris = '[]' AND NOT EXISTS (
        SELECT 1 FROM oauth_tokens t WHERE t.client_id = c.client_id AND t.revoked = 0 AND t.expires_at > ?)`,
  ).all(new Date().toISOString()) as { client_id: string }[];
  return new Set(rows.map((r) => r.client_id));
}

export function parseRedirectUris(raw: string): string[] {
  try {
    const v = JSON.parse(raw);
    return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
  } catch { return []; }
}

export function isCapability(v: unknown): v is Capability {
  return v === "read" || v === "draft" || v === "organize";
}

/** Parse `[{mailboxId, capability}]` leniently: malformed entries are dropped (unknown mailboxes/capabilities are filtered by the caller). */
export function parseGrantList(v: unknown): { mailboxId: string; capability: Capability }[] {
  if (!Array.isArray(v)) return [];
  const out: { mailboxId: string; capability: Capability }[] = [];
  for (const g of v) {
    if (g && typeof g === "object" && typeof (g as any).mailboxId === "string" && isCapability((g as any).capability)) {
      out.push({ mailboxId: (g as any).mailboxId, capability: (g as any).capability });
    }
  }
  return out;
}

/** Name shown on the consent page: the old page fell back to the client id. */
export const clientDisplayNameOrId = (c: ClientRow): string => c.client_name || c.client_id;
