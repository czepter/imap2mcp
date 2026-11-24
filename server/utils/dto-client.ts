import type { Capability, ClientDetail, Grant, Operation, Overview, Rule, TokenDetail, TokenSummary } from "../../shared/types/api";
import { getDb } from "../core/db/database.js";
import { config } from "../core/config.js";
import { listMailboxes } from "../core/imap/mailboxes.js";
import { CAPABILITIES, scopesToCaps } from "../core/oauth/common.js";
import { OPERATIONS, OP_CAPABILITY, PRESET_OPS, capabilityRows, isValidSelector, listRules, presetActive, type RuleRow } from "../core/policy/rules.js";
import { clientDisplayName, clientKind, deadApiClientIds, isoTs, getClientRow, parseRedirectUris, toClientSummary, type ClientRow } from "./dto-common";
import { mailboxStatusOf, toMailboxDto } from "./dto-mailbox";

/** The old "What each capability allows" table. */
export const CAPABILITY_HELP: Record<Capability, string> = {
  read: "List folders, search, read messages",
  draft: "Create drafts in the mailbox's Drafts folder only",
  organize: "Move messages and set flags within one mailbox. No delete.",
};

export function toRuleDto(r: RuleRow): Rule {
  return { id: r.id, mailboxId: r.mailbox_id, folder: r.folder, operation: r.operation, effect: r.effect, selectorValid: isValidSelector(r.folder), createdAt: isoTs(r.created_at) };
}

/**
 * Capabilities a token could use right now: scope ceiling intersected with the live grants, per mailbox
 * (the old dashboard `reach()`, in mailbox list order and capability order).
 */
export function tokenReach(
  scopes: string, clientId: string, mailboxes: { id: string; label: string }[], granted: Map<string, Set<string>>,
): TokenSummary["reach"] {
  const ceiling = new Set<string>(scopesToCaps(scopes));
  const out: TokenSummary["reach"] = [];
  for (const m of mailboxes) {
    const live = CAPABILITIES.filter((c) => ceiling.has(c) && granted.get(`${clientId}:${m.id}`)?.has(c));
    if (live.length) out.push({ mailboxId: m.id, mailboxLabel: m.label, capabilities: live });
  }
  return out;
}

export function buildOverview(): Overview {
  const db = getDb();
  const mailboxes = listMailboxes();
  const dead = deadApiClientIds();
  const clients = (db.prepare("SELECT client_id, client_name, redirect_uris, disabled, created_at FROM oauth_clients ORDER BY created_at DESC").all() as ClientRow[])
    .filter((c) => !dead.has(c.client_id));
  const grantRows = capabilityRows(db).filter((g) => !dead.has(g.client_id));
  const granted = new Map<string, Set<string>>(); // `${client}:${mailbox}` -> caps
  for (const g of grantRows) {
    const k = `${g.client_id}:${g.mailbox_id}`;
    if (!granted.has(k)) granted.set(k, new Set());
    granted.get(k)!.add(g.capability);
  }
  const now = new Date().toISOString();
  const tokens = db.prepare(
    `SELECT t.id, t.client_id, t.scopes, t.expires_at, t.created_at, c.client_name, c.redirect_uris
       FROM oauth_tokens t JOIN oauth_clients c ON c.client_id = t.client_id
      WHERE t.revoked = 0 AND (t.expires_at > ? OR (t.refresh_expires_at IS NOT NULL AND t.refresh_expires_at > ?))
      ORDER BY t.created_at DESC`,
  ).all(now, now) as { id: string; client_id: string; scopes: string; expires_at: string; created_at: string; client_name: string | null; redirect_uris: string }[];

  const clientCount = (mid: string) => new Set(grantRows.filter((g) => g.mailbox_id === mid).map((g) => g.client_id)).size;
  const grants: Grant[] = grantRows.map((g) => ({ clientId: g.client_id, mailboxId: g.mailbox_id, capability: g.capability }));
  return {
    registrationMode: config.registrationMode,
    mailboxes: mailboxes.map((m) => ({ ...toMailboxDto(m), status: mailboxStatusOf(m.id).status, clientCount: clientCount(m.id) })),
    clients: clients.map(toClientSummary),
    grants,
    tokens: tokens.map((t) => ({
      id: t.id,
      clientId: t.client_id,
      clientName: t.client_name || t.client_id, // the old token table fell back to the id, not "(unnamed)"
      kind: clientKind(t.redirect_uris),
      reach: tokenReach(t.scopes, t.client_id, mailboxes, granted),
      scopes: scopesToCaps(t.scopes),
      createdAt: isoTs(t.created_at),
      expiresAt: isoTs(t.expires_at),
    })),
  };
}

export interface LiveTokenRow { id: string; client_id: string; scopes: string; resource: string; expires_at: string; created_at: string }

/** A token that is not revoked and still usable or refreshable (the overview's liveness rule). */
export function getLiveToken(id: string): LiveTokenRow | undefined {
  const now = new Date().toISOString();
  return getDb().prepare(
    `SELECT id, client_id, scopes, resource, expires_at, created_at FROM oauth_tokens
      WHERE id = ? AND revoked = 0 AND (expires_at > ? OR (refresh_expires_at IS NOT NULL AND refresh_expires_at > ?))`,
  ).get(id, now, now) as LiveTokenRow | undefined;
}

export function buildTokenDetail(t: LiveTokenRow): TokenDetail {
  const db = getDb();
  const mailboxes = listMailboxes();
  const client = getClientRow(t.client_id)!;
  const granted = new Map<string, Set<string>>();
  for (const g of capabilityRows(db, { clientId: t.client_id })) {
    const k = `${g.client_id}:${g.mailbox_id}`;
    if (!granted.has(k)) granted.set(k, new Set());
    granted.get(k)!.add(g.capability);
  }
  const now = new Date().toISOString();
  const others = (db.prepare(
    `SELECT COUNT(*) AS n FROM oauth_tokens WHERE client_id = ? AND id <> ? AND revoked = 0
        AND (expires_at > ? OR (refresh_expires_at IS NOT NULL AND refresh_expires_at > ?))`,
  ).get(t.client_id, t.id, now, now) as { n: number }).n;
  return {
    token: {
      id: t.id,
      clientId: t.client_id,
      clientName: client.client_name || t.client_id,
      kind: clientKind(client.redirect_uris),
      reach: tokenReach(t.scopes, t.client_id, mailboxes, granted),
      scopes: scopesToCaps(t.scopes),
      createdAt: isoTs(t.created_at),
      expiresAt: isoTs(t.expires_at),
    },
    client: toClientSummary(client),
    mailboxes: mailboxes.map((m) => ({
      id: m.id,
      label: m.label,
      draftsFolder: m.drafts_folder,
      granted: Object.fromEntries(CAPABILITIES.map((cap) => [cap, presetActive(db, t.client_id, m.id, cap)])) as Record<Capability, boolean>,
    })),
    otherActiveTokenCount: others,
  };
}

export function buildClientDetail(c: ClientRow): ClientDetail {
  const db = getDb();
  const mailboxes = listMailboxes();
  const activeTokenCount = (db.prepare("SELECT COUNT(*) AS n FROM oauth_tokens WHERE client_id = ? AND revoked = 0").get(c.client_id) as { n: number }).n;
  const presetOperations = Object.fromEntries(CAPABILITIES.map((cap) => [cap, [...PRESET_OPS[cap]]])) as Record<Capability, Operation[]>;
  return {
    client: { ...toClientSummary(c), clientName: clientDisplayName(c.client_name), redirectUris: parseRedirectUris(c.redirect_uris) },
    mailboxes: mailboxes.map((m) => ({
      id: m.id,
      label: m.label,
      draftsFolder: m.drafts_folder,
      granted: Object.fromEntries(CAPABILITIES.map((cap) => [cap, presetActive(db, c.client_id, m.id, cap)])) as Record<Capability, boolean>,
    })),
    rules: listRules(db, c.client_id).map(toRuleDto),
    activeTokenCount,
    help: {
      capabilities: { ...CAPABILITY_HELP },
      presetOperations,
      operations: OPERATIONS.map((operation) => ({ operation, capability: OP_CAPABILITY[operation] })),
    },
  };
}

