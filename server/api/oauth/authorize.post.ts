import { defineEventHandler } from "h3";
import type { AuthorizeRedirect } from "../../../shared/types/api";
import { requireAdmin } from "../../utils/requireAdmin";
import { readJsonBody } from "../../utils/readJson";
import { parseGrantList } from "../../utils/dto-common";
import { redirectErrorUrl, validateAuthorize } from "../../utils/dto-oauth";
import { getDb } from "../../core/db/database.js";
import { listMailboxes } from "../../core/imap/mailboxes.js";
import { CODE_TTL_MS, baseUrl, capsToScopes, newSecret, sha256hex } from "../../core/oauth/common.js";
import { grantPreset } from "../../core/policy/rules.js";
import type { Capability } from "../../core/types.js";

export default defineEventHandler(async (event): Promise<AuthorizeRedirect> => {
  await requireAdmin(event);
  const body = await readJsonBody(event);
  // Never trust the echoed params: everything is validated again against the database.
  const echoed = body.params && typeof body.params === "object" && !Array.isArray(body.params) ? (body.params as Record<string, unknown>) : {};
  const r = validateAuthorize(echoed);
  if (!r.ok) return { redirectTo: r.redirectTo };
  const p = r.value;
  if (body.decision !== "approve") return { redirectTo: redirectErrorUrl(p, "access_denied") };

  // Only capabilities the client requested, only for mailboxes that exist.
  const wanted = new Set(parseGrantList(body.grants).map((g) => `${g.mailboxId}|${g.capability}`));
  const grants: Array<[string, Capability]> = [];
  const granted = new Set<Capability>();
  for (const m of listMailboxes()) {
    for (const c of p.caps) {
      if (wanted.has(`${m.id}|${c}`)) { grants.push([m.id, c]); granted.add(c); }
    }
  }
  if (grants.length === 0) return { redirectTo: redirectErrorUrl(p, "access_denied", "No permissions were granted") };

  const code = newSecret();
  const db = getDb();
  db.transaction(() => {
    for (const [mid, cap] of grants) grantPreset(db, p.client.client_id, mid, cap); // presets expand to policy rules
    db.prepare(
      `INSERT INTO oauth_codes (code_hash, client_id, redirect_uri, scopes, resource, code_challenge, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    ).run(sha256hex(code), p.client.client_id, p.redirect_uri, capsToScopes([...granted]), p.resource, p.code_challenge,
      new Date(Date.now() + CODE_TTL_MS).toISOString());
  })();

  const u = new URL(p.redirect_uri);
  u.searchParams.set("code", code);
  if (p.state) u.searchParams.set("state", p.state);
  u.searchParams.set("iss", baseUrl());
  return { redirectTo: u.toString() };
});
