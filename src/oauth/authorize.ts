import { Router } from "express";
import type { Request, Response } from "express";
import { getDb } from "../db/database.js";
import { requireAdmin, csrfProtection, csrfToken, CSRF_FIELD } from "../web/deps.js";
import { listMailboxes } from "../imap/mailboxes.js";
import { layout } from "../web/views/layout.js";
import { escapeHtml as esc } from "../web/views/escapeHtml.js";
import {
  CAPABILITIES, CODE_TTL_MS, baseUrl, capsToScopes, newSecret, resourceUrl, scopesToCaps, sha256hex,
} from "./common.js";
import type { Capability } from "../types.js";

const router = Router();

interface ClientRow { client_id: string; client_name: string | null; redirect_uris: string; disabled: number }

interface AuthParams {
  client: ClientRow;
  redirect_uri: string;
  state?: string;
  code_challenge: string;
  resource: string;
  caps: Capability[];
}

function page(res: Response, status: number, msg: string) {
  res.status(status).send(layout("Authorization error", `<div class="card"><h2>Authorization error</h2><div class="error">${esc(msg)}</div></div>`));
}

function redirectError(res: Response, p: { redirect_uri: string; state?: string }, error: string, desc?: string) {
  const u = new URL(p.redirect_uri);
  u.searchParams.set("error", error);
  if (desc) u.searchParams.set("error_description", desc);
  if (p.state) u.searchParams.set("state", p.state);
  u.searchParams.set("iss", baseUrl());
  res.redirect(302, u.toString());
}

const str = (v: unknown): string | undefined => (typeof v === "string" && v.length > 0 ? v : undefined);

/** Validate params from query (GET) or body (POST). Returns params or sends an error response. */
function validate(src: Record<string, unknown>, res: Response): AuthParams | null {
  const client_id = str(src.client_id);
  const redirect_uri = str(src.redirect_uri);
  if (!client_id || !redirect_uri) { page(res, 400, "Missing client_id or redirect_uri"); return null; }
  const client = getDb().prepare("SELECT client_id, client_name, redirect_uris, disabled FROM oauth_clients WHERE client_id = ?").get(client_id) as ClientRow | undefined;
  if (!client || client.disabled) { page(res, 400, "Unknown or disabled client"); return null; }
  let uris: string[] = [];
  try { uris = JSON.parse(client.redirect_uris); } catch { /* none */ }
  if (!uris.includes(redirect_uri)) { page(res, 400, "redirect_uri is not registered for this client"); return null; }

  const state = str(src.state);
  const ctx = { redirect_uri, state };
  if (src.response_type !== "code") { redirectError(res, ctx, "unsupported_response_type"); return null; }
  const code_challenge = str(src.code_challenge);
  if (!code_challenge || src.code_challenge_method !== "S256" || !/^[A-Za-z0-9\-_]{43}$/.test(code_challenge)) {
    redirectError(res, ctx, "invalid_request", "PKCE with code_challenge_method=S256 is required"); return null;
  }
  const resource = str(src.resource) ?? resourceUrl();
  if (resource !== resourceUrl()) { redirectError(res, ctx, "invalid_target", "Unknown resource"); return null; }
  const requested = scopesToCaps(str(src.scope) ?? "mail:read mail:draft mail:organize");
  if (requested.length === 0) { redirectError(res, ctx, "invalid_scope"); return null; }
  return { client, redirect_uri, state, code_challenge, resource, caps: requested };
}

router.get("/oauth/authorize", requireAdmin, (req: Request, res: Response) => {
  const p = validate(req.query as Record<string, unknown>, res);
  if (!p) return;
  const mailboxes = listMailboxes();
  const hidden = (k: string, v: string | undefined) => (v === undefined ? "" : `<input type="hidden" name="${esc(k)}" value="${esc(v)}">`);

  const rows = mailboxes.map((m) => `<tr><td>${esc(m.label)}</td>${CAPABILITIES.map((c) =>
    p.caps.includes(c)
      ? `<td><input type="checkbox" name="g_${esc(m.id)}_${c}" value="1" aria-label="${esc(c)} on ${esc(m.label)}"></td>`
      : `<td class="small">-</td>`).join("")}</tr>`).join("");

  res.setHeader("Cache-Control", "no-store");
  res.send(layout("Authorize", `
  <div class="card">
    <h2>Authorize ${esc(p.client.client_name || p.client.client_id)}</h2>
    <p>This application requests access to your mail. Nothing is allowed by default; tick exactly what to permit.</p>
    <p class="small">Redirects to: ${esc(p.redirect_uri)}</p>
    <form method="POST" action="/oauth/authorize">
      <input type="hidden" name="${CSRF_FIELD}" value="${esc(csrfToken(req))}">
      ${hidden("client_id", p.client.client_id)}${hidden("redirect_uri", p.redirect_uri)}${hidden("state", p.state)}
      ${hidden("response_type", "code")}${hidden("code_challenge", p.code_challenge)}${hidden("code_challenge_method", "S256")}
      ${hidden("resource", p.resource)}${hidden("scope", capsToScopes(p.caps))}
      ${mailboxes.length === 0
        ? `<div class="error">No mailboxes configured. <a href="/mailboxes/new">Add one</a> first.</div>`
        : `<table><tr><th>Mailbox</th>${CAPABILITIES.map((c) => `<th>${esc(c)}</th>`).join("")}</tr>${rows}</table>`}
      <button type="submit" name="decision" value="approve">Approve</button>
      <button type="submit" name="decision" value="deny" class="btn-danger">Deny</button>
    </form>
  </div>`, "admin"));
});

router.post("/oauth/authorize", requireAdmin, csrfProtection, (req: Request, res: Response) => {
  const body = (req.body ?? {}) as Record<string, unknown>;
  const p = validate(body, res);
  if (!p) return;
  if (body.decision !== "approve") return redirectError(res, p, "access_denied");

  const mailboxes = listMailboxes();
  const grants: Array<[string, Capability]> = [];
  const granted = new Set<Capability>();
  for (const m of mailboxes) {
    for (const c of p.caps) {
      if (body[`g_${m.id}_${c}`]) { grants.push([m.id, c]); granted.add(c); }
    }
  }
  if (grants.length === 0) return redirectError(res, p, "access_denied", "No permissions were granted");

  const code = newSecret();
  const db = getDb();
  db.transaction(() => {
    const ins = db.prepare("INSERT OR IGNORE INTO grants (client_id, mailbox_id, capability) VALUES (?, ?, ?)");
    for (const [mid, cap] of grants) ins.run(p.client.client_id, mid, cap);
    db.prepare(
      `INSERT INTO oauth_codes (code_hash, client_id, redirect_uri, scopes, resource, code_challenge, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).run(sha256hex(code), p.client.client_id, p.redirect_uri, capsToScopes([...granted]), p.resource, p.code_challenge,
      new Date(Date.now() + CODE_TTL_MS).toISOString());
  })();

  const u = new URL(p.redirect_uri);
  u.searchParams.set("code", code);
  if (p.state) u.searchParams.set("state", p.state);
  u.searchParams.set("iss", baseUrl());
  res.setHeader("Cache-Control", "no-store");
  res.redirect(302, u.toString());
});

export default router;
