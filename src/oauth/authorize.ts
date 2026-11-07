import { Router } from "express";
import { randomBytes } from "crypto";
import { getDb } from "../db/database.js";
import { getAccountsByUser } from "../imap/accounts.js";
import { SCOPES } from "../types.js";
import type { OAuthClient } from "../types.js";
import { escapeHtml } from "../web/views/escapeHtml.js";

const router = Router();

router.get("/oauth/authorize", (req, res) => {
  const { response_type, client_id, redirect_uri, scope, state, code_challenge, code_challenge_method } = req.query as Record<string, string>;

  if (response_type !== "code") {
    return res.status(400).send("Unsupported response_type. Must be 'code'.");
  }
  if (!client_id || !redirect_uri || !code_challenge) {
    return res.status(400).send("Missing required parameters: client_id, redirect_uri, code_challenge");
  }
  if (code_challenge_method && code_challenge_method !== "S256") {
    return res.status(400).send("Only S256 code_challenge_method is supported");
  }

  const db = getDb();
  const client = db.prepare("SELECT * FROM oauth_clients WHERE client_id = ?").get(client_id) as OAuthClient | undefined;
  if (!client) {
    return res.status(400).send("Unknown client_id");
  }

  const allowedUris: string[] = JSON.parse(client.redirect_uris);
  if (!allowedUris.includes(redirect_uri)) {
    return res.status(400).send("redirect_uri not registered for this client");
  }

  // If not logged in, redirect to login with return URL
  if (!req.session.userId) {
    req.session.returnTo = req.originalUrl;
    return res.redirect("/login");
  }

  const accounts = getAccountsByUser(req.session.userId);
  const requestedScopes = scope ? scope.split(" ") : Object.keys(SCOPES);

  res.send(renderConsentPage({
    clientName: client.client_name || client.client_id,
    requestedScopes,
    accounts,
    query: { client_id, redirect_uri, state, code_challenge, code_challenge_method: code_challenge_method || "S256" },
  }));
});

router.post("/oauth/authorize", (req, res) => {
  if (!req.session.userId) {
    return res.status(401).send("Not authenticated");
  }

  const { client_id, redirect_uri, state, code_challenge, code_challenge_method, account_id } = req.body;

  if (!client_id || !redirect_uri || !code_challenge) {
    return res.status(400).send("Missing required parameters");
  }

  // Validate client and redirect_uri match registration
  const db = getDb();
  const client = db.prepare("SELECT * FROM oauth_clients WHERE client_id = ?").get(client_id) as OAuthClient | undefined;
  if (!client) {
    return res.status(400).send("Unknown client_id");
  }
  const allowedUris: string[] = JSON.parse(client.redirect_uris);
  if (!allowedUris.includes(redirect_uri)) {
    return res.status(400).send("redirect_uri not registered for this client");
  }

  const grantedScopes: string[] = [];

  // Collect checked scopes from form
  for (const s of Object.keys(SCOPES)) {
    if (req.body[`scope_${s}`]) {
      grantedScopes.push(s);
    }
  }

  if (grantedScopes.length === 0) {
    return res.status(400).send("At least one permission must be granted");
  }
  if (!account_id) {
    return res.status(400).send("An email account must be selected");
  }

  // Verify account belongs to the authenticated user
  const accounts = getAccountsByUser(req.session.userId);
  if (!accounts.some(a => a.id === account_id)) {
    return res.status(403).send("Account does not belong to you");
  }

  const code = randomBytes(32).toString("hex");
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();

  db.prepare(`
    INSERT INTO oauth_codes (code, client_id, user_id, account_id, redirect_uri, scopes, code_challenge, expires_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(code, client_id, req.session.userId, account_id, redirect_uri, grantedScopes.join(" "), code_challenge, expiresAt);

  const redirectUrl = new URL(redirect_uri);
  redirectUrl.searchParams.set("code", code);
  if (state) redirectUrl.searchParams.set("state", state);

  res.redirect(redirectUrl.toString());
});

function renderConsentPage(opts: {
  clientName: string;
  requestedScopes: string[];
  accounts: { id: string; label: string }[];
  query: Record<string, string>;
}): string {
  const scopeCheckboxes = opts.requestedScopes
    .filter((s): s is keyof typeof SCOPES => s in SCOPES)
    .map(
      (s) =>
        `<label style="display:block;margin:8px 0;"><input type="checkbox" name="scope_${s}" value="1" checked> <strong>${s}</strong> — ${SCOPES[s]}</label>`
    )
    .join("\n");

  const accountOptions = opts.accounts
    .map((a) => `<option value="${escapeHtml(a.id)}">${escapeHtml(a.label)}</option>`)
    .join("\n");

  const hiddenFields = Object.entries(opts.query)
    .map(([k, v]) => `<input type="hidden" name="${escapeHtml(k)}" value="${escapeHtml(v)}">`)
    .join("\n");

  return `<!DOCTYPE html>
<html><head><title>Authorize Access</title>
<style>
  body { font-family: -apple-system, sans-serif; max-width: 500px; margin: 60px auto; padding: 20px; }
  .card { border: 1px solid #ddd; border-radius: 8px; padding: 24px; }
  h2 { margin-top: 0; }
  button { background: #2563eb; color: white; border: none; padding: 10px 24px; border-radius: 6px; cursor: pointer; font-size: 16px; margin-top: 16px; }
  button:hover { background: #1d4ed8; }
  select { width: 100%; padding: 8px; margin-top: 4px; border-radius: 4px; border: 1px solid #ccc; }
  .deny { background: #dc2626; margin-left: 8px; }
</style>
</head><body>
<div class="card">
  <h2>Authorize Access</h2>
  <p><strong>${escapeHtml(opts.clientName)}</strong> wants to access your email.</p>

  <form method="POST" action="/oauth/authorize">
    ${hiddenFields}

    <h3>Select Email Account</h3>
    ${opts.accounts.length > 0
      ? `<select name="account_id">${accountOptions}</select>`
      : `<p style="color:red;">No email accounts configured. <a href="/accounts/add">Add one first</a>.</p>`
    }

    <h3>Permissions</h3>
    ${scopeCheckboxes}

    <div style="margin-top:20px;">
      <button type="submit">Authorize</button>
    </div>
  </form>
</div>
</body></html>`;
}

export default router;
