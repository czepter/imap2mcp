import { Router } from "express";
import { randomUUID } from "crypto";
import { getDb } from "../db/database.js";
import { verifyPKCE } from "./pkce.js";
import { ACCESS_TTL_MS, REFRESH_TTL_MS, newSecret, rateLimiter, resourceUrl, sha256hex } from "./common.js";

const router = Router();
const limit = rateLimiter(60, 15 * 60 * 1000);

const err = (res: any, code: string, desc?: string, status = 400) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
  return res.status(status).json({ error: code, error_description: desc });
};

function issue(clientId: string, scopes: string, resource: string) {
  const access = newSecret();
  const refresh = newSecret();
  const id = randomUUID();
  const now = Date.now();
  getDb()
    .prepare(
      `INSERT INTO oauth_tokens (id, token_hash, refresh_hash, client_id, scopes, resource, expires_at, refresh_expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .run(id, sha256hex(access), sha256hex(refresh), clientId, scopes, resource,
      new Date(now + ACCESS_TTL_MS).toISOString(), new Date(now + REFRESH_TTL_MS).toISOString());
  return { access_token: access, token_type: "Bearer", expires_in: ACCESS_TTL_MS / 1000, refresh_token: refresh, scope: scopes };
}

function clientOk(clientId: string): boolean {
  const c = getDb().prepare("SELECT disabled FROM oauth_clients WHERE client_id = ?").get(clientId) as { disabled: number } | undefined;
  return !!c && !c.disabled;
}

router.post("/oauth/token", limit, (req, res) => {
  const b = (req.body ?? {}) as Record<string, unknown>;
  if (req.headers.authorization) return err(res, "invalid_client", "Client authentication via Authorization header is not supported", 401);
  const grant = b.grant_type;
  const clientId = typeof b.client_id === "string" ? b.client_id : "";
  if (!clientId) return err(res, "invalid_request", "client_id required");
  if (!clientOk(clientId)) return err(res, "invalid_client", "Unknown or disabled client", 401);
  const db = getDb();

  if (b.resource !== undefined && b.resource !== resourceUrl()) return err(res, "invalid_target", "Unknown resource");

  if (grant === "authorization_code") {
    const code = typeof b.code === "string" ? b.code : "";
    const verifier = typeof b.code_verifier === "string" ? b.code_verifier : "";
    const redirectUri = typeof b.redirect_uri === "string" ? b.redirect_uri : "";
    if (!code || !verifier || !redirectUri) return err(res, "invalid_request", "code, code_verifier, redirect_uri required");
    const hash = sha256hex(code);
    const row = db.prepare("SELECT * FROM oauth_codes WHERE code_hash = ?").get(hash) as any;
    if (!row || row.client_id !== clientId) return err(res, "invalid_grant");
    // single use: claim atomically before any further check can leak timing of validity
    const claimed = db.prepare("UPDATE oauth_codes SET used = 1 WHERE code_hash = ? AND used = 0").run(hash).changes;
    if (!claimed) return err(res, "invalid_grant", "Code already used");
    if (new Date(row.expires_at).getTime() <= Date.now()) return err(res, "invalid_grant", "Code expired");
    if (row.redirect_uri !== redirectUri) return err(res, "invalid_grant", "redirect_uri mismatch");
    if (!verifyPKCE(verifier, row.code_challenge)) return err(res, "invalid_grant", "PKCE verification failed");
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("Pragma", "no-cache");
    return res.json(issue(clientId, row.scopes, row.resource));
  }

  if (grant === "refresh_token") {
    const rt = typeof b.refresh_token === "string" ? b.refresh_token : "";
    if (!rt) return err(res, "invalid_request", "refresh_token required");
    const hash = sha256hex(rt);
    const row = db.prepare("SELECT * FROM oauth_tokens WHERE refresh_hash = ?").get(hash) as any;
    if (!row || row.client_id !== clientId) return err(res, "invalid_grant");
    if (row.revoked) {
      // reuse of a rotated/revoked refresh token: treat as theft, kill any live tokens of this client lineage
      db.prepare("UPDATE oauth_tokens SET revoked = 1 WHERE client_id = ? AND scopes = ? AND resource = ? AND revoked = 0 AND created_at >= ?")
        .run(clientId, row.scopes, row.resource, row.created_at);
      return err(res, "invalid_grant");
    }
    if (!row.refresh_expires_at || new Date(row.refresh_expires_at).getTime() <= Date.now()) return err(res, "invalid_grant", "Refresh token expired");

    // scope may only narrow
    const have = new Set(String(row.scopes).split(" "));
    let scopes = row.scopes as string;
    if (typeof b.scope === "string" && b.scope) {
      const asked = b.scope.split(/\s+/);
      if (!asked.every((s) => have.has(s))) return err(res, "invalid_scope");
      scopes = asked.join(" ");
    }
    const claimed = db.prepare("UPDATE oauth_tokens SET revoked = 1 WHERE id = ? AND revoked = 0").run(row.id).changes;
    if (!claimed) return err(res, "invalid_grant");
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("Pragma", "no-cache");
    return res.json(issue(clientId, scopes, row.resource));
  }

  return err(res, "unsupported_grant_type");
});

// RFC 7009 revocation (public clients identify by client_id; must own the token)
router.post("/oauth/revoke", limit, (req, res) => {
  const b = (req.body ?? {}) as Record<string, unknown>;
  const token = typeof b.token === "string" ? b.token : "";
  const clientId = typeof b.client_id === "string" ? b.client_id : "";
  if (!token || !clientId) return err(res, "invalid_request", "token and client_id required");
  const h = sha256hex(token);
  getDb()
    .prepare("UPDATE oauth_tokens SET revoked = 1 WHERE client_id = ? AND (token_hash = ? OR refresh_hash = ?)")
    .run(clientId, h, h);
  res.setHeader("Cache-Control", "no-store");
  res.status(200).json({});
});

export default router;
