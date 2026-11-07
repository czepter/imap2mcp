import { Router } from "express";
import { randomBytes } from "crypto";
import { v4 as uuid } from "uuid";
import { getDb } from "../db/database.js";
import { verifyPKCE } from "./pkce.js";
import type { OAuthCode, OAuthToken } from "../types.js";

const router = Router();

router.post("/oauth/token", (req, res) => {
  const { grant_type } = req.body;

  if (grant_type === "authorization_code") {
    return handleAuthorizationCode(req, res);
  } else if (grant_type === "refresh_token") {
    return handleRefreshToken(req, res);
  }

  res.status(400).json({ error: "unsupported_grant_type" });
});

function handleAuthorizationCode(req: any, res: any) {
  const { code, client_id, redirect_uri, code_verifier } = req.body;

  if (!code || !client_id || !code_verifier) {
    return res.status(400).json({ error: "invalid_request", error_description: "Missing required parameters" });
  }

  const db = getDb();
  const authCode = db.prepare("SELECT * FROM oauth_codes WHERE code = ?").get(code) as OAuthCode | undefined;

  if (!authCode) {
    return res.status(400).json({ error: "invalid_grant", error_description: "Invalid authorization code" });
  }
  if (authCode.used) {
    return res.status(400).json({ error: "invalid_grant", error_description: "Code already used" });
  }
  if (new Date(authCode.expires_at) < new Date()) {
    return res.status(400).json({ error: "invalid_grant", error_description: "Code expired" });
  }
  if (authCode.client_id !== client_id) {
    return res.status(400).json({ error: "invalid_grant", error_description: "Client mismatch" });
  }
  if (authCode.redirect_uri !== redirect_uri) {
    return res.status(400).json({ error: "invalid_grant", error_description: "Redirect URI mismatch" });
  }
  if (!verifyPKCE(code_verifier, authCode.code_challenge)) {
    return res.status(400).json({ error: "invalid_grant", error_description: "PKCE verification failed" });
  }

  // Mark code as used
  db.prepare("UPDATE oauth_codes SET used = 1 WHERE code = ?").run(code);

  // Issue tokens
  const accessToken = randomBytes(32).toString("hex");
  const refreshToken = randomBytes(32).toString("hex");
  const accessExpiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString(); // 1 hour
  const refreshExpiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(); // 30 days

  db.prepare(`
    INSERT INTO oauth_tokens (id, access_token, refresh_token, client_id, user_id, account_id, scopes, access_token_expires_at, refresh_token_expires_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(uuid(), accessToken, refreshToken, authCode.client_id, authCode.user_id, authCode.account_id, authCode.scopes, accessExpiresAt, refreshExpiresAt);

  res.json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: 3600,
    refresh_token: refreshToken,
    scope: authCode.scopes,
  });
}

function handleRefreshToken(req: any, res: any) {
  const { refresh_token, client_id } = req.body;

  if (!refresh_token) {
    return res.status(400).json({ error: "invalid_request" });
  }

  const db = getDb();
  const token = db.prepare("SELECT * FROM oauth_tokens WHERE refresh_token = ? AND revoked = 0").get(refresh_token) as OAuthToken | undefined;

  if (!token) {
    return res.status(400).json({ error: "invalid_grant", error_description: "Invalid refresh token" });
  }
  if (token.refresh_token_expires_at && new Date(token.refresh_token_expires_at) < new Date()) {
    return res.status(400).json({ error: "invalid_grant", error_description: "Refresh token expired" });
  }
  if (client_id && token.client_id !== client_id) {
    return res.status(400).json({ error: "invalid_grant", error_description: "Client mismatch" });
  }

  // Revoke old token (rotation)
  db.prepare("UPDATE oauth_tokens SET revoked = 1 WHERE id = ?").run(token.id);

  // Issue new tokens
  const newAccessToken = randomBytes(32).toString("hex");
  const newRefreshToken = randomBytes(32).toString("hex");
  const accessExpiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();
  const refreshExpiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();

  db.prepare(`
    INSERT INTO oauth_tokens (id, access_token, refresh_token, client_id, user_id, account_id, scopes, access_token_expires_at, refresh_token_expires_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(uuid(), newAccessToken, newRefreshToken, token.client_id, token.user_id, token.account_id, token.scopes, accessExpiresAt, refreshExpiresAt);

  res.json({
    access_token: newAccessToken,
    token_type: "Bearer",
    expires_in: 3600,
    refresh_token: newRefreshToken,
    scope: token.scopes,
  });
}

export default router;
