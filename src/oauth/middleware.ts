import type { Request, Response, NextFunction } from "express";
import { getDb } from "../db/database.js";
import type { OAuthToken, TokenContext } from "../types.js";

export function bearerAuth(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "unauthorized", error_description: "Bearer token required" });
  }

  const accessToken = authHeader.slice(7);
  const db = getDb();
  const token = db.prepare(
    "SELECT * FROM oauth_tokens WHERE access_token = ? AND revoked = 0"
  ).get(accessToken) as OAuthToken | undefined;

  if (!token) {
    res.setHeader("WWW-Authenticate", 'Bearer error="invalid_token"');
    return res.status(401).json({ error: "invalid_token" });
  }
  if (new Date(token.access_token_expires_at) < new Date()) {
    res.setHeader("WWW-Authenticate", 'Bearer error="invalid_token", error_description="Token expired"');
    return res.status(401).json({ error: "invalid_token", error_description: "Token expired" });
  }

  req.tokenContext = {
    userId: token.user_id,
    accountId: token.account_id,
    scopes: token.scopes.split(" "),
    clientId: token.client_id,
  };

  next();
}
