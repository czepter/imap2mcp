import type { Request, Response, NextFunction } from "express";
import { getDb } from "../db/database.js";
import { sha256hex, baseUrl, resourceUrl, scopesToCaps } from "./common.js";

function deny(res: Response, error?: string, desc?: string) {
  const params = [`resource_metadata="${baseUrl()}/.well-known/oauth-protected-resource"`];
  if (error) params.push(`error="${error}"`);
  if (desc) params.push(`error_description="${desc}"`);
  res.setHeader("WWW-Authenticate", `Bearer ${params.join(", ")}`);
  return res.status(401).json({ error: error ?? "unauthorized", error_description: desc });
}

export function bearerAuth(req: Request, res: Response, next: NextFunction) {
  const h = req.headers.authorization;
  if (!h || !/^Bearer /i.test(h)) return deny(res);
  const token = h.slice(7).trim();
  if (!token) return deny(res);

  const row = getDb()
    .prepare(
      `SELECT t.id, t.client_id, t.scopes, t.resource, t.expires_at, t.revoked, c.disabled
         FROM oauth_tokens t JOIN oauth_clients c ON c.client_id = t.client_id
        WHERE t.token_hash = ?`
    )
    .get(sha256hex(token)) as
    | { id: string; client_id: string; scopes: string; resource: string; expires_at: string; revoked: number; disabled: number }
    | undefined;

  if (!row || row.revoked || row.disabled) return deny(res, "invalid_token");
  if (new Date(row.expires_at).getTime() <= Date.now()) return deny(res, "invalid_token", "Token expired");
  if (row.resource !== resourceUrl()) return deny(res, "invalid_token", "Token audience mismatch");

  (req as any).tokenContext = {
    tokenId: row.id,
    clientId: row.client_id,
    scopes: scopesToCaps(row.scopes),
  };
  next();
}
