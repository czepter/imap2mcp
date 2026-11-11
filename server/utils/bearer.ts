import type { H3Event } from "h3";
import { getHeader, setResponseHeader, setResponseStatus } from "h3";
import { getDb } from "~~/server/core/db/database";
import { sha256hex, baseUrl, resourceUrl, scopesToCaps } from "~~/server/core/oauth/common";
import type { TokenContext } from "~~/server/core/types";

export type BearerResult = { ok: true; ctx: TokenContext } | { ok: false; body: { error: string; error_description?: string } };

function deny(event: H3Event, error?: string, desc?: string): BearerResult {
  const params = [`resource_metadata="${baseUrl()}/.well-known/oauth-protected-resource"`];
  if (error) params.push(`error="${error}"`);
  if (desc) params.push(`error_description="${desc}"`);
  setResponseHeader(event, "WWW-Authenticate", `Bearer ${params.join(", ")}`);
  setResponseStatus(event, 401);
  return { ok: false, body: { error: error ?? "unauthorized", error_description: desc } };
}

/**
 * Validates the bearer token against the live DB (hash lookup, revoked/disabled, expiry, audience).
 * On success the TokenContext is also attached to `event.context.tokenContext`. On failure the 401 status and the
 * WWW-Authenticate challenge are already set on the response and `body` is the JSON to return.
 */
export function bearerAuth(event: H3Event): BearerResult {
  const h = getHeader(event, "authorization");
  if (!h || !/^Bearer /i.test(h)) return deny(event);
  const token = h.slice(7).trim();
  if (!token) return deny(event);

  const row = getDb()
    .prepare(
      `SELECT t.id, t.client_id, t.scopes, t.resource, t.expires_at, t.revoked, c.disabled
         FROM oauth_tokens t JOIN oauth_clients c ON c.client_id = t.client_id
        WHERE t.token_hash = ?`
    )
    .get(sha256hex(token)) as
    | { id: string; client_id: string; scopes: string; resource: string; expires_at: string; revoked: number; disabled: number }
    | undefined;

  if (!row || row.revoked || row.disabled) return deny(event, "invalid_token");
  if (new Date(row.expires_at).getTime() <= Date.now()) return deny(event, "invalid_token", "Token expired");
  if (row.resource !== resourceUrl()) return deny(event, "invalid_token", "Token audience mismatch");

  const ctx: TokenContext = { tokenId: row.id, clientId: row.client_id, scopes: scopesToCaps(row.scopes) };
  (event.context as Record<string, unknown>).tokenContext = ctx;
  return { ok: true, ctx };
}
