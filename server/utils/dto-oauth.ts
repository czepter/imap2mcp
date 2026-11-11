import type { AuthorizeParams, Capability } from "../../shared/types/api";
import { getDb } from "../core/db/database.js";
import { CAPABILITIES, baseUrl, capsToScopes, resourceUrl, scopesToCaps } from "../core/oauth/common.js";
import { apiError } from "./apiError";
import type { ClientRow } from "./dto-common";

export interface ValidAuthorize {
  client: ClientRow;
  redirect_uri: string;
  state?: string;
  code_challenge: string;
  resource: string;
  caps: Capability[];
}

export type AuthorizeOutcome = { ok: true; value: ValidAuthorize } | { ok: false; redirectTo: string };

const str = (v: unknown): string | undefined => (typeof v === "string" && v.length > 0 ? v : undefined);

/** The client's redirect_uri carrying an OAuth error (same parameters as the old `redirectError`). */
export function redirectErrorUrl(p: { redirect_uri: string; state?: string }, error: string, desc?: string): string {
  const u = new URL(p.redirect_uri);
  u.searchParams.set("error", error);
  if (desc) u.searchParams.set("error_description", desc);
  if (p.state) u.searchParams.set("state", p.state);
  u.searchParams.set("iss", baseUrl());
  return u.toString();
}

/**
 * Validate an authorization request exactly like the old `validate()`. "Page" errors (the redirect_uri cannot be
 * trusted yet) throw a 400 apiError with the old message; protocol errors come back as `{ ok: false, redirectTo }`.
 */
export function validateAuthorize(src: Record<string, unknown>): AuthorizeOutcome {
  const client_id = str(src.client_id);
  const redirect_uri = str(src.redirect_uri);
  if (!client_id || !redirect_uri) apiError(400, "invalid_request", "Missing client_id or redirect_uri");
  const client = getDb().prepare("SELECT client_id, client_name, redirect_uris, disabled, created_at FROM oauth_clients WHERE client_id = ?").get(client_id) as ClientRow | undefined;
  if (!client || client.disabled) apiError(400, "invalid_request", "Unknown or disabled client");
  let uris: string[] = [];
  try { uris = JSON.parse(client.redirect_uris); } catch { /* none */ }
  if (!uris.includes(redirect_uri)) apiError(400, "invalid_request", "redirect_uri is not registered for this client");

  const state = str(src.state);
  const ctx = { redirect_uri, state };
  const fail = (error: string, desc?: string): AuthorizeOutcome => ({ ok: false, redirectTo: redirectErrorUrl(ctx, error, desc) });
  if (src.response_type !== "code") return fail("unsupported_response_type");
  const code_challenge = str(src.code_challenge);
  if (!code_challenge || src.code_challenge_method !== "S256" || !/^[A-Za-z0-9\-_]{43}$/.test(code_challenge)) {
    return fail("invalid_request", "PKCE with code_challenge_method=S256 is required");
  }
  const resource = str(src.resource) ?? resourceUrl();
  if (resource !== resourceUrl()) return fail("invalid_target", "Unknown resource");
  const caps = scopesToCaps(str(src.scope) ?? "mail:read mail:draft mail:organize");
  if (caps.length === 0) return fail("invalid_scope");
  return { ok: true, value: { client, redirect_uri, state, code_challenge, resource, caps } };
}

/** The validated, normalised params the SPA echoes back on POST. */
export function toAuthorizeParams(p: ValidAuthorize): AuthorizeParams {
  return {
    client_id: p.client.client_id,
    redirect_uri: p.redirect_uri,
    ...(p.state !== undefined ? { state: p.state } : {}),
    response_type: "code",
    code_challenge: p.code_challenge,
    code_challenge_method: "S256",
    resource: p.resource,
    scope: capsToScopes(p.caps),
  };
}

export const requestedColumns = (caps: Capability[]): Capability[] => CAPABILITIES.filter((c) => caps.includes(c));
