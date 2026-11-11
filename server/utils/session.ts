import { randomBytes, randomUUID } from "node:crypto";
import { deleteCookie, getSession, updateSession, type H3Event, type SessionConfig } from "h3";
import { config } from "../core/config";

/** Contents of the sealed `imap2mcp.sid` cookie. */
export interface AdminSession { admin?: true; csrf?: string; returnTo?: string }

export const SESSION_COOKIE = "imap2mcp.sid";
export const SESSION_MAX_AGE_S = 24 * 60 * 60;

/** Cookie attributes of the session cookie (same as the old express-session setup). */
export function sessionCookieOptions(secure: boolean) {
  return { httpOnly: true, sameSite: "lax" as const, secure, path: "/", maxAge: SESSION_MAX_AGE_S };
}

/** h3 session config. Read lazily on every call: SESSION_SECRET(_FILE) and BASE_URL are never baked in at build time. */
export function sessionConfig(): SessionConfig {
  return {
    name: SESSION_COOKIE,
    password: config.sessionSecret,
    maxAge: SESSION_MAX_AGE_S,
    sessionHeader: false, // the session travels only in the cookie, never in a request header
    cookie: sessionCookieOptions(config.isHttps),
  };
}

/** 32 random bytes, base64url. */
export function newCsrfToken(): string {
  return randomBytes(32).toString("base64url");
}

/**
 * Sealed cookies are stateless, so a copy of a signed-in cookie would stay valid until it expires even after logout
 * or re-login. This in-memory set of retired *authenticated* session ids closes that (single process, like the SQLite
 * deployment); entries live exactly as long as the cookie could (24 h). A restart empties it, as it did the old
 * in-memory session store.
 */
const retired = new Map<string, number>();
const RETIRED_MAX = 10_000;

function retire(id: string, createdAt: number): void {
  const now = Date.now();
  for (const [k, exp] of retired) { if (exp <= now) retired.delete(k); else break; } // insertion order ~ expiry order
  retired.set(id, createdAt + SESSION_MAX_AGE_S * 1000);
  while (retired.size > RETIRED_MAX) retired.delete(retired.keys().next().value as string);
}

/** Test hook. */
export function isRetiredSession(id: string): boolean { return retired.has(id); }

interface Live { id: string; createdAt: number; data: AdminSession }

async function load(event: H3Event): Promise<Live> {
  const s = (await getSession<AdminSession>(event, sessionConfig())) as unknown as Live;
  if (retired.has(s.id)) { // a replayed copy of a logged-out / superseded cookie: behave like no session at all
    s.id = randomUUID();
    s.createdAt = Date.now();
    s.data = Object.create(null);
  }
  return s;
}

export async function getAdminSession(event: H3Event): Promise<AdminSession> {
  return { ...(await load(event)).data };
}

export async function updateAdminSession(event: H3Event, patch: Partial<AdminSession>): Promise<void> {
  await load(event);
  await updateSession<AdminSession>(event, sessionConfig(), patch);
}

/** Drop the session: the cookie is deleted and (if it was signed in) can never be used again. */
export async function clearAdminSession(event: H3Event): Promise<void> {
  const s = await load(event);
  if (s.data.admin === true) retire(s.id, s.createdAt);
  const sessions = event.context.sessions as Record<string, unknown> | undefined;
  if (sessions) delete sessions[SESSION_COOKIE];
  const { maxAge: _m, ...opts } = sessionCookieOptions(config.isHttps);
  deleteCookie(event, SESSION_COOKIE, opts);
}

/** Regenerate the session id (fixation defence): drops old contents, then applies `patch`. */
export async function regenerateAdminSession(event: H3Event, patch: Partial<AdminSession>): Promise<void> {
  const s = await load(event);
  if (s.data.admin === true) retire(s.id, s.createdAt);
  s.id = randomUUID();
  s.createdAt = Date.now();
  s.data = Object.create(null);
  await updateSession<AdminSession>(event, sessionConfig(), patch);
}

/** Per-session CSRF token, created on first use. */
export async function csrfToken(event: H3Event): Promise<string> {
  const s = await load(event);
  if (!s.data.csrf) await updateSession<AdminSession>(event, sessionConfig(), { csrf: newCsrfToken() });
  return s.data.csrf!;
}
