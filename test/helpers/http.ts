/**
 * Cookie-jar client for the admin JSON API (docs/NUXT_MIGRATION.md). Behaves like the SPA's fetch layer:
 * keeps the `imap2mcp.sid` cookie, reads the CSRF token from `GET /api/session` and sends it as `X-CSRF-Token`
 * together with `Content-Type: application/json` on every mutation. Redirects are never followed.
 *
 * Plain `post/put/patch/del` do NOT attach the CSRF header (used by the negative CSRF tests);
 * the `*WithCsrf` variants fetch a fresh token first.
 */
import type { SessionInfo } from "../../shared/types/api.js";

export type { SessionInfo };

export interface ReqOpts {
  /** JSON body (serialised). */
  json?: unknown;
  /** Raw body, sent as is (with `contentType`). */
  body?: string;
  /** Content-Type to send; `null` sends none. Default: application/json when a body is sent. */
  contentType?: string | null;
  headers?: Record<string, string>;
}

export class Browser {
  private jar = new Map<string, string>();
  constructor(public base: string) {}

  private cookieHeader(): string {
    return [...this.jar].map(([k, v]) => `${k}=${v}`).join("; ");
  }
  private store(res: Response) {
    for (const c of res.headers.getSetCookie?.() ?? []) {
      const [pair] = c.split(";");
      const i = pair.indexOf("=");
      const name = pair.slice(0, i).trim();
      const val = pair.slice(i + 1).trim();
      const expired = /;\s*expires=Thu, 01 Jan 1970/i.test(c) || /;\s*max-age=0\b/i.test(c) || /;\s*max-age=-\d+/i.test(c);
      if (expired || val === "") this.jar.delete(name);
      else this.jar.set(name, val);
    }
  }

  cookies(): string {
    return this.cookieHeader();
  }
  /** Replace the whole jar (used to replay a captured cookie, e.g. tampering tests). */
  setCookieHeader(header: string): void {
    this.jar.clear();
    for (const part of header.split(/;\s*/)) {
      const i = part.indexOf("=");
      if (i > 0) this.jar.set(part.slice(0, i), part.slice(i + 1));
    }
  }
  cookie(name: string): string | undefined {
    return this.jar.get(name);
  }

  async req(method: string, path: string, o: ReqOpts = {}): Promise<Response> {
    const h: Record<string, string> = { ...(o.headers ?? {}) };
    const ck = this.cookieHeader();
    if (ck) h.cookie = ck;
    let body: string | undefined;
    if (o.json !== undefined) body = JSON.stringify(o.json);
    else if (o.body !== undefined) body = o.body;
    const ct = o.contentType === undefined ? (body !== undefined ? "application/json" : null) : o.contentType;
    if (ct) h["content-type"] = ct;
    const res = await fetch(this.base + path, { method, headers: h, body, redirect: "manual" });
    this.store(res);
    return res;
  }

  get(path: string, headers?: Record<string, string>) {
    return this.req("GET", path, { headers });
  }
  post(path: string, json: unknown = {}, headers?: Record<string, string>) {
    return this.req("POST", path, { json, headers });
  }
  put(path: string, json: unknown = {}, headers?: Record<string, string>) {
    return this.req("PUT", path, { json, headers });
  }
  patch(path: string, json: unknown = {}, headers?: Record<string, string>) {
    return this.req("PATCH", path, { json, headers });
  }
  del(path: string, json: unknown = {}, headers?: Record<string, string>) {
    return this.req("DELETE", path, { json, headers });
  }

  /** `GET /api/session` as parsed JSON (also what the SPA's auth middleware calls). */
  async session(): Promise<SessionInfo> {
    const r = await this.get("/api/session");
    if (r.status !== 200) throw new Error(`GET /api/session -> ${r.status}: ${await r.text()}`);
    return (await r.json()) as SessionInfo;
  }
  /** This session's CSRF token (always read fresh: login/setup rotate it). */
  async csrf(): Promise<string> {
    return (await this.session()).csrfToken;
  }
  /** Mutation with a fresh `X-CSRF-Token` and a JSON body. */
  async withCsrf(method: string, path: string, json: unknown = {}, headers: Record<string, string> = {}): Promise<Response> {
    const token = await this.csrf();
    return this.req(method, path, { json, headers: { "x-csrf-token": token, ...headers } });
  }
  postWithCsrf(path: string, json: unknown = {}) {
    return this.withCsrf("POST", path, json);
  }
  putWithCsrf(path: string, json: unknown = {}) {
    return this.withCsrf("PUT", path, json);
  }
  patchWithCsrf(path: string, json: unknown = {}) {
    return this.withCsrf("PATCH", path, json);
  }
  delWithCsrf(path: string, json: unknown = {}) {
    return this.withCsrf("DELETE", path, json);
  }
}

/** The `Location` header of a redirect response (the JSON API never redirects; used for protocol endpoints). */
export function location(res: Response): string {
  const l = res.headers.get("location");
  if (!l) throw new Error(`expected redirect, got ${res.status}`);
  return l;
}

/** Parse a JSON response body, failing with the raw text for diagnosis. */
export async function json<T = any>(res: Response): Promise<T> {
  const t = await res.text();
  try {
    return JSON.parse(t) as T;
  } catch {
    throw new Error(`expected JSON (status ${res.status}), got: ${t.slice(0, 300)}`);
  }
}

/** Asserts-friendly view of an admin-API error body: `{ error: { code, message } }`. */
export async function errorOf(res: Response): Promise<{ code: string; message: string }> {
  const b = await json<{ error?: { code?: string; message?: string } }>(res);
  if (!b.error || typeof b.error.code !== "string" || typeof b.error.message !== "string") {
    throw new Error(`not an API error body (status ${res.status}): ${JSON.stringify(b).slice(0, 300)}`);
  }
  return { code: b.error.code, message: b.error.message };
}
