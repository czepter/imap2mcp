import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import type { H3Event } from "h3";
import { createRateLimiter } from "../../server/utils/rateLimit";
import { csrfEqual, isApiPath } from "../../server/utils/csrf";
import { SESSION_COOKIE, SESSION_MAX_AGE_S, newCsrfToken, sessionCookieOptions } from "../../server/utils/session";
import { buildSpaCsp, inlineScriptHashes, spaCspFor, DEFAULT_CSP } from "../../server/utils/securityHeaders";
import { isCorsPath } from "../../server/utils/cors";
import { renderError } from "../../server/error";

const ev = (ip: string, headers: Record<string, string> = {}) =>
  ({ node: { req: { socket: { remoteAddress: ip }, headers } } }) as unknown as H3Event;

describe("rate limiter (fixed window, per client)", () => {
  it("allows `max` hits, then limits with a Retry-After that counts down", () => {
    let t = 1_000_000;
    const rl = createRateLimiter({ windowMs: 60_000, max: 3, now: () => t });
    const a = ev("1.1.1.1");
    for (let i = 0; i < 3; i++) expect(rl.hit(a).limited).toBe(false);
    const r = rl.hit(a);
    expect(r).toEqual({ limited: true, retryAfter: 60 });
    t += 45_500;
    expect(rl.hit(a)).toEqual({ limited: true, retryAfter: 15 });
    expect(rl.hit(ev("2.2.2.2")).limited).toBe(false); // other callers are unaffected
  });

  it("starts a fresh window after windowMs and reset() forgets the caller", () => {
    let t = 0;
    const rl = createRateLimiter({ windowMs: 1000, max: 1, now: () => t });
    const a = ev("1.1.1.1");
    rl.hit(a);
    expect(rl.hit(a).limited).toBe(true);
    t += 1001;
    expect(rl.hit(a).limited).toBe(false);
    expect(rl.hit(a).limited).toBe(true);
    rl.reset(a);
    expect(rl.hit(a).limited).toBe(false);
  });

  it("uses the socket address (X-Forwarded-For is ignored unless BASE_URL is https) and honours a custom key", () => {
    const rl = createRateLimiter({ windowMs: 1000, max: 1 });
    rl.hit(ev("9.9.9.9", { "x-forwarded-for": "1.1.1.1" }));
    expect(rl.hit(ev("9.9.9.9", { "x-forwarded-for": "2.2.2.2" })).limited).toBe(true); // spoofing XFF does not help
    const byKey = createRateLimiter({ windowMs: 1000, max: 1, key: (e) => e.node.req.headers["x-k"] as string });
    byKey.hit(ev("a", { "x-k": "k1" }));
    expect(byKey.hit(ev("b", { "x-k": "k1" })).limited).toBe(true);
    expect(byKey.hit(ev("b", { "x-k": "k2" })).limited).toBe(false);
  });
});

describe("csrf helpers", () => {
  it("csrfEqual is exact and tolerates different lengths", () => {
    const t = newCsrfToken();
    expect(csrfEqual(t, t)).toBe(true);
    expect(csrfEqual(t, t.slice(0, -1))).toBe(false);
    expect(csrfEqual(t, t + "x")).toBe(false);
    expect(csrfEqual(t, "")).toBe(false);
    expect(csrfEqual("", "")).toBe(true);
  });
  it("tokens are 32 random bytes, base64url", () => {
    const a = newCsrfToken(), b = newCsrfToken();
    expect(a).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(Buffer.from(a, "base64url")).toHaveLength(32);
    expect(a).not.toBe(b);
  });
  it("only /api paths are CSRF scope", () => {
    expect(isApiPath("/api")).toBe(true);
    expect(isApiPath("/api/login")).toBe(true);
    expect(isApiPath("/apix")).toBe(false);
    expect(isApiPath("/oauth/token")).toBe(false);
  });
});

describe("session cookie flags", () => {
  it("httpOnly, SameSite=Lax, 24 h, name imap2mcp.sid; Secure iff https", () => {
    expect(SESSION_COOKIE).toBe("imap2mcp.sid");
    expect(SESSION_MAX_AGE_S).toBe(86400);
    expect(sessionCookieOptions(false)).toEqual({ httpOnly: true, sameSite: "lax", secure: false, path: "/", maxAge: 86400 });
    expect(sessionCookieOptions(true).secure).toBe(true);
  });
});

describe("CSP builder", () => {
  it("SPA CSP matches the contract and never allows unsafe-inline scripts", () => {
    const csp = buildSpaCsp(["sha256-AAA=", "sha256-BBB="]);
    expect(csp).toBe(
      "default-src 'none'; script-src 'self' 'sha256-AAA=' 'sha256-BBB='; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'",
    );
    expect(/script-src[^;]*unsafe-inline/.test(csp)).toBe(false);
    expect(csp).not.toMatch(/form-action/);
    expect(DEFAULT_CSP).toMatch(/^default-src 'none'/);
    expect(DEFAULT_CSP).not.toMatch(/form-action/);
  });

  it("hashes exactly the executable inline scripts (bootstrap, importmap), not src scripts or JSON data blocks", () => {
    const boot = 'window.__NUXT__={};window.__NUXT__.config={public:{},app:{baseURL:"/"}}';
    const map = '{"imports":{"#entry":"/_nuxt/entry.abc.js"}}';
    const html = `<!DOCTYPE html><html><head>
<script type="importmap">${map}</script>
<link rel="modulepreload" href="/_nuxt/entry.abc.js">
</head><body><div id="__nuxt"></div>
<script type="application/json" data-nuxt-data="nuxt-app" id="__NUXT_DATA__">[{"a":1}]</script>
<script>${boot}</script>
<script type="module" src="/_nuxt/entry.abc.js" crossorigin></script>
<script src='/x.js'></script>
</body></html>`;
    const h = (s: string) => "sha256-" + createHash("sha256").update(s).digest("base64");
    expect(inlineScriptHashes(html).sort()).toEqual([h(map), h(boot)].sort());
    expect(spaCspFor(html)).toContain(`'${h(boot)}'`);
    expect(spaCspFor(undefined)).toBe(buildSpaCsp());
  });
});

describe("CORS scope", () => {
  it("only the machine-facing paths", () => {
    for (const p of ["/mcp", "/oauth/token", "/oauth/register", "/oauth/revoke", "/.well-known/oauth-authorization-server", "/.well-known"]) expect(isCorsPath(p)).toBe(true);
    for (const p of ["/api/session", "/oauth/authorize", "/mcpx", "/", "/healthz"]) expect(isCorsPath(p)).toBe(false);
  });
});

describe("error rendering", () => {
  const boom = Object.assign(new Error("ENOENT /srv/secret/path at Object.foo (/app/x.js:1:1)"), { statusCode: 500 });
  it("/api: apiError shape, generic text for 5xx and for foreign 4xx", () => {
    const api = Object.assign(new Error("Wrong password. Try again."), { statusCode: 401, data: { code: "invalid_credentials" } });
    expect(JSON.parse(renderError(api, "/api/login").body)).toEqual({ error: { code: "invalid_credentials", message: "Wrong password. Try again." } });
    const v = renderError(boom, "/api/overview");
    expect(v.status).toBe(500);
    expect(JSON.parse(v.body)).toEqual({ error: { code: "internal", message: "Internal server error" } });
    expect(v.body).not.toMatch(/secret|ENOENT|\.js/);
    expect(JSON.parse(renderError({ statusCode: 404, message: "Cannot find any path matching /api/x." }, "/api/x").body))
      .toEqual({ error: { code: "not_found", message: "Not found" } });
  });
  it("protocol routes: OAuth-style JSON", () => {
    const e = { statusCode: 400, message: "x", data: { error: "invalid_grant", error_description: "bad code" } };
    expect(JSON.parse(renderError(e, "/oauth/token").body)).toEqual({ error: "invalid_grant", error_description: "bad code" });
    expect(JSON.parse(renderError(boom, "/mcp").body)).toEqual({ error: "server_error", error_description: "Internal server error" });
  });
  it("everything else: minimal plain text", () => {
    const v = renderError(boom, "/whatever");
    expect(v).toEqual({ status: 500, type: "text/plain; charset=utf-8", body: "Internal server error" });
  });
});
