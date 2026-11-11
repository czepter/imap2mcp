/**
 * Black-box acceptance tests for HTTP-level security and routing (docs/NUXT_MIGRATION.md "Runtime rules", "Security"):
 * security headers and CSP on the SPA, the admin API and the protocol endpoints; SPA index fallback; JSON 404s under /api;
 * CORS only on the machine-facing endpoints; HSTS only behind https; JSON error shapes that do not leak internals.
 */
import { createHash, randomBytes } from "node:crypto";
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { makeSelfSignedCert } from "../helpers/certs.js";
import { Browser, errorOf } from "../helpers/http.js";
import { createBare, type Bare } from "../helpers/stack.js";

const haveOpenssl = !!makeSelfSignedCert();

const directives = (csp: string): Map<string, string[]> =>
  new Map(csp.split(";").map((d) => d.trim()).filter(Boolean).map((d) => { const [name, ...vals] = d.split(/\s+/); return [name.toLowerCase(), vals] as const; }));

const assetsOf = (html: string): string[] => [...html.matchAll(/(?:src|href)="(\/_nuxt\/[^"?#]+)"/g)].map((m) => m[1]).sort();

/** Headers the contract wants on every response. */
function expectBaseHeaders(r: Response, what: string) {
  expect(r.headers.get("x-content-type-options"), `${what} nosniff`).toBe("nosniff");
  expect(r.headers.get("x-frame-options"), `${what} frame`).toBe("DENY");
  expect(r.headers.get("referrer-policy"), `${what} referrer`).toBe("no-referrer");
}

describe.skipIf(!haveOpenssl)("security headers, SPA routing, CORS", () => {
  let bare: Bare;
  let admin: Browser;
  let indexHtml = "";
  const url = (p: string) => bare.base + p;

  beforeAll(async () => {
    bare = await createBare();
    admin = new Browser(bare.base);
    const pw = "Admin-" + randomBytes(6).toString("hex");
    expect((await admin.postWithCsrf("/api/setup", { token: bare.bootstrap, password: pw, password2: pw })).status).toBe(204);
    indexHtml = await (await fetch(url("/"))).text();
  });
  afterAll(async () => { await bare?.teardown(); });

  describe("the SPA", () => {
    it("GET / serves the SPA index (200 HTML, not a redirect) with the full header set and CSP", async () => {
      const r = await fetch(url("/"), { redirect: "manual" });
      expect(r.status).toBe(200);
      expect(r.headers.get("content-type")).toMatch(/^text\/html/);
      expect(indexHtml).toMatch(/<div id="__nuxt"|id="__nuxt"/);
      expectBaseHeaders(r, "/");
      expect(r.headers.get("cache-control")).toMatch(/no-store/);
      expect(r.headers.get("strict-transport-security")).toBeNull(); // http deployment

      const csp = r.headers.get("content-security-policy") ?? "";
      expect(csp).toBeTruthy();
      const d = directives(csp);
      expect(d.get("default-src")).toEqual(["'none'"]);
      expect(d.get("style-src")).toEqual(["'self'", "'unsafe-inline'"]);
      expect(d.get("img-src")).toEqual(["'self'", "data:"]);
      expect(d.get("font-src")).toEqual(["'self'"]);
      expect(d.get("connect-src")).toEqual(["'self'"]);
      expect(d.get("base-uri")).toEqual(["'none'"]);
      expect(d.get("frame-ancestors")).toEqual(["'none'"]);
      expect(d.has("form-action"), "form-action would block the OAuth redirect after approval").toBe(false);
      const script = d.get("script-src") ?? [];
      expect(script[0]).toBe("'self'");
      expect(script, "script-src must not allow inline or eval").not.toContain("'unsafe-inline'");
      expect(script).not.toContain("'unsafe-eval'");
      expect(script).not.toContain("*");
      expect(script.some((v) => /^https?:/.test(v))).toBe(false);
    });

    it("every inline <script> of the SPA index is covered by a hash or nonce in script-src (never by unsafe-inline)", async () => {
      const csp = (await fetch(url("/"))).headers.get("content-security-policy") ?? "";
      const script = directives(csp).get("script-src") ?? [];
      const inline = [...indexHtml.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)].filter((m) => !/\bsrc=/.test(m[1]) && m[2].trim() !== "" && !/type="(application\/json|importmap|speculationrules)"/.test(m[1]));
      for (const m of inline) {
        const hash = `'sha256-${createHash("sha256").update(m[2]).digest("base64")}'`;
        const nonce = /\bnonce="([^"]+)"/.exec(m[1])?.[1];
        const covered = script.includes(hash) || (nonce !== undefined && script.includes(`'nonce-${nonce}'`));
        expect(covered, `inline script not allowed by CSP (${hash}): ${m[2].slice(0, 80)}`).toBe(true);
      }
      // inline event handlers and javascript: URLs cannot be covered by a script hash
      expect(indexHtml).not.toMatch(/\son[a-z]+\s*=\s*["']/i);
      expect(indexHtml).not.toMatch(/href\s*=\s*["']\s*javascript:/i);
    });

    it("the built assets referenced by the index are served with the right types and nosniff", async () => {
      const assets = [...indexHtml.matchAll(/(?:src|href)="(\/_nuxt\/[^"?#]+)"/g)].map((m) => m[1]);
      expect(assets.length, "index.html references no /_nuxt assets").toBeGreaterThan(0);
      for (const a of assets) {
        const r = await fetch(url(a));
        expect(r.status, a).toBe(200);
        expect(r.headers.get("x-content-type-options"), a).toBe("nosniff");
        if (a.endsWith(".js")) expect(r.headers.get("content-type"), a).toMatch(/javascript/);
        if (a.endsWith(".css")) expect(r.headers.get("content-type"), a).toMatch(/text\/css/);
        expect(r.headers.get("set-cookie"), a).toBeNull();
      }
    });

    it.each(["/dashboard", "/login", "/setup", "/mailboxes/new", "/mailboxes/abc-123", "/clients/00000000-0000-4000-8000-000000000000", "/audit", "/oauth/authorize", "/oauth/authorize?client_id=x&redirect_uri=http%3A%2F%2Flocalhost%3A1%2Fcb", "/some/unknown/deep/link", "/nope"])(
      "deep link %s falls back to the SPA index with the same security headers",
      async (p) => {
        const r = await fetch(url(p), { redirect: "manual" });
        expect(r.status, p).toBe(200);
        expect(r.headers.get("content-type"), p).toMatch(/^text\/html/);
        const body = await r.text();
        expect(body, p).toContain('id="__nuxt"');
        expect(assetsOf(body), p).toEqual(assetsOf(indexHtml)); // the same SPA shell, whatever the path
        expectBaseHeaders(r, p);
        expect(r.headers.get("cache-control"), p).toMatch(/no-store/);
        expect(r.headers.get("content-security-policy"), p).toMatch(/script-src 'self'/);
      },
    );

    it("the fallback is for GET only: other methods on SPA paths are errors, not the index", async () => {
      for (const method of ["POST", "PUT", "DELETE"]) {
        const r = await fetch(url("/dashboard"), { method });
        expect(r.status, method).toBeGreaterThanOrEqual(400);
        expect(await r.text()).not.toContain('id="__nuxt"');
      }
    });

    it("HEAD / works like GET without a body", async () => {
      const r = await fetch(url("/"), { method: "HEAD" });
      expect(r.status).toBe(200);
      expect(await r.text()).toBe("");
      expectBaseHeaders(r, "HEAD /");
    });
  });

  describe("the admin API", () => {
    it("unknown /api paths are JSON 404s (never the SPA index), signed in or not, with the base headers", async () => {
      for (const b of [new Browser(bare.base), admin]) {
        for (const p of ["/api/nope", "/api/nope/deeper", "/api/mailboxes/x/nope"]) {
          const r = await b.get(p);
          expect(r.status, p).toBe(404);
          expect(r.headers.get("content-type"), p).toMatch(/json/);
          const e = await errorOf(r);
          expect(e.code, p).toBeTruthy();
          expectBaseHeaders(r, p);
          expect(r.headers.get("cache-control"), p).toMatch(/no-store/);
        }
      }
      const post = await admin.postWithCsrf("/api/nope", {});
      expect(post.status).toBe(404);
      expect(post.headers.get("content-type")).toMatch(/json/);
    });

    it.each(["/api/", "/api"])("the bare API root %s is a JSON 404, not the SPA", async (p) => {
      const r = await admin.get(p);
      expect(r.status, p).toBe(404);
      expect(r.headers.get("content-type"), p).toMatch(/json/);
      expect((await errorOf(r)).code).toBeTruthy();
    });

    it.each([["PUT", "/api/session"], ["DELETE", "/api/overview"], ["GET", "/api/login"], ["GET", "/api/logout"], ["PATCH", "/api/setup"], ["POST", "/api/overview"]] as const)(
      "wrong method %s %s is a JSON error in the { error: { code, message } } shape, not HTML",
      async (method, p) => {
        const r = await admin.req(method, p, { json: method === "GET" ? undefined : {}, headers: { "x-csrf-token": await admin.csrf() } });
        expect([404, 405], `${method} ${p}`).toContain(r.status);
        expect(r.headers.get("content-type"), `${method} ${p}`).toMatch(/json/);
        expect((await errorOf(r)).code).toBeTruthy();
      },
    );

    it("API responses carry the base headers, no-store, and CSP default-src 'none'", async () => {
      for (const [b, p] of [[admin, "/api/session"], [admin, "/api/overview"], [new Browser(bare.base), "/api/overview"], [admin, "/api/audit"]] as const) {
        const r = await b.get(p);
        expectBaseHeaders(r, p);
        expect(r.headers.get("cache-control"), p).toMatch(/no-store/);
        expect(r.headers.get("content-type"), p).toMatch(/application\/json/);
        const csp = r.headers.get("content-security-policy") ?? "";
        expect(csp, p).toMatch(/^default-src 'none'/);
        expect(directives(csp).has("form-action"), p).toBe(false);
      }
      for (const p of ["/api/audit/export.jsonl", "/api/audit/export.csv"]) {
        const r = await admin.get(p);
        expectBaseHeaders(r, p);
        expect(r.headers.get("cache-control"), p).toMatch(/no-store/);
        expect(r.headers.get("x-content-type-options")).toBe("nosniff");
        await r.text();
      }
    });

    it("malformed bodies are 4xx JSON errors that leak no stack traces, paths or library names", async () => {
      const token = await admin.csrf();
      const send = (body: string, contentType = "application/json") => admin.req("POST", "/api/mailboxes", { body, contentType, headers: { "x-csrf-token": token } });
      const cases: Array<[string, Response]> = [
        ["invalid JSON", await send("{not json")],
        ["empty body", await send("")],
        ["JSON null", await send("null")],
        ["JSON array", await send("[1,2]")],
        ["JSON string", await send('"x"')],
        ["over 1 MB", await send(JSON.stringify({ label: "x".repeat(1_100_000) }))],
      ];
      for (const [name, r] of cases) {
        expect(r.status, name).toBeGreaterThanOrEqual(400);
        expect(r.status, name).toBeLessThan(500);
        expect(r.headers.get("content-type"), name).toMatch(/json/);
        const text = await r.text();
        expect(() => JSON.parse(text), name).not.toThrow();
        expect(JSON.parse(text).error?.code, name).toBeTruthy();
        expect(text, name).not.toMatch(/node_modules|\.ts:\d|\.mjs|\bat \w+ \(|h3|nitro|stack/i);
      }
      expect((await admin.get("/api/overview")).status).toBe(200); // the server is fine
    });
  });

  describe("protocol endpoints keep their strict headers", () => {
    it.each([
      ["GET", "/healthz"],
      ["GET", "/readyz"],
      ["GET", "/.well-known/oauth-authorization-server"],
      ["GET", "/.well-known/oauth-protected-resource"],
      ["POST", "/mcp"],
      ["POST", "/oauth/token"],
      ["POST", "/oauth/register"],
      ["POST", "/oauth/revoke"],
    ])("%s %s: base headers, no-store, default-src 'none', no session cookie", async (method, p) => {
      const r = await fetch(url(p), { method, headers: method === "POST" ? { "content-type": "application/json" } : {}, body: method === "POST" ? "{}" : undefined });
      await r.text();
      expectBaseHeaders(r, `${method} ${p}`);
      expect(r.headers.get("cache-control"), p).toMatch(/no-store/);
      expect(r.headers.get("content-security-policy") ?? "", p).toMatch(/^default-src 'none'/);
      expect(directives(r.headers.get("content-security-policy") ?? "").has("form-action"), p).toBe(false);
      expect(r.headers.get("set-cookie"), `${p} must not create a session`).toBeNull();
    });

    it("protocol paths are never answered with the SPA index", async () => {
      for (const [m, p] of [["GET", "/oauth/token"], ["GET", "/oauth/register"], ["GET", "/oauth/revoke"], ["GET", "/.well-known/nope"], ["GET", "/mcp/nope"]] as const) {
        const r = await fetch(url(p), { method: m, headers: { accept: "text/html" } });
        const text = await r.text();
        expect(r.status, p).toBeGreaterThanOrEqual(400);
        expect(text, p).not.toContain('id="__nuxt"');
      }
    });
  });

  describe("CORS", () => {
    const EVIL = "https://evil.example";
    it.each([
      ["POST", "/mcp"],
      ["POST", "/oauth/token"],
      ["POST", "/oauth/register"],
      ["POST", "/oauth/revoke"],
      ["GET", "/.well-known/oauth-authorization-server"],
      ["GET", "/.well-known/oauth-protected-resource"],
    ])("%s %s answers cross-origin requests, never with credentials", async (method, p) => {
      const r = await fetch(url(p), { method, headers: { origin: EVIL, "content-type": "application/json" }, body: method === "POST" ? "{}" : undefined });
      await r.text();
      const allow = r.headers.get("access-control-allow-origin");
      expect(allow === "*" || allow === EVIL, `${p} allow-origin=${allow}`).toBe(true);
      expect(r.headers.get("access-control-allow-credentials")).not.toBe("true");
    });

    it("preflights of the protocol endpoints succeed", async () => {
      for (const p of ["/mcp", "/oauth/token", "/oauth/register", "/oauth/revoke", "/.well-known/oauth-authorization-server"]) {
        const r = await fetch(url(p), { method: "OPTIONS", headers: { origin: EVIL, "access-control-request-method": "POST", "access-control-request-headers": "content-type,authorization" } });
        expect(r.status, p).toBeLessThan(300);
        expect(r.headers.get("access-control-allow-origin"), p).toBeTruthy();
        expect(r.headers.get("access-control-allow-credentials"), p).not.toBe("true");
      }
    });

    it("the admin API, the SPA and the health endpoints send no CORS headers, and preflights do not grant cross-origin access", async () => {
      for (const [m, p] of [["GET", "/api/session"], ["GET", "/api/overview"], ["POST", "/api/login"], ["GET", "/"], ["GET", "/dashboard"], ["GET", "/api/audit/export.csv"], ["GET", "/healthz"]] as const) {
        const r = await admin.req(m, p, { json: m === "POST" ? {} : undefined, headers: { origin: EVIL } });
        await r.text();
        expect(r.headers.get("access-control-allow-origin"), `${m} ${p}`).toBeNull();
        expect(r.headers.get("access-control-allow-credentials"), `${m} ${p}`).toBeNull();
      }
      for (const p of ["/api/session", "/api/login", "/api/mailboxes", "/api/oauth/authorize"]) {
        const r = await fetch(url(p), { method: "OPTIONS", headers: { origin: EVIL, "access-control-request-method": "POST", "access-control-request-headers": "content-type,x-csrf-token" } });
        expect(r.headers.get("access-control-allow-origin"), `OPTIONS ${p}`).toBeNull();
        expect(r.headers.get("access-control-allow-credentials"), `OPTIONS ${p}`).toBeNull();
      }
    });
  });
});

describe.skipIf(!haveOpenssl)("behind https (BASE_URL=https://...)", () => {
  let bare: Bare;
  beforeAll(async () => { bare = await createBare({ env: { BASE_URL: "https://bridge.example.test" } }); });
  afterAll(async () => { await bare?.teardown(); });

  it("HSTS is sent on the SPA, the API, protocol endpoints, assets and errors", async () => {
    const index = await (await fetch(`${bare.base}/`)).text();
    const asset = /(?:src|href)="(\/_nuxt\/[^"?#]+)"/.exec(index)?.[1];
    const paths = ["/", "/dashboard", "/api/session", "/api/nope", "/healthz", "/.well-known/oauth-authorization-server", ...(asset ? [asset] : [])];
    for (const p of paths) {
      const r = await fetch(`${bare.base}${p}`);
      await r.text();
      expect(r.headers.get("strict-transport-security"), p).toMatch(/max-age=\d{6,}/);
      expectBaseHeaders(r, p);
    }
  });
});
