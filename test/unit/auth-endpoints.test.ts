import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { createServer, type Server } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";

/** Real h3 app (createApp + toNodeListener) wired exactly like Nitro does: middleware in file order, then the handlers. */
async function boot(env: Record<string, string>) {
  const dir = mkdtempSync(join(tmpdir(), "auth-ep-"));
  const saved = { ...process.env };
  Object.assign(process.env, { SESSION_SECRET: randomBytes(32).toString("hex"), DATA_DIR: join(dir, "data"), BASE_URL: "http://localhost:3000" }, env);
  delete process.env.SESSION_SECRET_FILE;
  vi.resetModules();
  const h3 = await import("h3");
  const { default: errorHandler } = await import("../../server/error");
  const m = [
    (await import("../../server/middleware/00.request-id")).default,
    (await import("../../server/middleware/01.security-headers")).default,
    (await import("../../server/middleware/02.cors")).default,
    (await import("../../server/middleware/03.csrf")).default,
  ];
  const api = {
    session: (await import("../../server/api/session.get")).default,
    setup: (await import("../../server/api/setup.post")).default,
    login: (await import("../../server/api/login.post")).default,
    logout: (await import("../../server/api/logout.post")).default,
  };
  const { requireAdmin } = await import("../../server/utils/requireAdmin");
  const { initBootstrap } = await import("../../server/utils/bootstrap");
  const { closeDb } = await import("../../server/core/db/database");
  const { setLogSink } = await import("../../server/core/log");
  const { readJsonBody } = await import("../../server/utils/readJson");

  const app = h3.createApp({ onError: (e, event) => errorHandler(e as never, event, { defaultHandler: undefined as never }) });
  for (const mw of m) app.use(mw);
  const router = h3.createRouter();
  router.get("/api/session", api.session);
  router.post("/api/setup", api.setup);
  router.post("/api/login", api.login);
  router.post("/api/logout", api.logout);
  router.get("/api/probe", h3.defineEventHandler(async (event) => { await requireAdmin(event); return { ok: true }; }));
  router.post("/api/echo", h3.defineEventHandler(async (event) => readJsonBody(event)));
  router.get("/api/boom", h3.defineEventHandler(() => { throw new Error("db password=hunter2 at /srv/app.js:1"); }));
  router.post("/oauth/token", h3.defineEventHandler(() => ({ ok: true })));
  router.get("/oauth/fail", h3.defineEventHandler(() => { throw h3.createError({ statusCode: 400, data: { error: "invalid_grant", error_description: "nope" } }); }));
  app.use(router);
  const server: Server = createServer(h3.toNodeListener(app));
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;

  const lines: string[] = [];
  setLogSink((l) => lines.push(l));
  const stdout: string[] = [];
  const spy = vi.spyOn(process.stdout, "write").mockImplementation(((c: string | Uint8Array) => { stdout.push(String(c)); return true; }) as never);

  return {
    base, lines, stdout, initBootstrap,
    async stop() {
      spy.mockRestore(); setLogSink(null);
      await new Promise((r) => server.close(r)); server.closeAllConnections();
      closeDb(); rmSync(dir, { recursive: true, force: true });
      for (const k of Object.keys(process.env)) if (!(k in saved)) delete process.env[k];
      Object.assign(process.env, saved);
    },
  };
}

class Client {
  jar = new Map<string, string>();
  csrf = "";
  constructor(public base: string) {}
  last: Response | undefined;
  async req(method: string, path: string, opts: { body?: unknown; csrf?: string | null; headers?: Record<string, string>; raw?: string; cookie?: string } = {}) {
    const headers: Record<string, string> = { ...(opts.headers ?? {}) };
    const cookie = opts.cookie ?? [...this.jar].map(([k, v]) => `${k}=${v}`).join("; ");
    if (cookie) headers.cookie = cookie;
    if (method !== "GET" && method !== "OPTIONS") {
      if (!("content-type" in headers)) headers["content-type"] = "application/json";
      const t = opts.csrf === undefined ? this.csrf : opts.csrf;
      if (t) headers["x-csrf-token"] = t;
    }
    const res = await fetch(this.base + path, { method, headers, body: opts.raw ?? (opts.body === undefined ? undefined : JSON.stringify(opts.body)) });
    for (const c of res.headers.getSetCookie()) {
      const [pair] = c.split(";");
      const i = pair!.indexOf("=");
      const name = pair!.slice(0, i), val = pair!.slice(i + 1);
      if (!val || /max-age=0/i.test(c)) this.jar.delete(name); else this.jar.set(name, val);
    }
    this.last = res;
    return res;
  }
  async session() {
    const r = await this.req("GET", "/api/session");
    const j = await r.json() as { csrfToken: string; authenticated: boolean; setupRequired: boolean; registrationMode: string; baseUrl: string };
    this.csrf = j.csrfToken;
    return j;
  }
}
const err = async (r: Response) => ((await r.json()) as { error: { code: string; message: string } }).error;

describe("admin auth over h3 (setup, login, logout, CSRF, headers)", () => {
  let t: Awaited<ReturnType<typeof boot>>;
  const TOKEN = "bootstrap-" + randomBytes(8).toString("hex");
  const PW = "Correct-Horse-" + randomBytes(4).toString("hex");
  beforeAll(async () => { t = await boot({ ADMIN_BOOTSTRAP_TOKEN: TOKEN }); });
  afterAll(async () => { await t.stop(); });

  it("GET /api/session before setup: setupRequired, fresh csrf token, cookie flags, security headers, request id", async () => {
    const c = new Client(t.base);
    const r = await c.req("GET", "/api/session", { headers: { "x-request-id": "my-request-id-1234" } });
    const j = await r.json() as Record<string, unknown>;
    expect(j).toMatchObject({ setupRequired: true, authenticated: false, registrationMode: "dynamic", baseUrl: "http://localhost:3000" });
    expect(j.csrfToken).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const cookie = r.headers.getSetCookie().find((x) => x.startsWith("imap2mcp.sid="))!;
    expect(cookie).toMatch(/HttpOnly/i);
    expect(cookie).toMatch(/SameSite=Lax/i);
    expect(cookie).toMatch(/Max-Age=86400/i);
    expect(cookie).toMatch(/Path=\//);
    expect(cookie).not.toMatch(/Secure/i); // http BASE_URL
    expect(r.headers.get("x-request-id")).toBe("my-request-id-1234");
    expect(r.headers.get("x-content-type-options")).toBe("nosniff");
    expect(r.headers.get("x-frame-options")).toBe("DENY");
    expect(r.headers.get("referrer-policy")).toBe("no-referrer");
    expect(r.headers.get("cache-control")).toBe("no-store");
    expect(r.headers.get("content-security-policy")).toMatch(/^default-src 'none'/);
    expect(r.headers.get("strict-transport-security")).toBeNull();
    expect(r.headers.get("access-control-allow-origin")).toBeNull();
    // an invalid incoming id is replaced
    const r2 = await c.req("GET", "/api/session", { headers: { "x-request-id": "bad id!" } });
    expect(r2.headers.get("x-request-id")).toMatch(/^[0-9a-f-]{36}$/);
    // the same token is returned while the session lives
    expect((await c.session()).csrfToken).toBe(j.csrfToken);
  });

  it("CSRF: non-GET under /api needs X-CSRF-Token and application/json; GET and non-/api are exempt", async () => {
    const c = new Client(t.base);
    await c.session();
    for (const csrf of [null, "wrong", c.csrf + "x"]) {
      const r = await c.req("POST", "/api/login", { body: { password: "x" }, csrf });
      expect(r.status).toBe(403);
      expect(await err(r)).toEqual({ code: "csrf", message: "Invalid or missing CSRF token" });
    }
    const wrongType = await c.req("POST", "/api/login", { body: { password: "x" }, headers: { "content-type": "application/x-www-form-urlencoded" } });
    expect(wrongType.status).toBe(403);
    expect((await err(wrongType)).code).toBe("csrf");
    expect((await c.req("POST", "/api/logout", { csrf: null })).status).toBe(403);
    const noSession = new Client(t.base);
    expect((await noSession.req("POST", "/api/login", { body: {}, csrf: "anything" })).status).toBe(403);
    expect((await c.req("POST", "/api/login", { body: { password: "x" }, headers: { "content-type": "Application/JSON; charset=utf-8" } })).status).not.toBe(403);
    expect((await c.req("POST", "/oauth/token", { csrf: null, headers: { "content-type": "application/x-www-form-urlencoded" } })).status).toBe(200); // protocol endpoint: no CSRF
  });

  it("setup is 404 until the bootstrap token was issued; initBootstrap prints the banner and the log line", async () => {
    const c = new Client(t.base);
    await c.session();
    const r = await c.req("POST", "/api/setup", { body: { token: TOKEN, password: PW, password2: PW } });
    expect(r.status).toBe(404);
    t.initBootstrap();
    expect(t.stdout.join("")).toContain(TOKEN);
    expect(t.stdout.join("")).toContain("First run: no admin configured.");
    expect(t.stdout.join("")).toContain("http://localhost:3000/setup");
    const logged = t.lines.join("\n");
    expect(logged).toContain("first run: no admin configured; setup code printed to stdout");
    expect(logged).not.toContain(TOKEN);
  });

  it("setup validates token, then password rules, then creates the admin and signs in with a rotated session", async () => {
    const c = new Client(t.base);
    await c.session();
    const preCookie = c.jar.get("imap2mcp.sid");
    const preCsrf = c.csrf;
    let r = await c.req("POST", "/api/setup", { body: { token: "nope", password: PW, password2: PW } });
    expect(r.status).toBe(403);
    expect(await err(r)).toMatchObject({ message: "Invalid bootstrap token" });
    r = await c.req("POST", "/api/setup", { body: { password: PW, password2: PW } });
    expect(r.status).toBe(403);
    r = await c.req("POST", "/api/setup", { body: { token: TOKEN, password: "short", password2: "short" } });
    expect(r.status).toBe(400);
    expect(await err(r)).toMatchObject({ message: "Password must be at least 12 characters" });
    r = await c.req("POST", "/api/setup", { body: { token: TOKEN, password: PW, password2: PW + "x" } });
    expect(r.status).toBe(400);
    expect(await err(r)).toMatchObject({ message: "Passwords do not match" });
    r = await c.req("POST", "/api/setup", { raw: "[1]" });
    expect(r.status).toBe(400);

    r = await c.req("POST", "/api/setup", { body: { token: TOKEN, password: PW, password2: PW } });
    expect(r.status).toBe(204);
    expect(await r.text()).toBe("");
    const newCsrf = r.headers.get("x-csrf-token")!;
    expect(newCsrf).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(newCsrf).not.toBe(preCsrf);
    expect(c.jar.get("imap2mcp.sid")).not.toBe(preCookie);
    c.csrf = newCsrf;
    const s = await c.session();
    expect(s).toMatchObject({ setupRequired: false, authenticated: true, csrfToken: newCsrf });
    // the pre-login cookie does not carry the signed-in state, and setup is gone for good
    expect((await new Client(t.base).req("GET", "/api/session", { cookie: `imap2mcp.sid=${preCookie}` }).then((x) => x.json()) as { authenticated: boolean }).authenticated).toBe(false);
    r = await c.req("POST", "/api/setup", { body: { token: TOKEN, password: PW, password2: PW } });
    expect(r.status).toBe(404);
  });

  it("requireAdmin: 401 without a signed-in session, 200 with one", async () => {
    const c = new Client(t.base);
    await c.session();
    const r = await c.req("GET", "/api/probe");
    expect(r.status).toBe(401);
    expect(await err(r)).toEqual({ code: "unauthorized", message: "Authentication required" });
  });

  it("login: wrong password 401, right password 204 + new session; logout kills the cookie server-side (replay is rejected)", async () => {
    const c = new Client(t.base);
    await c.session();
    const anonCookie = c.jar.get("imap2mcp.sid");
    let r = await c.req("POST", "/api/login", { body: { password: "wrong-password-123" } });
    expect(r.status).toBe(401);
    expect(await err(r)).toEqual({ code: "invalid_credentials", message: "Wrong password. Try again." });
    r = await c.req("POST", "/api/login", { body: {} });
    expect(r.status).toBe(401);
    r = await c.req("POST", "/api/login", { body: { password: "x".repeat(2000) } });
    expect(r.status).toBe(401);

    r = await c.req("POST", "/api/login", { body: { password: PW } });
    expect(r.status).toBe(204);
    c.csrf = r.headers.get("x-csrf-token")!;
    const signed = c.jar.get("imap2mcp.sid")!;
    expect(signed).not.toBe(anonCookie);
    expect((await c.req("GET", "/api/probe")).status).toBe(200);
    expect((await c.session()).authenticated).toBe(true);

    r = await c.req("POST", "/api/logout");
    expect(r.status).toBe(204);
    expect(r.headers.getSetCookie().join("\n")).toMatch(/imap2mcp\.sid=;.*(Max-Age=0|Expires=Thu, 01 Jan 1970)/i);
    expect(c.jar.has("imap2mcp.sid")).toBe(false);
    // replaying the old signed-in cookie must not work, even though it still decrypts
    const thief = new Client(t.base);
    const rep = await thief.req("GET", "/api/probe", { cookie: `imap2mcp.sid=${signed}` });
    expect(rep.status).toBe(401);
    expect((await thief.req("GET", "/api/session", { cookie: `imap2mcp.sid=${signed}` }).then((x) => x.json()) as { authenticated: boolean }).authenticated).toBe(false);
  });

  it("re-login regenerates the session: the previous signed-in cookie is dead (fixation / replay defence)", async () => {
    const c = new Client(t.base);
    await c.session();
    let r = await c.req("POST", "/api/login", { body: { password: PW } });
    c.csrf = r.headers.get("x-csrf-token")!;
    const first = c.jar.get("imap2mcp.sid")!;
    r = await c.req("POST", "/api/login", { body: { password: PW } });
    expect(r.status).toBe(204);
    const second = c.jar.get("imap2mcp.sid")!;
    expect(second).not.toBe(first);
    expect((await new Client(t.base).req("GET", "/api/probe", { cookie: `imap2mcp.sid=${first}` })).status).toBe(401);
    expect((await new Client(t.base).req("GET", "/api/probe", { cookie: `imap2mcp.sid=${second}` })).status).toBe(200);
  });

  it("a tampered cookie is just no session", async () => {
    const c = new Client(t.base);
    const r = await c.req("GET", "/api/session", { cookie: "imap2mcp.sid=Fe26.2**garbage" });
    expect((await r.json() as { authenticated: boolean }).authenticated).toBe(false);
  });

  it("readJsonBody: object only, 1 MB cap", async () => {
    const c = new Client(t.base);
    await c.session();
    expect(await (await c.req("POST", "/api/echo", { body: { a: 1 } })).json()).toEqual({ a: 1 });
    for (const raw of ["[1]", "null", "7", '"s"', "{nope", ""]) {
      const r = await c.req("POST", "/api/echo", { raw });
      expect(r.status, raw).toBe(400);
      expect((await err(r)).code).toBe("bad_request");
    }
    const big = await c.req("POST", "/api/echo", { raw: JSON.stringify({ pad: "x".repeat(1024 * 1024) }) });
    expect(big.status).toBe(400);
  });

  it("CORS only on the machine endpoints, never with credentials; preflight answered with 204", async () => {
    const c = new Client(t.base);
    let r = await c.req("OPTIONS", "/oauth/token", { headers: { origin: "https://app.example", "access-control-request-method": "POST", "access-control-request-headers": "authorization,content-type" } });
    expect(r.status).toBe(204);
    expect(r.headers.get("access-control-allow-origin")).toBe("https://app.example");
    expect(r.headers.get("access-control-allow-methods")).toBe("GET,HEAD,PUT,PATCH,POST,DELETE");
    expect(r.headers.get("access-control-allow-headers")).toBe("authorization,content-type");
    expect(r.headers.get("access-control-allow-credentials")).toBeNull();
    expect(r.headers.get("vary")).toMatch(/Origin/);
    r = await c.req("POST", "/oauth/token", { csrf: null, headers: { origin: "https://app.example" } });
    expect(r.headers.get("access-control-allow-origin")).toBe("https://app.example");
    expect(r.headers.get("access-control-allow-credentials")).toBeNull();
    r = await c.req("GET", "/api/session", { headers: { origin: "https://evil.example" } });
    expect(r.headers.get("access-control-allow-origin")).toBeNull();
    r = await c.req("OPTIONS", "/api/login", { headers: { origin: "https://evil.example", "access-control-request-method": "POST" } });
    expect(r.headers.get("access-control-allow-origin")).toBeNull();
    expect(r.status).not.toBe(204);
  });

  it("errors: no stack/internals for 500, OAuth-style JSON on protocol routes, security headers survive", async () => {
    const c = new Client(t.base);
    let r = await c.req("GET", "/api/boom");
    expect(r.status).toBe(500);
    const text = await r.text();
    expect(JSON.parse(text)).toEqual({ error: { code: "internal", message: "Internal server error" } });
    expect(text).not.toMatch(/hunter2|srv|\.js|at /);
    expect(r.headers.get("x-content-type-options")).toBe("nosniff");
    expect(r.headers.get("content-type")).toMatch(/application\/json/);
    expect(t.lines.join("\n")).not.toContain("hunter2"); // redacted in the log
    expect(t.lines.join("\n")).toContain("request failed");
    r = await c.req("GET", "/api/does-not-exist");
    expect(r.status).toBe(404);
    expect(await err(r)).toEqual({ code: "not_found", message: "Not found" });
    r = await c.req("GET", "/oauth/fail");
    expect(r.status).toBe(400);
    expect(await r.json()).toEqual({ error: "invalid_grant", error_description: "nope" });
    r = await c.req("GET", "/some/page");
    expect(r.status).toBe(404);
    expect(r.headers.get("content-type")).toMatch(/text\/plain/);
  });

  it("login is rate limited (10 attempts / 15 min), Retry-After is set, and the right password is refused while limited", async () => {
    const c = new Client(t.base);
    await c.session();
    // earlier tests used several attempts from this IP; keep failing until limited
    let limited: Response | undefined;
    for (let i = 0; i < 12 && !limited; i++) {
      const r = await c.req("POST", "/api/login", { body: { password: "wrong-password-123" } });
      if (r.status === 429) limited = r;
    }
    expect(limited).toBeDefined();
    expect(limited!.headers.get("retry-after")).toMatch(/^\d+$/);
    expect(await err(limited!)).toEqual({ code: "too_many_requests", message: "Too many attempts, try again later" });
    // even the right password is refused while limited (same as the old limiter, which ran before the handler)
    expect((await c.req("POST", "/api/login", { body: { password: PW } })).status).toBe(429);
  });
});

describe("https BASE_URL", () => {
  let t: Awaited<ReturnType<typeof boot>>;
  beforeAll(async () => { t = await boot({ BASE_URL: "https://bridge.example.com/" }); });
  afterAll(async () => { await t.stop(); });

  it("Secure cookie, HSTS, X-Forwarded-For trusted for exactly one hop", async () => {
    const c = new Client(t.base);
    const r = await c.req("GET", "/api/session");
    expect(r.headers.getSetCookie().find((x) => x.startsWith("imap2mcp.sid="))).toMatch(/; Secure/i);
    expect(r.headers.get("strict-transport-security")).toBe("max-age=31536000");
    expect((await r.json() as { baseUrl: string }).baseUrl).toBe("https://bridge.example.com");
    const { clientIp } = await import("../../server/utils/rateLimit");
    const ev = (xff?: string) => ({ node: { req: { socket: { remoteAddress: "10.0.0.1" }, headers: xff ? { "x-forwarded-for": xff } : {} } } }) as never;
    expect(clientIp(ev("6.6.6.6, 203.0.113.9"))).toBe("203.0.113.9"); // last entry = what the one trusted proxy saw
    expect(clientIp(ev())).toBe("10.0.0.1");
  });
});
