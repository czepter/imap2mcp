/**
 * Black-box acceptance tests for the admin session API (docs/NUXT_MIGRATION.md "Admin JSON API", "Security"):
 * GET /api/session, POST /api/setup, /api/login, /api/logout; CSRF contract; cookie flags; rate limits;
 * 401 on every protected endpoint without a session. Written from the contract, not the implementation.
 */
import { describe, it, expect, afterAll } from "vitest";
import { randomBytes } from "node:crypto";
import { makeSelfSignedCert } from "../helpers/certs.js";
import { Browser, errorOf } from "../helpers/http.js";
import { bootstrapTokenFrom } from "../helpers/server.js";
import { adminLogin, createBare, createStack, waitFor, type Bare, type Stack } from "../helpers/stack.js";

const haveOpenssl = !!makeSelfSignedCert();
const strongPw = () => "Correct-Horse-" + randomBytes(5).toString("hex");

describe.skipIf(!haveOpenssl)("session, setup, login, logout lifecycle", () => {
  let bare: Bare;
  const pw = strongPw();
  let preSetupCookie = "";
  let preSetupCsrf = "";
  const admin = () => new Browser(bare.base);

  afterAll(async () => { await bare?.teardown(); });

  it("before setup: session says setupRequired, anonymous, with a CSRF token, registration mode and base URL", async () => {
    bare = await createBare();
    const b = admin();
    const r = await b.get("/api/session");
    expect(r.status).toBe(200);
    expect(r.headers.get("content-type")).toMatch(/application\/json/);
    expect(r.headers.get("cache-control")).toMatch(/no-store/);
    const body = (await r.json()) as any;
    expect(body).toEqual({ setupRequired: true, authenticated: false, csrfToken: expect.any(String), registrationMode: "dynamic", baseUrl: bare.base });
    expect(body.csrfToken.length).toBeGreaterThanOrEqual(20);
    // the token belongs to the session cookie that came with the response
    expect(b.cookie("imap2mcp.sid")).toBeTruthy();
    preSetupCookie = b.cookies();
    preSetupCsrf = body.csrfToken;
  });

  it("the CSRF token is stable within a session and differs between sessions", async () => {
    const b = admin();
    const t1 = await b.csrf();
    const t2 = await b.csrf();
    expect(t2).toBe(t1);
    expect(await admin().csrf()).not.toBe(t1);
  });

  it("the bootstrap token is printed once to stdout and never appears in any API response", async () => {
    expect(await waitFor(() => bootstrapTokenFrom(bare.srv.output()))).toBe(bare.bootstrap);
    const b = admin();
    for (const p of ["/api/session", "/api/overview"]) expect(await (await b.get(p)).text()).not.toContain(bare.bootstrap);
  });

  it("before setup nothing is reachable and login cannot succeed", async () => {
    const b = admin();
    for (const p of ["/api/overview", "/api/audit", "/api/mailboxes/x", "/api/clients/x"]) expect((await b.get(p)).status, p).toBe(401);
    const r = await adminLogin(b, "anything-at-all-123");
    expect(r.status).toBeGreaterThanOrEqual(400);
    expect(r.status).toBeLessThan(500);
    expect((await b.session()).authenticated).toBe(false);
  });

  it("setup refuses a missing/wrong CSRF token and non-JSON content types before looking at the body", async () => {
    const b = admin();
    const token = await b.csrf();
    const good = { token: bare.bootstrap, password: pw, password2: pw };
    const noHeader = await b.post("/api/setup", good);
    expect(noHeader.status).toBe(403);
    expect((await errorOf(noHeader)).code).toBe("csrf");
    expect((await b.post("/api/setup", good, { "x-csrf-token": "A".repeat(43) })).status).toBe(403);
    const form = await b.req("POST", "/api/setup", { body: new URLSearchParams(good).toString(), contentType: "application/x-www-form-urlencoded", headers: { "x-csrf-token": token } });
    expect(form.status).toBe(403);
    expect((await errorOf(form)).code).toBe("csrf");
    const plain = await b.req("POST", "/api/setup", { body: JSON.stringify(good), contentType: "text/plain", headers: { "x-csrf-token": token } });
    expect(plain.status).toBe(403);
    const noType = await b.req("POST", "/api/setup", { body: JSON.stringify(good), contentType: null, headers: { "x-csrf-token": token } });
    expect(noType.status).toBe(403);
    expect((await b.session()).setupRequired).toBe(true); // nothing was created
  });

  it("setup validates token and passwords with the human messages the old UI showed", async () => {
    const b = admin();
    const wrong = await b.postWithCsrf("/api/setup", { token: "wrong-token", password: pw, password2: pw });
    expect(wrong.status).toBe(403);
    expect((await errorOf(wrong)).message).toBe("Invalid bootstrap token");
    const missing = await b.postWithCsrf("/api/setup", { password: pw, password2: pw });
    expect(missing.status).toBe(403);
    const short = await b.postWithCsrf("/api/setup", { token: bare.bootstrap, password: "short", password2: "short" });
    expect(short.status).toBe(400);
    expect((await errorOf(short)).message).toBe("Password must be at least 12 characters");
    const mismatch = await b.postWithCsrf("/api/setup", { token: bare.bootstrap, password: pw, password2: pw + "x" });
    expect(mismatch.status).toBe(400);
    expect((await errorOf(mismatch)).message).toBe("Passwords do not match");
    const notAnObject = await b.withCsrf("POST", "/api/setup", [1, 2, 3]);
    expect(notAnObject.status).toBeGreaterThanOrEqual(400);
    expect(notAnObject.status).toBeLessThan(500);
    expect(await b.session()).toMatchObject({ setupRequired: true, authenticated: false });
  });

  it("a good setup answers 204, signs in, rotates the CSRF token and does not elevate the pre-setup cookie", async () => {
    await bare.restart(); // fresh rate-limit budget (the limiter is in memory); cookies and data survive
    const b = admin();
    const before = await b.csrf();
    const r = await b.postWithCsrf("/api/setup", { token: bare.bootstrap, password: pw, password2: pw });
    expect(r.status).toBe(204);
    const s = await b.session();
    expect(s).toMatchObject({ setupRequired: false, authenticated: true });
    expect(s.csrfToken).not.toBe(before); // session regenerated: nothing from the anonymous session survives
    expect((await b.get("/api/overview")).status).toBe(200);
    // fixation: a cookie that existed before setup is still anonymous
    const old = admin();
    old.setCookieHeader(preSetupCookie);
    expect(await old.session()).toMatchObject({ setupRequired: false, authenticated: false });
    expect((await old.get("/api/overview")).status).toBe(401);
    expect(preSetupCsrf).toBeTruthy();
  });

  it("afterwards /api/setup is 404 forever, even with the right token and a valid CSRF token", async () => {
    const b = admin();
    const attacker = "Attacker-" + randomBytes(5).toString("hex");
    const r = await b.postWithCsrf("/api/setup", { token: bare.bootstrap, password: attacker, password2: attacker });
    expect(r.status).toBe(404);
    expect((await adminLogin(admin(), attacker)).status).toBe(401);
    expect((await adminLogin(admin(), pw)).status).toBe(204);
  });

  it("login: wrong password is 401 with a JSON error and leaves the session anonymous", async () => {
    await bare.restart(); // fresh rate-limit budget
    const b = admin();
    const r = await adminLogin(b, "definitely-wrong-" + randomBytes(3).toString("hex"));
    expect(r.status).toBe(401);
    const e = await errorOf(r);
    expect(e.code).toBeTruthy();
    expect(e.message.length).toBeGreaterThan(0);
    expect(e.message).not.toContain("definitely-wrong");
    expect(await b.session()).toMatchObject({ authenticated: false, setupRequired: false });
    expect((await b.get("/api/overview")).status).toBe(401);
    // malformed bodies are 4xx, never 5xx
    for (const body of [{}, { password: 5 }, { password: "x".repeat(5000) }, { password: null }]) {
      const m = await b.postWithCsrf("/api/login", body);
      expect(m.status, JSON.stringify(body).slice(0, 40)).toBeGreaterThanOrEqual(400);
      expect(m.status, JSON.stringify(body).slice(0, 40)).toBeLessThan(500);
    }
  });

  it("login: right password is 204, rotates the CSRF token, and the session cookie works for the whole API", async () => {
    const b = admin();
    const before = await b.csrf();
    const r = await adminLogin(b, pw);
    expect(r.status).toBe(204);
    expect(await r.text()).toBe("");
    const s = await b.session();
    expect(s).toMatchObject({ authenticated: true, setupRequired: false });
    expect(s.csrfToken).not.toBe(before);
    expect((await b.get("/api/overview")).status).toBe(200);
  });

  it("logout needs the CSRF token; with it: 204 and the browser session is anonymous again", async () => {
    const b = admin();
    await adminLogin(b, pw);
    const refused = await b.post("/api/logout");
    expect(refused.status).toBe(403);
    expect((await b.get("/api/overview")).status).toBe(200); // still signed in
    const r = await b.postWithCsrf("/api/logout");
    expect(r.status).toBe(204);
    expect((await b.get("/api/overview")).status).toBe(401);
    expect(await b.session()).toMatchObject({ authenticated: false });
  });

  it("a tampered session cookie is just an anonymous session (no 5xx, no elevation)", async () => {
    const b = admin();
    await adminLogin(b, pw);
    const sid = b.cookie("imap2mcp.sid")!;
    expect(sid.length).toBeGreaterThan(20);
    const flipped = sid.slice(0, -4) + (sid.endsWith("AAAA") ? "BBBB" : "AAAA");
    for (const v of [flipped, sid.slice(0, sid.length >> 1), "garbage", "", "Fe26.2**" + "a".repeat(80)]) {
      const t = admin();
      t.setCookieHeader(`imap2mcp.sid=${v}`);
      const r = await t.get("/api/overview");
      expect(r.status, `cookie ${v.slice(0, 20)}`).toBe(401);
      const s = await t.get("/api/session");
      expect(s.status).toBe(200);
      expect(((await s.json()) as any).authenticated).toBe(false);
    }
  });

  it("a session cookie sealed with another SESSION_SECRET is rejected after a restart with a different secret; the same secret still works", async () => {
    const b = admin();
    await adminLogin(b, pw);
    await bare.restart(); // same secret, same data: the 24 h cookie survives a restart
    expect((await b.get("/api/overview")).status).toBe(200);
    await bare.restart({ SESSION_SECRET: randomBytes(32).toString("hex") });
    expect((await b.get("/api/overview")).status).toBe(401);
    expect(await b.session()).toMatchObject({ authenticated: false, setupRequired: false });
    expect((await adminLogin(b, pw)).status).toBe(204); // the admin itself persisted
  });

  it("a session whose admin row has been removed is no longer an admin session", async () => {
    const b = admin();
    await adminLogin(b, pw);
    expect((await b.get("/api/overview")).status).toBe(200);
    bare.srv.db().prepare("DELETE FROM admin").run();
    expect((await b.get("/api/overview")).status).toBe(401);
  });
});

describe.skipIf(!haveOpenssl)("cookie flags", () => {
  it("http BASE_URL: HttpOnly, SameSite=Lax, Path=/, 24 h, not Secure, no HSTS", async () => {
    const bare = await createBare();
    try {
      const r = await fetch(`${bare.base}/api/session`);
      const cookie = (r.headers.getSetCookie?.() ?? []).find((c) => c.startsWith("imap2mcp.sid=")) ?? "";
      expect(cookie, "Set-Cookie on GET /api/session").toBeTruthy();
      expect(cookie).toMatch(/;\s*HttpOnly/i);
      expect(cookie).toMatch(/;\s*SameSite=Lax/i);
      expect(cookie).toMatch(/;\s*Path=\//i);
      expect(cookie).not.toMatch(/;\s*Secure/i);
      const maxAge = /Max-Age=(\d+)/i.exec(cookie);
      const expires = /Expires=([^;]+)/i.exec(cookie);
      const ttl = maxAge ? Number(maxAge[1]) : expires ? (Date.parse(expires[1]) - Date.now()) / 1000 : NaN;
      expect(ttl).toBeGreaterThan(23 * 3600);
      expect(ttl).toBeLessThanOrEqual(24 * 3600 + 60);
      expect(r.headers.get("strict-transport-security")).toBeNull();
    } finally { await bare.teardown(); }
  });

  it("https BASE_URL: the cookie is Secure and HSTS is sent", async () => {
    const bare = await createBare({ env: { BASE_URL: "https://bridge.example.test" } });
    try {
      const r = await fetch(`${bare.srv.baseUrl}/api/session`);
      const cookie = (r.headers.getSetCookie?.() ?? []).find((c) => c.startsWith("imap2mcp.sid=")) ?? "";
      expect(cookie).toMatch(/;\s*Secure/i);
      expect(cookie).toMatch(/;\s*HttpOnly/i);
      expect(cookie).toMatch(/;\s*SameSite=Lax/i);
      expect(r.headers.get("strict-transport-security")).toMatch(/max-age=\d+/);
      expect(((await r.json()) as any).baseUrl).toBe("https://bridge.example.test");
    } finally { await bare.teardown(); }
  });
});

describe.skipIf(!haveOpenssl)("rate limits", () => {
  it("setup attempts are limited (10 per 15 minutes) once the budget is spent, even for the right token", async () => {
    const bare = await createBare();
    try {
      const b = new Browser(bare.base);
      const codes: number[] = [];
      for (let i = 0; i < 14; i++) codes.push((await b.postWithCsrf("/api/setup", { token: "wrong-" + i, password: "x", password2: "x" })).status);
      expect(codes).toContain(429);
      const held = await b.postWithCsrf("/api/setup", { token: bare.bootstrap, password: strongPw(), password2: "x" });
      expect(held.status).toBe(429);
      expect(held.headers.get("retry-after")).toMatch(/^\d+$/);
      expect((await errorOf(held)).code).toBeTruthy();
      expect((await b.session()).setupRequired).toBe(true);
    } finally { await bare.teardown(); }
  });

  it("login failures are limited, X-Forwarded-For cannot dodge the limit on an http deployment, and a success resets the counter", async () => {
    const bare = await createBare();
    try {
      const pw = strongPw();
      const setup = new Browser(bare.base);
      expect((await setup.postWithCsrf("/api/setup", { token: bare.bootstrap, password: pw, password2: pw })).status).toBe(204);

      // a successful login resets the failure counter: 9 failures, 1 success, 9 failures are all still answered with 401
      const a = new Browser(bare.base);
      for (let i = 0; i < 9; i++) expect((await adminLogin(a, "wrong-" + i)).status).toBe(401);
      expect((await adminLogin(a, pw)).status).toBe(204);
      for (let i = 0; i < 9; i++) expect((await adminLogin(a, "wrong-again-" + i)).status).toBe(401);

      // spoofed X-Forwarded-For values must not create fresh buckets (BASE_URL is http: no proxy is trusted)
      const b = new Browser(bare.base);
      const token = await b.csrf();
      const codes: number[] = [];
      for (let i = 0; i < 16; i++) {
        const r = await b.req("POST", "/api/login", { json: { password: "spoof-" + i }, headers: { "x-csrf-token": token, "x-forwarded-for": `203.0.113.${i + 1}` } });
        codes.push(r.status);
      }
      expect(codes).toContain(429);
      const held = await b.req("POST", "/api/login", { json: { password: pw }, headers: { "x-csrf-token": token, "x-forwarded-for": "198.51.100.77" } });
      expect(held.status).toBe(429);
      expect(held.headers.get("retry-after")).toMatch(/^\d+$/);
    } finally { await bare.teardown(); }
  });
});

describe.skipIf(!haveOpenssl)("every protected endpoint answers 401 without an admin session", () => {
  let s: Stack;
  afterAll(async () => { await s?.teardown(); });

  it("401 + JSON error body for every method and path of the admin API, with and without a valid anonymous CSRF token", async () => {
    s = await createStack({ accounts: ["alice@example.test"] });
    const m = s.mailbox["alice@example.test"];
    const c = "00000000-0000-4000-8000-000000000000";
    const endpoints: Array<[string, string, unknown?]> = [
      ["GET", "/api/overview"],
      ["POST", "/api/mailboxes", { label: "x", host: "localhost", port: 993, username: "u", password: "p" }],
      ["GET", `/api/mailboxes/${m}`],
      ["PATCH", `/api/mailboxes/${m}`, { label: "x", host: "localhost", port: 993, username: "u" }],
      ["POST", `/api/mailboxes/${m}/test`],
      ["POST", `/api/mailboxes/${m}/retry`],
      ["PUT", `/api/mailboxes/${m}/drafts`, { folder: "Drafts" }],
      ["DELETE", `/api/mailboxes/${m}`, { confirmLabel: "Box alice" }],
      ["POST", "/api/clients", { name: "x", redirectUris: ["http://localhost:1/cb"] }],
      ["GET", `/api/clients/${c}`],
      ["PUT", `/api/clients/${c}/grants`, { grants: [] }],
      ["POST", `/api/clients/${c}/rules`, { mailboxId: m, folder: "*", operation: "search", effect: "allow" }],
      ["DELETE", `/api/clients/${c}/rules/${c}`],
      ["POST", `/api/clients/${c}/disable`],
      ["POST", `/api/clients/${c}/enable`],
      ["POST", `/api/clients/${c}/revoke`],
      ["POST", `/api/tokens/${c}/revoke`],
      ["GET", "/api/audit"],
      ["GET", "/api/audit/export.jsonl"],
      ["GET", "/api/audit/export.csv"],
      ["GET", "/api/oauth/authorize?response_type=code&client_id=x"],
      ["POST", "/api/oauth/authorize", { decision: "approve", grants: [] }],
    ];
    const anon = new Browser(s.base);
    const token = await anon.csrf();
    for (const [method, path, body] of endpoints) {
      const label = `${method} ${path}`;
      const withToken = await anon.req(method, path, { json: method === "GET" ? undefined : body ?? {}, headers: { "x-csrf-token": token } });
      expect(withToken.status, `${label} (valid CSRF, anonymous)`).toBe(401);
      expect((await errorOf(withToken)).code, label).toBeTruthy();
      if (method === "GET") continue;
      // without CSRF the request is refused as well; which check comes first is not part of the contract
      const without = await new Browser(s.base).req(method, path, { json: body ?? {} });
      expect([401, 403], `${label} (no token, anonymous)`).toContain(without.status);
    }
    // nothing was created or changed by any of it
    expect(s.srv.db().prepare("SELECT COUNT(*) n FROM mailboxes").get()).toEqual({ n: 1 });
    expect(s.srv.db().prepare("SELECT COUNT(*) n FROM oauth_clients").get()).toEqual({ n: 0 });
  });
});
