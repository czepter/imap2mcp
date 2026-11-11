/**
 * Version 0 acceptance criteria 2 and 3 plus the admin-surface hardening from DESIGN_V0:
 * mailbox setup/reconnect after restart, TLS validation, SSRF policy, encryption at rest with the key outside
 * the DB, fail-closed key handling, /setup lock-down, CSRF, session cookie flags, rate limiting.
 * Ported from the server-rendered admin UI to the JSON API (docs/NUXT_MIGRATION.md): the same properties, asserted on
 * API responses (status codes and DTOs) instead of HTML pages and redirects.
 */
import { describe, it, expect, afterAll } from "vitest";
import { createServer as createTcpServer } from "node:net";
import { readFileSync, existsSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { makeSelfSignedCert } from "../helpers/certs.js";
import { Browser, errorOf, json } from "../helpers/http.js";
import { bootstrapTokenFrom, makeWorkdir, startServer } from "../helpers/server.js";
import {
  addMailboxRaw, adminLogin, createStack, obtainToken, Mcp, rawMcp, msg, sha256hex, sleep, waitFor, registerClient, consent, testMailbox, REDIRECT, type Stack,
} from "../helpers/stack.js";

const cert = makeSelfSignedCert();
const haveOpenssl = !!cert;
if (!haveOpenssl) console.warn("SKIPPED security: openssl not available to create the fixture TLS certificate");

const ALICE = "alice@example.test";

function dbFilesBytes(dataDir: string): Buffer {
  const files = readdirSync(dataDir).filter((f) => f.startsWith("bridge.db"));
  return Buffer.concat(files.map((f) => readFileSync(join(dataDir, f))));
}

describe.skipIf(!haveOpenssl)("encryption at rest, restart, key handling", () => {
  let s: Stack;
  const secrets: Record<string, string> = {};

  it("sets up through the admin API, tests the connection, and never returns the saved secret", async () => {
    s = await createStack({ accounts: [ALICE] });
    const id = s.mailbox[ALICE];
    const pw = s.imapPasswords[ALICE];
    secrets.imapPassword = pw;
    const responses: Array<[string, Response]> = [
      ["GET /api/overview", await s.admin.get("/api/overview")],
      ["GET /api/mailboxes/:id", await s.admin.get(`/api/mailboxes/${id}`)],
      ["POST /api/mailboxes/:id/test", await s.admin.postWithCsrf(`/api/mailboxes/${id}/test`)],
      ["PATCH /api/mailboxes/:id (password kept)", await s.admin.patchWithCsrf(`/api/mailboxes/${id}`, { label: "Box alice", host: "localhost", port: s.fake.port, username: ALICE })],
      ["GET /api/session", await s.admin.get("/api/session")],
    ];
    for (const [name, res] of responses) {
      expect(res.status, name).toBe(200);
      const text = await res.text();
      expect(text, name).not.toContain(pw);
      expect(text, name).not.toMatch(/v1:[0-9a-f]{8}:/); // no ciphertext either
    }
    // the Mailbox DTO has no password-ish field at all (the old form rendered an empty password input)
    const mb = (await (await s.admin.get(`/api/mailboxes/${id}`)).json()) as any;
    expect(Object.keys(mb.mailbox).sort()).toEqual(["createdAt", "draftsFolder", "host", "id", "label", "port", "username"]);
  });

  it("stores the IMAP password as AES-256-GCM v1 ciphertext, bound to its row", async () => {
    const row = s.srv.db().prepare("SELECT imap_password_enc FROM mailboxes").get() as any;
    expect(row.imap_password_enc).toMatch(/^v1:[0-9a-f]{8}:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+$/);
    const iv = row.imap_password_enc.split(":")[2];
    expect(Buffer.from(iv, "base64")).toHaveLength(12);
  });

  it("DB + WAL + SHM dump and the application log contain no plaintext secret", async () => {
    const id = s.mailbox[ALICE];
    s.fake.addMessage(ALICE, "INBOX", msg("log probe"));
    const { tokens } = await obtainToken(s, [[id, "read"], [id, "draft"]]);
    const mcp = await new Mcp(s.base, tokens.access_token).connect();
    expect((await mcp.call("search_messages", { mailbox: id, folder: "INBOX" })).isError).toBe(false);
    expect((await mcp.call("create_draft", { mailbox: id, subject: "d", body: "b" })).isError).toBe(false);
    await mcp.close();

    // a failed login attempt must not echo the attempted password
    const attempt = "WrongPw-" + randomBytes(6).toString("hex");
    await adminLogin(new Browser(s.base), attempt);

    Object.assign(secrets, { access: tokens.access_token, refresh: tokens.refresh_token, adminPassword: s.adminPassword, key: s.work.keyHex, session: s.work.sessionSecret, attempt });

    const live = dbFilesBytes(s.work.dataDir); // includes the -wal while the process is running
    const log = s.srv.output();
    for (const [name, val] of Object.entries(secrets)) {
      expect(live.includes(Buffer.from(val)), `DB/WAL contains ${name}`).toBe(false);
      expect(log.includes(val), `log contains ${name}`).toBe(false);
    }
    // the stored forms are hashes
    expect(s.srv.db().prepare("SELECT 1 FROM oauth_tokens WHERE token_hash = ?").get(sha256hex(tokens.access_token))).toBeTruthy();
    expect(s.srv.db().prepare("SELECT password_hash FROM admin").get()).toMatchObject({ password_hash: expect.not.stringContaining(s.adminPassword) });

    await s.srv.stop(); // checkpoint on close
    const after = dbFilesBytes(s.work.dataDir);
    for (const [name, val] of Object.entries(secrets)) expect(after.includes(Buffer.from(val)), `DB after close contains ${name}`).toBe(false);
    expect(readFileSync(join(s.work.dataDir, "bridge.db")).includes(Buffer.from("SQLite format 3"))).toBe(true);
  });

  it("restart: token still valid, mailbox reconnects, admin can log in again", async () => {
    // issue a token first (server is stopped; start it)
    await s.restart();
    const id = s.mailbox[ALICE];
    const login = await adminLogin(s.admin, s.adminPassword);
    expect(login.status).toBe(204);
    const { tokens } = await obtainToken(s, [[id, "read"]]);
    await s.restart();
    // /setup stays closed and no new bootstrap token is printed after a restart
    expect(bootstrapTokenFrom(s.srv.output())).toBeNull();
    expect((await s.admin.session()).setupRequired).toBe(false);
    expect((await s.admin.postWithCsrf("/api/setup", { token: s.bootstrap, password: "Another-Pw-123456", password2: "Another-Pw-123456" })).status).toBe(404);

    const before = s.fake.commands.filter((c) => c.line.startsWith("UID SEARCH")).length;
    const mcp = await new Mcp(s.base, tokens.access_token).connect();
    const r = await mcp.call("search_messages", { mailbox: id, folder: "INBOX" });
    expect(r.isError, r.text).toBe(false);
    expect(r.data.total).toBeGreaterThan(0);
    expect(s.fake.commands.filter((c) => c.line.startsWith("UID SEARCH")).length).toBeGreaterThan(before);
    await mcp.close();

    // UI path after restart as well
    await adminLogin(s.admin, s.adminPassword);
    const t = await testMailbox(s, id);
    expect(t.ok, t.message).toBe(true);
    expect(t.message).toMatch(/Connected\./);
  });

  it("a ciphertext moved to another row does not decrypt (AAD binds row and column)", async () => {
    const other = await addMailboxRaw(s, { label: "Twin", host: "localhost", port: s.fake.port, user: ALICE, pass: "irrelevant-pw" });
    await s.srv.stop(); // edit the file only while no server holds it open: a live WAL is not reliably visible to a second connection
    const db = s.srv.db();
    const real = (db.prepare("SELECT imap_password_enc e FROM mailboxes WHERE id = ?").get(s.mailbox[ALICE]) as any).e;
    expect(db.prepare("UPDATE mailboxes SET imap_password_enc = ? WHERE id = ?").run(real, other).changes).toBe(1);
    db.close();
    await s.restart();
    await adminLogin(s.admin, s.adminPassword);
    const logins = () => s.fake.commands.filter((c) => c.line.includes("LOGIN-ATTEMPT")).length;
    const n = logins();
    const t = await testMailbox(s, other);
    expect(t.ok).toBe(false);
    expect(t.message).not.toMatch(/Connected\./);
    expect(logins()).toBe(n); // never even tried to log in
  });

  it("a wrong master key fails closed: no mailbox use, no IMAP login, no secret in errors", async () => {
    const id = s.mailbox[ALICE];
    const { tokens } = await obtainToken(s, [[id, "read"]]);
    await s.srv.stop();
    const goodKey = s.work.keyHex;
    const wrong = randomBytes(32).toString("hex");
    writeFileSync(s.work.keyFile, wrong + "\n");
    const logins = () => s.fake.commands.filter((c) => c.line.includes("LOGIN-ATTEMPT")).length;
    const n = logins();
    try {
      let up = true;
      try { await s.restart(); } catch { up = false; }
      console.info(`wrong-key run: server ${up ? "started (fails at use)" : "refused to start"}`);
      if (up) {
        // acceptable design: starts, but nothing decrypts
        const mcp = await new Mcp(s.base, tokens.access_token).connect();
        const r = await mcp.call("search_messages", { mailbox: id, folder: "INBOX" });
        expect(r.isError).toBe(true);
        expect(r.text).not.toContain(s.imapPasswords[ALICE]);
        await mcp.close();
        await adminLogin(s.admin, s.adminPassword);
        const t = await testMailbox(s, id);
        expect(t.ok).toBe(false);
        expect(JSON.stringify(t)).not.toContain(s.imapPasswords[ALICE]);
      }
      expect(logins()).toBe(n);
      expect(s.srv.output()).not.toContain(s.imapPasswords[ALICE]);
    } finally {
      await s.srv.stop();
      writeFileSync(s.work.keyFile, goodKey + "\n");
    }
    await s.restart(); // right key again: everything works
    const mcp = await new Mcp(s.base, tokens.access_token).connect();
    { const rr = await mcp.call("search_messages", { mailbox: id, folder: "INBOX" }); expect(rr.isError, rr.text).toBe(false); }
    await mcp.close();
  });

  afterAll(async () => { await s?.teardown(); });
});

describe.skipIf(!haveOpenssl)("startup fails closed on bad configuration", () => {
  const cases: Array<[string, (w: ReturnType<typeof makeWorkdir>) => Record<string, string | undefined>]> = [
    ["no encryption key at all", () => ({ ENCRYPTION_KEY_FILE: undefined, ENCRYPTION_KEY: undefined })],
    ["key file does not exist", (w) => ({ ENCRYPTION_KEY_FILE: join(w.dir, "nope.key") })],
    ["key too short", (w) => { writeFileSync(w.keyFile, "abcd\n"); return {}; }],
    ["key not hex/base64", (w) => { writeFileSync(w.keyFile, "z".repeat(64) + "\n"); return {}; }],
    ["all-zero key", (w) => { writeFileSync(w.keyFile, "0".repeat(64) + "\n"); return {}; }],
    ["placeholder key from an example file", () => ({ ENCRYPTION_KEY_FILE: undefined, ENCRYPTION_KEY: "generate-a-64-char-hex-string-here-use-openssl-rand-hex-32" })],
    ["no SESSION_SECRET", () => ({ SESSION_SECRET: "" })],
    ["short SESSION_SECRET", () => ({ SESSION_SECRET: "short" })],
    ["invalid REGISTRATION_MODE", () => ({ REGISTRATION_MODE: "open" })],
  ];
  it.each(cases)("refuses to start: %s", async (_name, mk) => {
    const w = makeWorkdir();
    try {
      const env = mk(w);
      const srv = await startServer({ work: w, env, expectExit: true });
      const code = await Promise.race([srv.exited(), sleep(15000).then(() => "timeout" as const)]);
      if (code === "timeout") await srv.stop();
      expect(code).not.toBe("timeout");
      expect(code).not.toBe(0);
      // nothing is listening
      await expect(fetch(`${srv.baseUrl}/.well-known/oauth-authorization-server`)).rejects.toBeTruthy();
      expect(srv.output()).toMatch(/FATAL|required|must|key/i);
      expect(srv.output()).not.toContain(w.keyHex);
    } finally { w.cleanup(); }
  });

  it("accepts a base64 key file and ENCRYPTION_KEY (hex) as well", async () => {
    const w = makeWorkdir();
    try {
      writeFileSync(w.keyFile, randomBytes(32).toString("base64") + "\n");
      const a = await startServer({ work: w });
      await a.stop();
      const w2 = makeWorkdir();
      try {
        const b = await startServer({ work: w2, env: { ENCRYPTION_KEY_FILE: undefined, ENCRYPTION_KEY: randomBytes(32).toString("hex") } });
        await b.stop();
      } finally { w2.cleanup(); }
    } finally { w.cleanup(); }
  });
});

describe.skipIf(!haveOpenssl)("TLS validation and SSRF policy on mailbox connections", () => {
  it("rejects an untrusted certificate (no rejectUnauthorized override) and never sends credentials", async () => {
    const s = await createStack({ accounts: [ALICE], skipMailboxes: true, noCa: true });
    try {
      const id = await addMailboxRaw(s, { label: "Untrusted", host: "localhost", port: s.fake.port, user: ALICE, pass: s.imapPasswords[ALICE] });
      const t = await testMailbox(s, id);
      expect(t.ok).toBe(false);
      expect(t.message).not.toMatch(/Connected\./);
      expect(t.message).toMatch(/certificate/i);
      const { tokens } = await obtainToken(s, [[id, "read"]]);
      const mcp = await new Mcp(s.base, tokens.access_token).connect();
      const r = await mcp.call("list_folders", { mailbox: id });
      expect(r.isError).toBe(true);
      expect(r.data.code).toBe("UPSTREAM_ERROR");
      expect(s.fake.commands.filter((c) => c.line.includes("LOGIN-ATTEMPT"))).toHaveLength(0);
      await mcp.close();
    } finally { await s.teardown(); }
  });

  it("never falls back to plaintext IMAP: a non-TLS server receives no credentials", async () => {
    const received: string[] = [];
    const plain = createTcpServer((sock) => {
      sock.write("* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN] plaintext imap\r\n");
      sock.on("data", (d) => received.push(d.toString("latin1")));
      sock.on("error", () => {});
    });
    await new Promise<void>((r) => plain.listen(0, "127.0.0.1", r));
    const port = (plain.address() as any).port;
    const s = await createStack({ accounts: [ALICE], skipMailboxes: true });
    try {
      const pw = "PlainPw-" + randomBytes(6).toString("hex");
      const id = await addMailboxRaw(s, { label: "Plain", host: "localhost", port, user: "u", pass: pw });
      const t = await testMailbox(s, id);
      expect(t.ok).toBe(false);
      expect(JSON.stringify(t)).not.toContain(pw);
      const { tokens } = await obtainToken(s, [[id, "read"]]);
      const mcp = await new Mcp(s.base, tokens.access_token).connect();
      const r = await mcp.call("list_folders", { mailbox: id });
      expect(r.isError).toBe(true);
      // upstream errors reveal neither host, port nor password
      expect(r.text).not.toMatch(new RegExp(`localhost|${port}|${pw}`));
      await sleep(300);
      const wire = received.join("");
      expect(wire).not.toContain(pw);
      expect(wire).not.toMatch(/LOGIN|AUTHENTICATE|STARTTLS/i);
      await mcp.close();
    } finally { await s.teardown(); plain.close(); }
  });

  it("SSRF: a host resolving to a private/loopback address is refused unless listed in ALLOW_PRIVATE_HOSTS", async () => {
    const s = await createStack({ accounts: [ALICE], skipMailboxes: true, env: { ALLOW_PRIVATE_HOSTS: "" } });
    try {
      for (const host of ["localhost", "127.0.0.1", "169.254.169.254", "10.0.0.5", "[::1]"]) {
        const id = await addMailboxRaw(s, { label: host, host, port: s.fake.port, user: ALICE, pass: s.imapPasswords[ALICE] });
        const t = await testMailbox(s, id);
        expect(t.ok, host).toBe(false);
        expect(t.message, host).toMatch(/ALLOW_PRIVATE_HOSTS|private/i);
        const { tokens } = await obtainToken(s, [[id, "read"]]);
        const mcp = await new Mcp(s.base, tokens.access_token).connect();
        expect((await mcp.call("list_folders", { mailbox: id })).isError, host).toBe(true);
        await mcp.close();
      }
      expect(s.fake.commands.filter((c) => c.line.includes("LOGIN-ATTEMPT"))).toHaveLength(0);
    } finally { await s.teardown(); }
  });

  it("SSRF allow-list is per host name: allowing 'localhost' does not allow '127.0.0.1'", async () => {
    const s = await createStack({ accounts: [ALICE], skipMailboxes: true, env: { ALLOW_PRIVATE_HOSTS: "localhost" } });
    try {
      const ok = await addMailboxRaw(s, { label: "ok", host: "localhost", port: s.fake.port, user: ALICE, pass: s.imapPasswords[ALICE] });
      expect((await testMailbox(s, ok)).ok).toBe(true);
      const ip = await addMailboxRaw(s, { label: "ip", host: "127.0.0.1", port: s.fake.port, user: ALICE, pass: s.imapPasswords[ALICE] });
      expect((await testMailbox(s, ip)).ok).toBe(false);
    } finally { await s.teardown(); }
  });
});

describe.skipIf(!haveOpenssl)("admin bootstrap, CSRF, sessions", () => {
  it("/setup: locked to the bootstrap token, then 404 forever; password cannot be re-set", async () => {
    const w = makeWorkdir();
    const fixed = "fixed-bootstrap-" + randomBytes(8).toString("hex");
    const srv = await startServer({ work: w, env: { ADMIN_BOOTSTRAP_TOKEN: fixed } });
    try {
      expect(bootstrapTokenFrom(srv.output())).toBe(fixed);
      const b = new Browser(srv.baseUrl);
      // before setup: the SPA is told to go to /setup, and nothing else is reachable
      const before = await b.session();
      expect(before).toMatchObject({ setupRequired: true, authenticated: false });
      expect((await b.get("/api/overview")).status).toBe(401);
      const pw = "Correct-Horse-" + randomBytes(5).toString("hex");
      const bad = await b.postWithCsrf("/api/setup", { token: "wrong-token", password: pw, password2: pw });
      expect(bad.status).toBe(403);
      expect((await b.postWithCsrf("/api/setup", { token: fixed, password: "short", password2: "short" })).status).toBe(400);
      expect((await b.postWithCsrf("/api/setup", { token: fixed, password: pw, password2: pw + "x" })).status).toBe(400);
      expect((await b.get("/api/overview")).status).toBe(401); // still not logged in
      expect((await b.session()).setupRequired).toBe(true);
      const good = await b.postWithCsrf("/api/setup", { token: fixed, password: pw, password2: pw });
      expect(good.status).toBe(204);
      expect((await b.get("/api/overview")).status).toBe(200); // logged in after setup
      expect(await b.session()).toMatchObject({ setupRequired: false, authenticated: true });

      // afterwards: unreachable
      const fresh = new Browser(srv.baseUrl);
      expect((await fresh.session()).setupRequired).toBe(false);
      const attacker = "Attacker-" + randomBytes(5).toString("hex");
      const post = await fresh.postWithCsrf("/api/setup", { token: fixed, password: attacker, password2: attacker });
      expect(post.status).toBe(404);
      expect((await adminLogin(new Browser(srv.baseUrl), attacker)).status).toBe(401);
      expect((await adminLogin(new Browser(srv.baseUrl), pw)).status).toBe(204);
    } finally { await srv.stop(); w.cleanup(); }
  });

  describe("on a configured instance", () => {
    let s: Stack;
    let mailboxId: string;
    let clientId: string;
    let tokens: any;
    let revokeId: string;

    it("prepare", async () => {
      s = await createStack({ accounts: [ALICE] });
      mailboxId = s.mailbox[ALICE];
      ({ clientId, tokens } = await obtainToken(s, [[mailboxId, "read"]]));
      revokeId = (s.srv.db().prepare("SELECT id FROM oauth_tokens WHERE token_hash = ?").get(sha256hex(tokens.access_token)) as any).id;
    });
    afterAll(async () => { await s?.teardown(); });

    it("unauthenticated visitors cannot use any admin route", async () => {
      const anon = new Browser(s.base);
      for (const p of ["/api/overview", `/api/mailboxes/${mailboxId}`, `/api/clients/${clientId}`, "/api/audit", "/api/audit/export.jsonl", "/api/audit/export.csv"]) {
        const r = await anon.get(p);
        expect(r.status, p).toBe(401);
        expect((await errorOf(r)).code, p).toBeTruthy();
      }
      // with a perfectly valid CSRF token of their own anonymous session, mutations are still refused
      const mutations: Array<[string, string, unknown]> = [
        ["POST", "/api/mailboxes", { label: "evil", host: "localhost", port: 993, username: "u", password: "p" }],
        ["PUT", `/api/clients/${clientId}/grants`, { grants: [{ mailboxId, capability: "organize" }] }],
        ["POST", `/api/tokens/${revokeId}/revoke`, {}],
        ["DELETE", `/api/mailboxes/${mailboxId}`, { confirmLabel: "Box alice" }],
        ["POST", `/api/clients/${clientId}/disable`, {}],
      ];
      for (const [method, p, body] of mutations) {
        const r = await anon.withCsrf(method, p, body);
        expect(r.status, `${method} ${p}`).toBe(401);
      }
      expect(s.srv.db().prepare("SELECT COUNT(*) n FROM mailboxes").get()).toEqual({ n: 1 });
      // consent screen also needs the owner
      const c = await consent(anon, s.base, { clientId, grants: [[mailboxId, "read"]] });
      expect(c.location).toBe("status:401");
    });

    it("CSRF: state-changing requests without a valid token are refused and change nothing", async () => {
      const before = {
        mailboxes: s.srv.db().prepare("SELECT COUNT(*) n FROM mailboxes").get(),
        grants: s.srv.db().prepare("SELECT COUNT(*) n FROM policy_rules").get(),
      };
      const otherSession = new Browser(s.base);
      expect((await adminLogin(otherSession, s.adminPassword)).status).toBe(204);
      const foreignToken = await otherSession.csrf();
      const ownToken = await s.admin.csrf(); // make sure this session has its own token
      expect(foreignToken).not.toBe(ownToken);

      const attempts: Array<[string, string, unknown]> = [
        ["POST", "/api/mailboxes", { label: "evil", host: "localhost", port: 993, username: "u", password: "p" }],
        ["DELETE", `/api/mailboxes/${mailboxId}`, { confirmLabel: "Box alice" }],
        ["PATCH", `/api/mailboxes/${mailboxId}`, { label: "renamed", host: "localhost", port: 993, username: "u" }],
        ["PUT", `/api/clients/${clientId}/grants`, { grants: [{ mailboxId, capability: "organize" }] }],
        ["POST", `/api/clients/${clientId}/rules`, { mailboxId, folder: "*", operation: "search", effect: "allow" }],
        ["POST", `/api/clients/${clientId}/disable`, {}],
        ["POST", `/api/clients/${clientId}/revoke`, {}],
        ["POST", `/api/tokens/${revokeId}/revoke`, {}],
        ["POST", "/api/logout", {}],
      ];
      for (const [method, path, body] of attempts) {
        const label = `${method} ${path}`;
        const none = await s.admin.req(method, path, { json: body, headers: { origin: "https://evil.example" } });
        expect(none.status, `${label} without token`).toBe(403);
        expect((await errorOf(none)).code, label).toBe("csrf");
        const wrong = await s.admin.req(method, path, { json: body, headers: { "x-csrf-token": "A".repeat(43) } });
        expect(wrong.status, `${label} wrong token`).toBe(403);
        const foreign = await s.admin.req(method, path, { json: body, headers: { "x-csrf-token": foreignToken } });
        expect(foreign.status, `${label} token from another session`).toBe(403);
        // a cross-site <form> can only send simple content types: the right token with the wrong type must fail too
        const form = await s.admin.req(method, path, { body: JSON.stringify(body), contentType: "text/plain", headers: { "x-csrf-token": ownToken } });
        expect(form.status, `${label} text/plain`).toBe(403);
        // and the token must travel in the header, never in the JSON body (the old _csrf form field is gone)
        const inBody = await s.admin.req(method, path, { json: { _csrf: ownToken, ...(body as object) } });
        expect(inBody.status, `${label} token in body`).toBe(403);
      }
      // the consent POST too
      const consentNoCsrf = await s.admin.post("/api/oauth/authorize", { params: { client_id: clientId, redirect_uri: REDIRECT, response_type: "code" }, decision: "approve", grants: [{ mailboxId, capability: "read" }] });
      expect(consentNoCsrf.status).toBe(403);
      expect(await consentNoCsrf.text()).not.toContain("redirectTo");
      // login too
      expect((await new Browser(s.base).post("/api/login", { password: s.adminPassword })).status).toBe(403);

      expect(s.srv.db().prepare("SELECT COUNT(*) n FROM mailboxes").get()).toEqual(before.mailboxes);
      expect(s.srv.db().prepare("SELECT COUNT(*) n FROM policy_rules").get()).toEqual(before.grants);
      expect(s.srv.db().prepare("SELECT revoked FROM oauth_tokens WHERE id = ?").get(revokeId)).toEqual({ revoked: 0 });
      expect(s.srv.db().prepare("SELECT disabled FROM oauth_clients WHERE client_id = ?").get(clientId)).toEqual({ disabled: 0 });
      expect((await rawMcp(s.base, `Bearer ${tokens.access_token}`)).status).toBe(200);
      expect((await s.admin.get("/api/overview")).status).toBe(200); // still logged in
    });

    it("session cookie is HttpOnly + SameSite=Lax, and security headers are present", async () => {
      const b = new Browser(s.base);
      const res = await b.get("/api/session");
      const cookie = (res.headers.getSetCookie?.() ?? []).find((c) => c.startsWith("imap2mcp.sid")) ?? "";
      expect(cookie).toMatch(/HttpOnly/i);
      expect(cookie).toMatch(/SameSite=Lax/i);
      expect(cookie).toMatch(/Path=\//i);
      expect(cookie).not.toMatch(/;\s*Secure/i); // BASE_URL is http in this fixture
      expect(res.headers.get("x-frame-options")).toBe("DENY");
      expect(res.headers.get("x-content-type-options")).toBe("nosniff");
      expect(res.headers.get("content-security-policy")).toMatch(/default-src 'none'/);
      expect(res.headers.get("cache-control")).toMatch(/no-store/);
    });

    it("login is rate limited", async () => {
      const w = makeWorkdir();
      const srv = await startServer({ work: w });
      try {
        const tok = await waitFor(() => bootstrapTokenFrom(srv.output()));
        const setup = new Browser(srv.baseUrl);
        const pw = "Admin-" + randomBytes(6).toString("hex");
        expect((await setup.postWithCsrf("/api/setup", { token: tok, password: pw, password2: pw })).status).toBe(204);
        const b = new Browser(srv.baseUrl);
        const codes: number[] = [];
        for (let i = 0; i < 14; i++) codes.push((await adminLogin(b, "wrong-" + i)).status);
        expect(codes).toContain(429);
        // even the right password is held back once limited
        const held = await adminLogin(b, pw);
        expect(held.status).toBe(429);
        expect(held.headers.get("retry-after")).toMatch(/^\d+$/);
        expect((await errorOf(held)).code).toBeTruthy();
      } finally { await srv.stop(); w.cleanup(); }
    });

    it("the mailbox secret and token hashes are not exposed through any admin endpoint", async () => {
      const paths = ["/api/overview", `/api/mailboxes/${mailboxId}`, `/api/clients/${clientId}`, "/api/audit", "/api/session"];
      for (const p of paths) {
        const text = await (await s.admin.get(p)).text();
        expect(text, p).not.toContain(s.imapPasswords[ALICE]);
        expect(text, p).not.toContain(tokens.access_token);
        expect(text, p).not.toContain(tokens.refresh_token);
        expect(text, p).not.toContain(sha256hex(tokens.access_token));
        expect(text, p).not.toContain(sha256hex(tokens.refresh_token));
        expect(text, p).not.toContain(s.work.sessionSecret);
        expect(text, p).not.toContain(s.work.keyHex);
        expect(text, p).not.toMatch(/v1:[0-9a-f]{8}:/);
      }
    });
  });
});

void existsSync;
void registerClient;
void msg;
void json;
