/**
 * Protocol tests against the BUILT server (`.output/server/index.mjs`, run `nuxt build` first or point
 * PROTOCOL_SERVER_ENTRY at another build). Spawns the real process; no helpers from test/helpers on purpose.
 * Covers the machine-facing endpoints: health, well-known, dynamic registration, token/refresh/revoke, /mcp auth and
 * methods, unknown paths, startup fail-closed and SIGTERM shutdown.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import Database from "better-sqlite3";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const ENTRY = resolve(process.env.PROTOCOL_SERVER_ENTRY ?? join(import.meta.dirname, "../../.output/server/index.mjs"));
const CWD = resolve(dirname(ENTRY), "../.."); // the directory holding .output and drizzle/
const sha = (s: string) => createHash("sha256").update(s).digest("hex");

async function freePort(): Promise<number> {
  return new Promise((res, rej) => {
    const s = createServer();
    s.once("error", rej);
    s.listen(0, "127.0.0.1", () => { const p = (s.address() as { port: number }).port; s.close(() => res(p)); });
  });
}

interface Running { base: string; port: number; proc: ChildProcess; output(): string; exited(): Promise<number | null>; dataDir: string }

function launch(dataDir: string, port: number, env: Record<string, string | undefined> = {}): Running {
  const e: Record<string, string | undefined> = {
    PATH: process.env.PATH, HOME: process.env.HOME, NODE_ENV: "production",
    PORT: String(port), BASE_URL: `http://127.0.0.1:${port}`, DATA_DIR: dataDir,
    SESSION_SECRET: randomBytes(32).toString("hex"), ENCRYPTION_KEY: randomBytes(32).toString("hex"),
    SIDECAR_DISABLED: "1", REGISTRATION_MODE: "dynamic", ...env,
  };
  for (const k of Object.keys(e)) if (e[k] === undefined) delete e[k];
  const proc = spawn(process.execPath, [ENTRY], { cwd: CWD, env: e as NodeJS.ProcessEnv, stdio: ["ignore", "pipe", "pipe"] });
  let out = "";
  proc.stdout!.on("data", (d) => (out += d));
  proc.stderr!.on("data", (d) => (out += d));
  const exited = new Promise<number | null>((r) => proc.once("exit", (c) => r(c)));
  return { base: `http://127.0.0.1:${port}`, port, proc, output: () => out, exited: () => exited, dataDir };
}

async function waitListening(s: Running): Promise<void> {
  const deadline = Date.now() + 40_000;
  while (!/IMAP Bridge listening/.test(s.output())) {
    if (s.proc.exitCode !== null) throw new Error(`server exited early (${s.proc.exitCode}):\n${s.output()}`);
    if (Date.now() > deadline) { s.proc.kill("SIGKILL"); throw new Error(`server did not start:\n${s.output()}`); }
    await new Promise((r) => setTimeout(r, 100));
  }
}

const challengeOf = (verifier: string) => createHash("sha256").update(verifier).digest("base64url");
const MCP_HEADERS = { "content-type": "application/json", accept: "application/json, text/event-stream" };

describe("protocol endpoints (built server)", () => {
  let tmp: string;
  let s: Running;
  let db: Database.Database;

  beforeAll(async () => {
    if (!existsSync(ENTRY)) throw new Error(`${ENTRY} not found: run \`nuxt build\` first (or set PROTOCOL_SERVER_ENTRY)`);
    tmp = mkdtempSync(join(tmpdir(), "imap2mcp-proto-"));
    s = launch(join(tmp, "data"), await freePort());
    await waitListening(s);
    db = new Database(join(tmp, "data", "bridge.db"));
  }, 60_000);

  afterAll(async () => {
    try { db?.close(); } catch { /* ignore */ }
    if (s && s.proc.exitCode === null) { s.proc.kill("SIGKILL"); await s.exited(); }
    rmSync(tmp, { recursive: true, force: true });
  });

  const register = async (extra: Record<string, unknown> = {}) => {
    const r = await fetch(`${s.base}/oauth/register`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ client_name: "proto test", redirect_uris: ["http://127.0.0.1:9/cb"], token_endpoint_auth_method: "none", ...extra }),
    });
    return { r, body: (await r.json()) as any };
  };

  /** Inserts an authorization code the way the consent step would, so the token endpoint can be exercised alone. */
  const mintCode = (clientId: string, verifier: string, scopes = "mail:read") => {
    const code = randomBytes(24).toString("base64url");
    db.prepare("INSERT INTO oauth_codes (code_hash, client_id, redirect_uri, scopes, resource, code_challenge, expires_at) VALUES (?,?,?,?,?,?,?)")
      .run(sha(code), clientId, "http://127.0.0.1:9/cb", scopes, `${s.base}/mcp`, challengeOf(verifier), new Date(Date.now() + 60_000).toISOString());
    return code;
  };
  const tokenForm = (fields: Record<string, string>, headers: Record<string, string> = {}) =>
    fetch(`${s.base}/oauth/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", ...headers }, body: new URLSearchParams(fields) });

  describe("health", () => {
    it("/healthz is 200 {status:ok}, uncacheable, and never sets a cookie", async () => {
      const r = await fetch(`${s.base}/healthz`);
      expect(r.status).toBe(200);
      expect(await r.json()).toEqual({ status: "ok" });
      expect(r.headers.get("cache-control")).toBe("no-store");
      expect(r.headers.get("set-cookie")).toBeNull();
    });
    it("/readyz reports fixed check names only", async () => {
      const r = await fetch(`${s.base}/readyz`);
      expect(r.status).toBe(200);
      expect(r.headers.get("cache-control")).toBe("no-store");
      expect(r.headers.get("set-cookie")).toBeNull();
      expect(await r.json()).toEqual({ status: "ok", checks: { db: "ok", key: "ok", sidecar: "disabled", migrations: "ok" } });
    });
  });

  describe("well-known metadata", () => {
    it("authorization server metadata", async () => {
      const r = await fetch(`${s.base}/.well-known/oauth-authorization-server`);
      expect(r.status).toBe(200);
      const m = (await r.json()) as any;
      expect(m).toMatchObject({
        issuer: s.base, authorization_endpoint: `${s.base}/oauth/authorize`, token_endpoint: `${s.base}/oauth/token`,
        registration_endpoint: `${s.base}/oauth/register`, revocation_endpoint: `${s.base}/oauth/revoke`,
        code_challenge_methods_supported: ["S256"], token_endpoint_auth_methods_supported: ["none"],
        authorization_response_iss_parameter_supported: true,
      });
    });
    it("protected resource metadata at the root and the path-suffixed form", async () => {
      for (const p of ["/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"]) {
        const r = await fetch(`${s.base}${p}`);
        expect(r.status, p).toBe(200);
        expect(await r.json()).toMatchObject({ resource: `${s.base}/mcp`, authorization_servers: [s.base], bearer_methods_supported: ["header"] });
      }
    });
    it("sends permissive CORS without credentials", async () => {
      const r = await fetch(`${s.base}/.well-known/oauth-authorization-server`, { headers: { origin: "https://app.example" } });
      expect(r.headers.get("access-control-allow-origin")).toBe("https://app.example");
      expect(r.headers.get("access-control-allow-credentials")).toBeNull();
    });
  });

  describe("dynamic client registration", () => {
    it("registers a public client (201) with the RFC 7591 response", async () => {
      const { r, body } = await register();
      expect(r.status).toBe(201);
      expect(body.client_id).toMatch(/^[0-9a-f-]{36}$/);
      expect(body).toMatchObject({ client_name: "proto test", redirect_uris: ["http://127.0.0.1:9/cb"], grant_types: ["authorization_code", "refresh_token"], response_types: ["code"], token_endpoint_auth_method: "none" });
      expect(typeof body.client_id_issued_at).toBe("number");
      expect(db.prepare("SELECT client_name FROM oauth_clients WHERE client_id = ?").get(body.client_id)).toEqual({ client_name: "proto test" });
    });
    it("rejects bad redirect URIs and unsupported auth methods", async () => {
      for (const redirect_uris of [[], ["http://evil.example/cb"], ["https://ok.example/cb#frag"], "https://ok.example/cb", Array(11).fill("https://ok.example/cb")]) {
        const { r, body } = await register({ redirect_uris });
        expect(r.status, JSON.stringify(redirect_uris)).toBe(400);
        expect(body.error).toBe("invalid_redirect_uri");
      }
      const { r, body } = await register({ token_endpoint_auth_method: "client_secret_basic" });
      expect(r.status).toBe(400);
      expect(body.error).toBe("invalid_client_metadata");
    });
    it("answers malformed and oversized bodies with 400 / 413 JSON", async () => {
      const bad = await fetch(`${s.base}/oauth/register`, { method: "POST", headers: { "content-type": "application/json" }, body: "{nope" });
      expect(bad.status).toBe(400);
      expect(((await bad.json()) as any).error).toBe("invalid_request");
      const big = await fetch(`${s.base}/oauth/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_name: "x".repeat(1_100_000) }) });
      expect(big.status).toBe(413);
    });
  });

  describe("token endpoint", () => {
    it("authorization_code (form body) then refresh_token, then the access token works on /mcp, then revoke kills it", async () => {
      const { body: reg } = await register();
      const clientId = reg.client_id as string;
      const verifier = randomBytes(32).toString("base64url");
      const code = mintCode(clientId, verifier, "mail:read mail:draft");

      const t = await tokenForm({ grant_type: "authorization_code", client_id: clientId, code, code_verifier: verifier, redirect_uri: "http://127.0.0.1:9/cb", resource: `${s.base}/mcp` });
      expect(t.status).toBe(200);
      expect(t.headers.get("cache-control")).toBe("no-store");
      expect(t.headers.get("pragma")).toBe("no-cache");
      const tokens = (await t.json()) as any;
      expect(tokens).toMatchObject({ token_type: "Bearer", expires_in: 3600, scope: "mail:read mail:draft" });

      // code is single use
      const again = await tokenForm({ grant_type: "authorization_code", client_id: clientId, code, code_verifier: verifier, redirect_uri: "http://127.0.0.1:9/cb" });
      expect(again.status).toBe(400);
      expect(await again.json()).toMatchObject({ error: "invalid_grant", error_description: "Code already used" });

      // the access token authenticates a real MCP call
      const list = await fetch(`${s.base}/mcp`, { method: "POST", headers: { ...MCP_HEADERS, authorization: `Bearer ${tokens.access_token}` }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }) });
      expect(list.status).toBe(200);
      expect(list.headers.get("x-request-id")).toMatch(/^[A-Za-z0-9_-]{8,64}$/);
      const text = await list.text();
      expect(text).toContain("list_mailboxes");
      expect(text).toContain("annotations"); // titles/annotations set by createMcpServer survive

      // refresh rotates; a JSON body works as well
      const r1 = await fetch(`${s.base}/oauth/token`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ grant_type: "refresh_token", client_id: clientId, refresh_token: tokens.refresh_token }) });
      expect(r1.status).toBe(200);
      const rotated = (await r1.json()) as any;
      expect(rotated.scope).toBe("mail:read mail:draft");
      const stale = await fetch(`${s.base}/mcp`, { method: "POST", headers: { ...MCP_HEADERS, authorization: `Bearer ${tokens.access_token}` }, body: "{}" });
      expect(stale.status).toBe(401); // the old access token died with the rotation

      // reuse of the rotated refresh token is theft: every live token of the lineage dies
      const reuse = await tokenForm({ grant_type: "refresh_token", client_id: clientId, refresh_token: tokens.refresh_token });
      expect(reuse.status).toBe(400);
      const afterTheft = await fetch(`${s.base}/mcp`, { method: "POST", headers: { ...MCP_HEADERS, authorization: `Bearer ${rotated.access_token}` }, body: "{}" });
      expect(afterTheft.status).toBe(401);
    });

    it("revoke (form) kills the token for its owner only", async () => {
      const { body: a } = await register();
      const { body: b } = await register();
      const verifier = randomBytes(32).toString("base64url");
      const t = (await (await tokenForm({ grant_type: "authorization_code", client_id: a.client_id, code: mintCode(a.client_id, verifier), code_verifier: verifier, redirect_uri: "http://127.0.0.1:9/cb" })).json()) as any;
      const call = () => fetch(`${s.base}/mcp`, { method: "POST", headers: { ...MCP_HEADERS, authorization: `Bearer ${t.access_token}` }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }) });
      const form = (clientId: string) => fetch(`${s.base}/oauth/revoke`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ token: t.access_token, client_id: clientId }) });
      const other = await form(b.client_id);
      expect(other.status).toBe(200);
      expect(await other.json()).toEqual({});
      expect((await call()).status).toBe(200); // not the owner: untouched
      const own = await form(a.client_id);
      expect(own.status).toBe(200);
      expect(own.headers.get("cache-control")).toBe("no-store");
      expect((await call()).status).toBe(401);
      const missing = await fetch(`${s.base}/oauth/revoke`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_id: a.client_id }) });
      expect(missing.status).toBe(400);
      expect(await missing.json()).toMatchObject({ error: "invalid_request" });
    });

    it("rejects the usual protocol violations", async () => {
      const { body: reg } = await register();
      const cid = reg.client_id as string;
      const err = async (r: Response, status: number, error: string) => {
        expect(r.status).toBe(status);
        expect(r.headers.get("cache-control")).toBe("no-store");
        expect(((await r.json()) as any).error).toBe(error);
      };
      await err(await tokenForm({ grant_type: "authorization_code" }), 400, "invalid_request");
      await err(await tokenForm({ grant_type: "authorization_code", client_id: randomUUID() }), 401, "invalid_client");
      await err(await tokenForm({ grant_type: "authorization_code", client_id: cid }, { authorization: "Basic " + Buffer.from(`${cid}:x`).toString("base64") }), 401, "invalid_client");
      await err(await tokenForm({ grant_type: "client_credentials", client_id: cid }), 400, "unsupported_grant_type");
      await err(await tokenForm({ grant_type: "authorization_code", client_id: cid, resource: "https://other.example/mcp" }), 400, "invalid_target");
      await err(await tokenForm({ grant_type: "authorization_code", client_id: cid, code: "x", code_verifier: "y", redirect_uri: "http://127.0.0.1:9/cb" }), 400, "invalid_grant");
      const verifier = randomBytes(32).toString("base64url");
      await err(await tokenForm({ grant_type: "authorization_code", client_id: cid, code: mintCode(cid, verifier), code_verifier: "wrong", redirect_uri: "http://127.0.0.1:9/cb" }), 400, "invalid_grant");
      await err(await tokenForm({ grant_type: "authorization_code", client_id: cid, code: mintCode(cid, verifier), code_verifier: verifier, redirect_uri: "http://127.0.0.1:9/other" }), 400, "invalid_grant");
      // a refresh may only narrow the scope
      const tok = (await (await tokenForm({ grant_type: "authorization_code", client_id: cid, code: mintCode(cid, verifier, "mail:read"), code_verifier: verifier, redirect_uri: "http://127.0.0.1:9/cb" })).json()) as any;
      await err(await tokenForm({ grant_type: "refresh_token", client_id: cid, refresh_token: tok.refresh_token, scope: "mail:read mail:organize" }), 400, "invalid_scope");
      const narrowed = await tokenForm({ grant_type: "refresh_token", client_id: cid, refresh_token: tok.refresh_token, scope: "mail:read" });
      expect(narrowed.status).toBe(200);
    });
  });

  describe("/mcp", () => {
    const tokenFor = async () => {
      const { body } = await register();
      const verifier = randomBytes(32).toString("base64url");
      const r = await tokenForm({ grant_type: "authorization_code", client_id: body.client_id, code: mintCode(body.client_id, verifier), code_verifier: verifier, redirect_uri: "http://127.0.0.1:9/cb" });
      return ((await r.json()) as any).access_token as string;
    };

    it("401 + WWW-Authenticate challenge without / with a bad credential, on every method", async () => {
      for (const method of ["POST", "GET", "DELETE"]) {
        for (const authorization of [undefined, "Bearer nope", "Basic abc", "Bearer "]) {
          const r = await fetch(`${s.base}/mcp`, { method, headers: authorization ? { authorization } : {}, ...(method === "POST" ? { body: "{}" } : {}) });
          expect(r.status, `${method} ${authorization}`).toBe(401);
          expect(r.headers.get("www-authenticate")).toContain(`Bearer resource_metadata="${s.base}/.well-known/oauth-protected-resource"`);
        }
      }
      const r = await fetch(`${s.base}/mcp`, { method: "POST", headers: { authorization: "Bearer nope" } });
      expect(r.headers.get("www-authenticate")).toContain('error="invalid_token"');
      expect(await r.json()).toEqual({ error: "invalid_token" });
      const none = await fetch(`${s.base}/mcp`, { method: "POST" });
      expect(await none.json()).toEqual({ error: "unauthorized" });
    });

    it("rejects an expired token and a token for another audience", async () => {
      const tok = await tokenFor();
      const call = () => fetch(`${s.base}/mcp`, { method: "POST", headers: { ...MCP_HEADERS, authorization: `Bearer ${tok}` }, body: "{}" });
      db.prepare("UPDATE oauth_tokens SET resource = 'https://other.example/mcp' WHERE token_hash = ?").run(sha(tok));
      let r = await call();
      expect(r.status).toBe(401);
      expect(r.headers.get("www-authenticate")).toContain('error_description="Token audience mismatch"');
      db.prepare("UPDATE oauth_tokens SET resource = ?, expires_at = ? WHERE token_hash = ?").run(`${s.base}/mcp`, new Date(Date.now() - 1000).toISOString(), sha(tok));
      r = await call();
      expect(r.status).toBe(401);
      expect(r.headers.get("www-authenticate")).toContain('error_description="Token expired"');
    });

    it("405 + Allow: POST + JSON-RPC error body on GET and DELETE with a valid token", async () => {
      const tok = await tokenFor();
      for (const method of ["GET", "DELETE", "PUT"]) {
        const r = await fetch(`${s.base}/mcp`, { method, headers: { authorization: `Bearer ${tok}` } });
        expect(r.status, method).toBe(405);
        expect(r.headers.get("allow")).toBe("POST");
        expect(await r.json()).toEqual({ jsonrpc: "2.0", error: { code: -32000, message: "Method not allowed (stateless server)" }, id: null });
      }
    });

    it("echoes a valid X-Request-Id, replaces an invalid one, and is stateless", async () => {
      const tok = await tokenFor();
      const init = { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "t", version: "1" } } };
      const post = (rid?: string) => fetch(`${s.base}/mcp`, { method: "POST", headers: { ...MCP_HEADERS, authorization: `Bearer ${tok}`, ...(rid ? { "x-request-id": rid } : {}) }, body: JSON.stringify(init) });
      const ok = await post("proto-req-id-1234");
      expect(ok.status).toBe(200);
      expect(ok.headers.get("x-request-id")).toBe("proto-req-id-1234");
      expect(ok.headers.get("mcp-session-id")).toBeNull();
      expect(await ok.text()).toContain("imap-bridge");
      const bad = await post("bad id with spaces");
      expect(bad.headers.get("x-request-id")).toMatch(/^[0-9a-f-]{36}$/);
    });

    it("transport-level errors: wrong content type 415, missing Accept 406, bad JSON 400, notifications 202", async () => {
      const tok = await tokenFor();
      const h = { authorization: `Bearer ${tok}` };
      const ct = await fetch(`${s.base}/mcp`, { method: "POST", headers: { ...h, accept: MCP_HEADERS.accept, "content-type": "text/plain" }, body: "x" });
      expect(ct.status).toBe(415);
      const acc = await fetch(`${s.base}/mcp`, { method: "POST", headers: { ...h, "content-type": "application/json" }, body: "{}" });
      expect(acc.status).toBe(406);
      const bad = await fetch(`${s.base}/mcp`, { method: "POST", headers: { ...h, ...MCP_HEADERS }, body: "{nope" });
      expect(bad.status).toBe(400);
      expect(((await bad.json()) as any).error.code).toBe(-32700);
      const note = await fetch(`${s.base}/mcp`, { method: "POST", headers: { ...h, ...MCP_HEADERS }, body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) });
      expect(note.status).toBe(202);
    });
  });

  describe("unknown paths", () => {
    it("protocol paths answer 404 JSON for other methods and sub-paths", async () => {
      const cases: Array<[string, string]> = [
        ["GET", "/oauth/token"], ["PUT", "/oauth/token"], ["GET", "/oauth/register"], ["GET", "/oauth/revoke"],
        ["POST", "/healthz"], ["POST", "/readyz"], ["POST", "/.well-known/oauth-authorization-server"],
        ["GET", "/mcp/extra"], ["GET", "/healthz/x"], ["GET", "/.well-known/nothing"], ["POST", "/.well-known/oauth-protected-resource"],
        ["GET", "/api/does-not-exist"], ["HEAD", "/api/does-not-exist"], // (writes below /api are answered 403 by the CSRF middleware first)
        ["POST", "/dashboard"], ["PUT", "/nothing"], ["DELETE", "/nothing"], ["POST", "/oauth/authorize"],
      ];
      for (const [method, path] of cases) {
        const r = await fetch(`${s.base}${path}`, { method, ...(method === "POST" ? { body: "{}", headers: { "content-type": "application/json" } } : {}) });
        expect(r.status, `${method} ${path}`).toBe(404);
        expect(r.headers.get("content-type"), `${method} ${path}`).toMatch(/application\/json/);
      }
    });
    it("other GETs get the SPA document", async () => {
      for (const p of ["/", "/dashboard", "/some/deep/link", "/oauth/authorize"]) {
        const r = await fetch(`${s.base}${p}`, { headers: { accept: "text/html" } });
        expect(r.status, p).toBe(200);
        expect(r.headers.get("content-type"), p).toMatch(/text\/html/);
        expect(await r.text(), p).toMatch(/<html/i);
      }
    });
  });

  describe("rate limits", () => {
    it("/oauth/token returns the OAuth-style 429 with Retry-After once its window is exhausted", async () => {
      const port = await freePort();
      const dir = mkdtempSync(join(tmpdir(), "imap2mcp-proto-rl-"));
      const r = launch(join(dir, "data"), port);
      try {
        await waitListening(r);
        let last: Response | undefined;
        for (let i = 0; i < 62; i++) {
          last = await fetch(`${r.base}/oauth/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: "grant_type=x" });
          if (last.status === 429) break;
        }
        expect(last!.status).toBe(429);
        expect(Number(last!.headers.get("retry-after"))).toBeGreaterThan(0);
        expect(await last!.json()).toEqual({ error: "too_many_requests", error_description: "Too many token requests" });
        // health has its own, larger budget and is unaffected
        expect((await fetch(`${r.base}/healthz`)).status).toBe(200);
      } finally {
        r.proc.kill("SIGKILL"); await r.exited(); rmSync(dir, { recursive: true, force: true });
      }
    }, 60_000);
  });
});

describe("process lifecycle (built server)", () => {
  it("fails closed with FATAL and exit code 1 on invalid configuration, before listening", async () => {
    const dir = mkdtempSync(join(tmpdir(), "imap2mcp-proto-fatal-"));
    try {
      for (const env of [{ SESSION_SECRET: "short" }, { ENCRYPTION_KEY: "nothex" }, { REGISTRATION_MODE: "bogus" }]) {
        const r = launch(join(dir, "data"), await freePort(), env);
        expect(await r.exited(), JSON.stringify(env)).toBe(1);
        expect(r.output()).toMatch(/FATAL: /);
        expect(r.output()).not.toMatch(/IMAP Bridge listening/);
      }
    } finally { rmSync(dir, { recursive: true, force: true }); }
  }, 60_000);

  it("fails closed when the database cannot be opened", async () => {
    const dir = mkdtempSync(join(tmpdir(), "imap2mcp-proto-fatal-"));
    try {
      const { writeFileSync, mkdirSync } = await import("node:fs");
      mkdirSync(join(dir, "data"), { recursive: true });
      writeFileSync(join(dir, "data", "bridge.db"), "this is not a sqlite database, at all, really not");
      const r = launch(join(dir, "data"), await freePort());
      expect(await r.exited()).toBe(1);
      expect(r.output()).toMatch(/FATAL: database could not be opened/);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  }, 60_000);

  it("logs the listening line, then exits 0 on SIGTERM and checkpoints the WAL", async () => {
    const dir = mkdtempSync(join(tmpdir(), "imap2mcp-proto-term-"));
    const port = await freePort();
    const r = launch(join(dir, "data"), port);
    try {
      await waitListening(r);
      const line = r.output().split("\n").find((l) => l.includes("IMAP Bridge listening"))!;
      expect(JSON.parse(line)).toMatchObject({ msg: "IMAP Bridge listening", baseUrl: r.base, mcp: `${r.base}/mcp`, port });
      expect((await fetch(`${r.base}/healthz`)).status).toBe(200);
      r.proc.kill("SIGTERM");
      const code = await Promise.race([r.exited(), new Promise<"timeout">((res) => setTimeout(() => res("timeout"), 20_000))]);
      expect(code).toBe(0);
      expect(r.output()).toContain("shutting down");
      await expect(fetch(`${r.base}/healthz`)).rejects.toThrow();
      expect(existsSync(join(dir, "data", "bridge.db-wal")) ? (await import("node:fs")).statSync(join(dir, "data", "bridge.db-wal")).size : 0).toBe(0);
    } finally {
      if (r.proc.exitCode === null) { r.proc.kill("SIGKILL"); await r.exited(); }
      rmSync(dir, { recursive: true, force: true });
    }
  }, 60_000);

  it("honours NITRO_PORT-less PORT and exits 0 on SIGINT as well", async () => {
    const dir = mkdtempSync(join(tmpdir(), "imap2mcp-proto-int-"));
    const r = launch(join(dir, "data"), await freePort());
    try {
      await waitListening(r);
      r.proc.kill("SIGINT");
      expect(await r.exited()).toBe(0);
    } finally {
      if (r.proc.exitCode === null) { r.proc.kill("SIGKILL"); await r.exited(); }
      rmSync(dir, { recursive: true, force: true });
    }
  }, 60_000);
});
