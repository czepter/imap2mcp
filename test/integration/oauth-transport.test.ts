/**
 * Version 0 acceptance criterion 1: OAuth authorization-code + PKCE -> tool calls over Streamable HTTP;
 * missing / expired / wrong-audience / revoked / invalid tokens rejected; Basic and static tokens cannot authorize.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import type { OAuthClientProvider } from "@modelcontextprotocol/sdk/client/auth.js";
import { makeSelfSignedCert } from "../helpers/certs.js";
import {
  createStack, obtainToken, registerClient, consent, exchange, pkce, rawMcp, Mcp, sha256hex, hiddenFields, REDIRECT, msg, type Stack,
} from "../helpers/stack.js";

const haveOpenssl = !!makeSelfSignedCert();
if (!haveOpenssl) console.warn("SKIPPED oauth-transport: openssl not available to create the fixture TLS certificate");

describe.skipIf(!haveOpenssl)("OAuth + Streamable HTTP", () => {
  let s: Stack;
  let alice: string;
  let shared: string; // one client reused where lineage/disable semantics do not matter (registration is rate limited)
  beforeAll(async () => {
    s = await createStack();
    alice = s.mailbox["alice@example.test"];
    shared = await registerClient(s.base);
    s.fake.addMessage("alice@example.test", "INBOX", msg("Hello world"));
  });
  afterAll(async () => { await s?.teardown(); });

  describe("discovery metadata", () => {
    it("advertises S256 only, public clients, and the /mcp resource", async () => {
      const as = await (await fetch(`${s.base}/.well-known/oauth-authorization-server`)).json() as any;
      expect(as.code_challenge_methods_supported).toEqual(["S256"]);
      expect(as.token_endpoint_auth_methods_supported).toEqual(["none"]);
      expect(as.authorization_endpoint).toBe(`${s.base}/oauth/authorize`);
      const pr = await (await fetch(`${s.base}/.well-known/oauth-protected-resource`)).json() as any;
      expect(pr.resource).toBe(`${s.base}/mcp`);
      expect(pr.authorization_servers).toContain(s.base);
    });
    it("401 on /mcp carries a WWW-Authenticate Bearer challenge pointing at resource metadata", async () => {
      const r = await rawMcp(s.base);
      expect(r.status).toBe(401);
      expect(r.headers.get("www-authenticate")).toMatch(/^Bearer .*resource_metadata=/);
    });
  });

  describe("authorization-code flow with PKCE", () => {
    it("completes via the MCP SDK's own OAuth client (discovery, dynamic registration, PKCE) and calls a tool", async () => {
      let authUrl: URL | undefined;
      let clientInfo: any, tokens: any, verifier = "";
      const provider: OAuthClientProvider = {
        get redirectUrl() { return REDIRECT; },
        get clientMetadata() {
          return { client_name: "sdk-client", redirect_uris: [REDIRECT], grant_types: ["authorization_code", "refresh_token"], response_types: ["code"], token_endpoint_auth_method: "none", scope: "mail:read" };
        },
        clientInformation: () => clientInfo,
        saveClientInformation: (i: any) => { clientInfo = i; },
        tokens: () => tokens,
        saveTokens: (t: any) => { tokens = t; },
        redirectToAuthorization: (u: URL) => { authUrl = u; },
        saveCodeVerifier: (v: string) => { verifier = v; },
        codeVerifier: () => verifier,
      } as any;

      const url = new URL(`${s.base}/mcp`);
      const t1 = new StreamableHTTPClientTransport(url, { authProvider: provider });
      const c1 = new Client({ name: "sdk", version: "1" });
      await expect(c1.connect(t1)).rejects.toThrow(); // Unauthorized -> redirectToAuthorization
      expect(authUrl).toBeDefined();
      expect(authUrl!.searchParams.get("code_challenge_method")).toBe("S256");
      expect(authUrl!.searchParams.get("resource")).toBe(`${s.base}/mcp`);

      // The owner approves in the browser.
      const page = await s.admin.get(authUrl!.pathname + authUrl!.search);
      expect(page.status).toBe(200);
      const form = hiddenFields(await page.text());
      form[`g_${alice}_read`] = "1";
      form.decision = "approve";
      const done = await s.admin.post("/oauth/authorize", form);
      const code = new URL(done.headers.get("location")!).searchParams.get("code")!;
      expect(code).toBeTruthy();

      await t1.finishAuth(code);
      expect(tokens?.access_token).toBeTruthy();

      const t2 = new StreamableHTTPClientTransport(url, { authProvider: provider });
      const c2 = new Client({ name: "sdk", version: "1" });
      await c2.connect(t2);
      const r: any = await c2.callTool({ name: "list_mailboxes", arguments: {} });
      expect(JSON.parse(r.content[0].text).mailboxes.map((m: any) => m.id)).toEqual([alice]);
      await c2.close();
    });

    it("issues 1h access / 30d refresh tokens, opaque and not stored in plaintext", async () => {
      const { tokens } = await obtainToken(s, [[alice, "read"]]);
      expect(tokens.token_type).toBe("Bearer");
      expect(tokens.expires_in).toBe(3600);
      expect(tokens.access_token).toMatch(/^[A-Za-z0-9_-]{43}$/);
      const row = s.srv.db().prepare("SELECT * FROM oauth_tokens WHERE token_hash = ?").get(sha256hex(tokens.access_token)) as any;
      expect(row).toBeTruthy();
      expect(row.resource).toBe(`${s.base}/mcp`);
      const refreshDays = (Date.parse(row.refresh_expires_at) - Date.parse(row.created_at.replace(" ", "T") + "Z")) / 86_400_000;
      expect(refreshDays).toBeGreaterThan(29.9);
      expect(refreshDays).toBeLessThan(30.1);
      const dump = JSON.stringify(s.srv.db().prepare("SELECT * FROM oauth_tokens").all());
      expect(dump).not.toContain(tokens.access_token);
      expect(dump).not.toContain(tokens.refresh_token);
    });

    it("rejects: wrong PKCE verifier, code reuse, wrong redirect_uri, other client's code", async () => {
      const clientId = await registerClient(s.base);
      const c = await consent(s.admin, s.base, { clientId, grants: [[alice, "read"]] });
      const code = new URL(c.location).searchParams.get("code")!;
      expect((await exchange(s.base, clientId, code, pkce().verifier)).status).toBe(400); // wrong verifier (consumes the code)
      expect((await exchange(s.base, clientId, code, c.pkce.verifier)).status).toBe(400); // code already burnt

      const c2 = await consent(s.admin, s.base, { clientId, grants: [[alice, "read"]] });
      const code2 = new URL(c2.location).searchParams.get("code")!;
      expect((await exchange(s.base, clientId, code2, c2.pkce.verifier, { redirect_uri: "http://localhost:9/other" })).status).toBe(400);

      const other = await registerClient(s.base);
      const c3 = await consent(s.admin, s.base, { clientId, grants: [[alice, "read"]] });
      const code3 = new URL(c3.location).searchParams.get("code")!;
      expect((await exchange(s.base, other, code3, c3.pkce.verifier)).status).toBeGreaterThanOrEqual(400);

      const c4 = await consent(s.admin, s.base, { clientId, grants: [[alice, "read"]] });
      const code4 = new URL(c4.location).searchParams.get("code")!;
      const ok = await exchange(s.base, clientId, code4, c4.pkce.verifier);
      expect(ok.status).toBe(200);
    });

    it("authorize requires PKCE S256 and rejects plain / missing challenge and foreign resource", async () => {
      const clientId = await registerClient(s.base);
      const q = (extra: Record<string, string>) => new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: REDIRECT, ...extra });
      const base = pkce();
      const noPkce = await s.admin.get(`/oauth/authorize?${q({})}`);
      expect(noPkce.status).toBe(302);
      expect(noPkce.headers.get("location")).toContain("error=invalid_request");
      const plain = await s.admin.get(`/oauth/authorize?${q({ code_challenge: base.challenge, code_challenge_method: "plain" })}`);
      expect(plain.headers.get("location")).toContain("error=invalid_request");
      const res = await s.admin.get(`/oauth/authorize?${q({ code_challenge: base.challenge, code_challenge_method: "S256", resource: "https://evil.example/mcp" })}`);
      expect(res.headers.get("location")).toContain("error=invalid_target");
      const badRedirect = await s.admin.get(`/oauth/authorize?${new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: "http://localhost:1/not-registered", code_challenge: base.challenge, code_challenge_method: "S256" })}`);
      expect(badRedirect.status).toBe(400); // never redirects to an unregistered URI
    });

    it("refresh rotates the refresh token; reusing the old one fails", async () => {
      const { clientId, tokens } = await obtainToken(s, [[alice, "read"]]);
      const refresh = async (rt: string) => fetch(`${s.base}/oauth/token`, {
        method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ grant_type: "refresh_token", client_id: clientId, refresh_token: rt }),
      });
      const r1 = await refresh(tokens.refresh_token);
      expect(r1.status).toBe(200);
      const t2 = await r1.json() as any;
      expect(t2.refresh_token).not.toBe(tokens.refresh_token);
      // the rotated-in tokens work
      const mcp = await new Mcp(s.base, t2.access_token).connect();
      expect((await mcp.call("list_mailboxes")).isError).toBe(false);
      // the old access token died with the rotation
      expect((await rawMcp(s.base, `Bearer ${tokens.access_token}`)).status).toBe(401);
      // replaying the old refresh token is refused AND (reuse detection) burns the lineage
      expect((await refresh(tokens.refresh_token)).status).toBe(400);
      expect((await rawMcp(s.base, `Bearer ${t2.access_token}`)).status).toBe(401);
      await mcp.close();
    });
  });

  describe("token endpoint details", () => {
    it("refuses client authentication via the Authorization header (public clients only)", async () => {
      const clientId = shared;
      const c = await consent(s.admin, s.base, { clientId, grants: [[alice, "read"]] });
      const code = new URL(c.location).searchParams.get("code")!;
      const r = await exchange(s.base, clientId, code, c.pkce.verifier);
      expect(r.status).toBe(200);
      const c2 = await consent(s.admin, s.base, { clientId, grants: [[alice, "read"]] });
      const code2 = new URL(c2.location).searchParams.get("code")!;
      const basic = await fetch(`${s.base}/oauth/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded", authorization: "Basic " + Buffer.from(`${clientId}:secret`).toString("base64") },
        body: new URLSearchParams({ grant_type: "authorization_code", client_id: clientId, code: code2, code_verifier: c2.pkce.verifier, redirect_uri: REDIRECT }),
      });
      expect(basic.status).toBe(401);
    });
    it("a refresh may narrow scopes but never widen them", async () => {
      const { clientId, tokens } = await obtainToken(s, [[alice, "read"], [alice, "draft"]]);
      expect(tokens.scope.split(" ").sort()).toEqual(["mail:draft", "mail:read"]);
      const refresh = (rt: string, scope: string) => fetch(`${s.base}/oauth/token`, {
        method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ grant_type: "refresh_token", client_id: clientId, refresh_token: rt, scope }),
      });
      expect((await refresh(tokens.refresh_token, "mail:read mail:organize")).status).toBe(400); // organize was never consented
      const narrowed = await refresh(tokens.refresh_token, "mail:read"); // the refused attempt did not burn the refresh token
      expect(narrowed.status).toBe(200);
      expect(((await narrowed.json()) as any).scope).toBe("mail:read");
    });
  });

  describe("dynamic client registration", () => {
    it("accepts https and loopback http redirect URIs, grants nothing by itself", async () => {
      const id = await registerClient(s.base, ["https://client.example/cb", "http://localhost:4000/cb", "http://127.0.0.1:4001/cb"]);
      expect(s.srv.db().prepare("SELECT COUNT(*) n FROM grants WHERE client_id = ?").get(id)).toEqual({ n: 0 });
    });
    it.each([["http://evil.example/cb"], ["javascript:alert(1)"], ["https://x.example/cb#frag"], ["not a url"]])("rejects redirect URI %s", async (uri) => {
      const r = await fetch(`${s.base}/oauth/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ redirect_uris: [uri] }) });
      expect(r.status).toBe(400);
    });
    it("a registered client with no consent cannot reach any mailbox", async () => {
      const clientId = await registerClient(s.base);
      const c = await consent(s.admin, s.base, { clientId, grants: [], });
      expect(c.location).toContain("error=access_denied");
    });
    it("REGISTRATION_MODE=admin refuses dynamic registration", async () => {
      const s2 = await createStack({ skipMailboxes: true, env: { REGISTRATION_MODE: "admin" } });
      try {
        const r = await fetch(`${s2.base}/oauth/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ redirect_uris: [REDIRECT] }) });
        expect(r.status).toBe(403);
        // admin can still create a client through the UI
        const created = await s2.admin.postWithCsrf("/dashboard", "/clients", { client_name: "ui-client", redirect_uris: REDIRECT });
        expect(created.status).toBe(302);
        expect(created.headers.get("location")).toMatch(/^\/clients\//);
      } finally { await s2.teardown(); }
    });
  });

  describe("MCP endpoint rejects anything but a valid, live, audience-bound bearer token", () => {
    let good: string;
    beforeAll(async () => { good = (await obtainToken(s, [[alice, "read"]], { clientId: shared })).tokens.access_token; });

    it("accepts the valid token", async () => {
      const r = await rawMcp(s.base, `Bearer ${good}`);
      expect(r.status).toBe(200);
    });
    it("rejects a request with no credentials", async () => { expect((await rawMcp(s.base)).status).toBe(401); });
    it("rejects garbage tokens", async () => {
      for (const t of ["garbage", "a".repeat(43), "", "null", "Bearer", "' OR 1=1 --"]) {
        expect((await rawMcp(s.base, `Bearer ${t}`)).status, t).toBe(401);
      }
    });
    it("rejects an expired token", async () => {
      const { tokens } = await obtainToken(s, [[alice, "read"]], { clientId: shared });
      expect((await rawMcp(s.base, `Bearer ${tokens.access_token}`)).status).toBe(200);
      s.srv.db().prepare("UPDATE oauth_tokens SET expires_at = ? WHERE token_hash = ?").run(new Date(Date.now() - 1000).toISOString(), sha256hex(tokens.access_token));
      expect((await rawMcp(s.base, `Bearer ${tokens.access_token}`)).status).toBe(401);
    });
    it("rejects a token whose audience is not this server's /mcp resource", async () => {
      const { tokens } = await obtainToken(s, [[alice, "read"]], { clientId: shared });
      s.srv.db().prepare("UPDATE oauth_tokens SET resource = ? WHERE token_hash = ?").run("https://other-server.example/mcp", sha256hex(tokens.access_token));
      expect((await rawMcp(s.base, `Bearer ${tokens.access_token}`)).status).toBe(401);
    });
    it("token endpoint refuses a foreign resource indicator", async () => {
      const clientId = shared;
      const c = await consent(s.admin, s.base, { clientId, grants: [[alice, "read"]] });
      const code = new URL(c.location).searchParams.get("code")!;
      const r = await exchange(s.base, clientId, code, c.pkce.verifier, { resource: "https://other-server.example/mcp" });
      expect(r.status).toBe(400);
    });
    it("rejects a revoked token (admin UI), including on an already-connected client", async () => {
      const { tokens } = await obtainToken(s, [[alice, "read"]], { clientId: shared });
      const live = await new Mcp(s.base, tokens.access_token).connect();
      expect((await live.call("list_mailboxes")).isError).toBe(false);
      const id = (s.srv.db().prepare("SELECT id FROM oauth_tokens WHERE token_hash = ?").get(sha256hex(tokens.access_token)) as any).id;
      const r = await s.admin.postWithCsrf("/dashboard", `/tokens/${id}/revoke`, {});
      expect(r.status).toBe(302);
      expect((await rawMcp(s.base, `Bearer ${tokens.access_token}`)).status).toBe(401);
      await expect(live.call("list_mailboxes")).rejects.toThrow();
      await live.close();
    });
    it("rejects a token revoked at the OAuth revocation endpoint", async () => {
      const { clientId, tokens } = await obtainToken(s, [[alice, "read"]], { clientId: shared });
      const rv = await fetch(`${s.base}/oauth/revoke`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ token: tokens.access_token, client_id: clientId }) });
      expect(rv.status).toBe(200);
      expect((await rawMcp(s.base, `Bearer ${tokens.access_token}`)).status).toBe(401);
    });
    it("rejects tokens of a disabled client", async () => {
      const { clientId, tokens } = await obtainToken(s, [[alice, "read"]]);
      const r = await s.admin.postWithCsrf("/dashboard", `/clients/${clientId}/disable`, {});
      expect(r.status).toBe(302);
      expect((await rawMcp(s.base, `Bearer ${tokens.access_token}`)).status).toBe(401);
    });
    it("rejects HTTP Basic auth (admin password, client id, anything)", async () => {
      const b = (u: string, p: string) => "Basic " + Buffer.from(`${u}:${p}`).toString("base64");
      const clientId = shared;
      for (const h of [b("admin", s.adminPassword), b("owner", s.adminPassword), b(clientId, ""), b(clientId, good), b("alice@example.test", s.imapPasswords["alice@example.test"])]) {
        expect((await rawMcp(s.base, h)).status).toBe(401);
      }
    });
    it("rejects static / pre-shared secrets presented as bearer tokens", async () => {
      const candidates = [s.bootstrap, s.work.sessionSecret, s.work.keyHex, s.adminPassword, s.imapPasswords["alice@example.test"], sha256hex(good)];
      for (const t of candidates) expect((await rawMcp(s.base, `Bearer ${t}`)).status, t.slice(0, 6)).toBe(401);
    });
    it("rejects an admin session cookie and API-key style headers", async () => {
      const r = await fetch(`${s.base}/mcp`, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json, text/event-stream", cookie: s.admin.cookies(), "x-api-key": s.work.sessionSecret },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
      });
      expect(r.status).toBe(401);
    });
    it("also rejects bad credentials on GET and DELETE", async () => {
      for (const method of ["GET", "DELETE"]) {
        const r = await fetch(`${s.base}/mcp`, { method, headers: { authorization: "Bearer nope" } });
        expect(r.status).toBe(401);
      }
    });
  });
});
