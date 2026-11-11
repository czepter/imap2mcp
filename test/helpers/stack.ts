import { createHash, randomBytes } from "node:crypto";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { Browser, json } from "./http.js";
import type { AuthorizeParams, AuthorizeRequest, Mailbox, MailboxTestResult } from "../../shared/types/api.js";
import { FakeImapServer } from "./fakeImap.js";
import { makeSelfSignedCert, type TestCert } from "./certs.js";
import { bootstrapTokenFrom, makeWorkdir, startServer, type RunningServer, type Workdir } from "./server.js";

export const sha256hex = (s: string) => createHash("sha256").update(s).digest("hex");
export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export async function waitFor<T>(fn: () => T | null | undefined | false, ms = 5000): Promise<T> {
  const end = Date.now() + ms;
  for (;;) {
    const v = fn();
    if (v) return v as T;
    if (Date.now() > end) throw new Error("waitFor timed out");
    await sleep(50);
  }
}

export type Cap = "read" | "draft" | "organize";
export const ALL_CAPS: Cap[] = ["read", "draft", "organize"];

export interface Pkce { verifier: string; challenge: string }
export function pkce(): Pkce {
  const verifier = randomBytes(32).toString("base64url");
  return { verifier, challenge: createHash("sha256").update(verifier).digest("base64url") };
}

export interface Tokens { access_token: string; refresh_token: string; expires_in: number; scope: string; token_type: string }

export const REDIRECT = "http://localhost:8765/callback";

export interface Stack {
  cert: TestCert;
  fake: FakeImapServer;
  work: Workdir;
  srv: RunningServer;
  admin: Browser;
  adminPassword: string;
  bootstrap: string;
  base: string;
  /** mailbox ids by fake account user */
  mailbox: Record<string, string>;
  imapPasswords: Record<string, string>;
  accounts: string[];
  restart(env?: Record<string, string | undefined>): Promise<void>;
  teardown(): Promise<void>;
}

export const ACCOUNTS = ["alice@example.test", "bob@example.test"];

export async function createStack(o: { accounts?: string[]; move?: boolean; skipMailboxes?: boolean; noCa?: boolean; env?: Record<string, string | undefined>; /** configure the fake IMAP server before it starts listening (v2 fault knobs) */ fake?: (f: FakeImapServer) => void } = {}): Promise<Stack> {
  const cert = makeSelfSignedCert();
  if (!cert) throw new Error("openssl unavailable");
  const accounts = o.accounts ?? ACCOUNTS;
  const imapPasswords: Record<string, string> = {};
  const fake = new FakeImapServer({ key: cert.key, cert: cert.cert, move: o.move });
  for (const a of accounts) {
    imapPasswords[a] = "ImapPw-" + randomBytes(9).toString("hex");
    fake.addAccount(a, imapPasswords[a]);
  }
  o.fake?.(fake);
  await fake.start();
  const work = makeWorkdir();
  const srv = await startServer({ work, caFile: o.noCa ? undefined : cert.certPath, env: o.env });
  const bootstrap = await waitFor(() => bootstrapTokenFrom(srv.output()));
  const admin = new Browser(srv.baseUrl);
  const adminPassword = "Admin-" + randomBytes(9).toString("hex");

  const stack: Stack = {
    cert, fake, work, srv, admin, adminPassword, bootstrap, base: srv.baseUrl, mailbox: {}, imapPasswords, accounts,
    async restart(env) {
      await stack.srv.stop();
      stack.srv = await startServer({ work, caFile: o.noCa ? undefined : cert.certPath, env: { ...o.env, ...env }, port: stack.srv.port });
      stack.admin = new Browser(stack.srv.baseUrl);
    },
    async teardown() {
      await stack.srv.stop().catch(() => {});
      await fake.stop().catch(() => {});
      work.cleanup();
    },
  };

  await setupAdmin(stack);
  for (const a of o.skipMailboxes ? [] : accounts) {
    stack.mailbox[a] = await addMailbox(stack, { label: `Box ${a.split("@")[0]}`, host: "localhost", port: fake.port, user: a, pass: imapPasswords[a] });
  }
  return stack;
}

export async function setupAdmin(s: Stack): Promise<void> {
  const r = await s.admin.postWithCsrf("/api/setup", { token: s.bootstrap, password: s.adminPassword, password2: s.adminPassword });
  if (r.status !== 204) throw new Error(`setup failed: ${r.status} ${await r.text()}`);
}

/** POST /api/login. 204 on success; the caller asserts the status (401 wrong password, 429 rate limited, 403 CSRF). */
export async function adminLogin(b: Browser, password: string): Promise<Response> {
  return b.postWithCsrf("/api/login", { password });
}

/** Creates a mailbox through the admin API WITHOUT testing it or choosing a Drafts folder. Returns its id. */
export async function addMailboxRaw(s: Pick<Stack, "admin">, m: { label: string; host: string; port: number; user: string; pass: string }): Promise<string> {
  const r = await s.admin.postWithCsrf("/api/mailboxes", { label: m.label, host: m.host, port: m.port, username: m.user, password: m.pass });
  if (r.status !== 201) throw new Error(`add mailbox failed: ${r.status} ${await r.text()}`);
  return (await json<Mailbox>(r)).id;
}

/** POST /api/mailboxes/:id/test -> parsed result. */
export async function testMailbox(s: Pick<Stack, "admin">, id: string): Promise<MailboxTestResult> {
  const r = await s.admin.postWithCsrf(`/api/mailboxes/${id}/test`);
  if (r.status !== 200) throw new Error(`mailbox test request failed: ${r.status} ${await r.text()}`);
  return json<MailboxTestResult>(r);
}

/** Adds a mailbox through the admin API, runs the connection test, and selects the Drafts folder. */
export async function addMailbox(s: Pick<Stack, "admin">, m: { label: string; host: string; port: number; user: string; pass: string }): Promise<string> {
  const id = await addMailboxRaw(s, m);
  const t = await testMailbox(s, id);
  if (!t.ok) throw new Error(`mailbox test failed: ${t.message}`);
  const d = await s.admin.putWithCsrf(`/api/mailboxes/${id}/drafts`, { folder: "Drafts" });
  if (d.status !== 204) throw new Error(`set drafts failed: ${d.status} ${await d.text()}`);
  return id;
}

export async function registerClient(base: string, redirectUris = [REDIRECT], name = "test-client"): Promise<string> {
  const r = await fetch(`${base}/oauth/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ client_name: name, redirect_uris: redirectUris, token_endpoint_auth_method: "none", grant_types: ["authorization_code", "refresh_token"], response_types: ["code"] }),
  });
  if (r.status !== 201) throw new Error(`register failed ${r.status} ${await r.text()}`);
  return ((await r.json()) as { client_id: string }).client_id;
}

export interface AuthorizeOpts {
  clientId: string;
  /** [mailboxId, capability] ticks on the consent screen */
  grants: Array<[string, Cap]>;
  scope?: string;
  resource?: string;
  redirectUri?: string;
  pkce?: Pkce;
  decision?: "approve" | "deny";
}

/** Query string of an authorization request as the client would send it. */
export function authorizeQuery(o: Pick<AuthorizeOpts, "clientId" | "scope" | "resource" | "redirectUri"> & { pkce: Pkce }): URLSearchParams {
  const q = new URLSearchParams({
    response_type: "code", client_id: o.clientId, redirect_uri: o.redirectUri ?? REDIRECT, state: "st-" + randomBytes(4).toString("hex"),
    code_challenge: o.pkce.challenge, code_challenge_method: "S256", scope: o.scope ?? "mail:read mail:draft mail:organize",
  });
  if (o.resource) q.set("resource", o.resource);
  return q;
}

/**
 * Drives the consent screen's API as the logged-in owner: GET /api/oauth/authorize (validate + describe), then
 * POST /api/oauth/authorize with the echoed params, the ticks and the decision. Returns the `redirectTo` (code or
 * error) as `location`, or `status:<n>` when the API answered with an HTTP error instead of a redirect target.
 */
export async function consentQuery(admin: Browser, query: URLSearchParams | string, grants: Array<[string, Cap]>, decision: "approve" | "deny" = "approve"): Promise<{ location: string }> {
  const page = await admin.get(`/api/oauth/authorize?${query}`);
  const text = await page.text();
  let body: Partial<AuthorizeRequest> & { redirectTo?: string } = {};
  try { body = JSON.parse(text); } catch { /* not JSON */ }
  if (typeof body.redirectTo === "string") return { location: body.redirectTo }; // protocol error reported to the client
  if (page.status !== 200) return { location: `status:${page.status}` };
  const params = body.params as AuthorizeParams;
  const r = await admin.postWithCsrf("/api/oauth/authorize", { params, decision, grants: grants.map(([mailboxId, capability]) => ({ mailboxId, capability })) });
  let out: { redirectTo?: string } = {};
  try { out = JSON.parse(await r.text()); } catch { /* not JSON */ }
  return { location: typeof out.redirectTo === "string" ? out.redirectTo : `status:${r.status}` };
}

export async function consent(admin: Browser, _base: string, o: AuthorizeOpts): Promise<{ location: string; pkce: Pkce }> {
  const p = o.pkce ?? pkce();
  const q = authorizeQuery({ ...o, pkce: p });
  const { location } = await consentQuery(admin, q, o.grants, o.decision ?? "approve");
  return { location, pkce: p };
}

export async function exchange(base: string, clientId: string, code: string, verifier: string, extra: Record<string, string> = {}): Promise<Response> {
  return fetch(`${base}/oauth/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "authorization_code", client_id: clientId, code, code_verifier: verifier, redirect_uri: REDIRECT, ...extra }),
  });
}

/** register -> consent -> token. Returns tokens and ids. */
export async function obtainToken(s: Stack, grants: Array<[string, Cap]>, o: { scope?: string; clientId?: string; name?: string } = {}): Promise<{ clientId: string; tokens: Tokens }> {
  const clientId = o.clientId ?? (await registerClient(s.base, [REDIRECT], o.name));
  const c = await consent(s.admin, s.base, { clientId, grants, scope: o.scope });
  const code = new URL(c.location).searchParams.get("code");
  if (!code) throw new Error(`no code in ${c.location}`);
  const r = await exchange(s.base, clientId, code, c.pkce.verifier);
  if (r.status !== 200) throw new Error(`token exchange failed ${r.status} ${await r.text()}`);
  return { clientId, tokens: (await r.json()) as Tokens };
}

/** PUT /api/clients/:id/grants: the complete desired preset set (everything not listed is revoked). */
export async function setGrants(s: Pick<Stack, "admin">, clientId: string, grants: Array<[string, Cap]>): Promise<void> {
  const r = await s.admin.putWithCsrf(`/api/clients/${clientId}/grants`, { grants: grants.map(([mailboxId, capability]) => ({ mailboxId, capability })) });
  if (r.status !== 204) throw new Error(`set grants failed ${r.status} ${await r.text()}`);
}

export interface ToolResult { isError: boolean; data: any; text: string }

export class Mcp {
  private client = new Client({ name: "it-client", version: "0.0.0" });
  private connected = false;
  constructor(private base: string, private token: string) {}
  async connect(): Promise<this> {
    const t = new StreamableHTTPClientTransport(new URL(this.base + "/mcp"), { requestInit: { headers: { Authorization: `Bearer ${this.token}` } } });
    await this.client.connect(t);
    this.connected = true;
    return this;
  }
  async tools(): Promise<string[]> {
    return (await this.client.listTools()).tools.map((t) => t.name);
  }
  /** Full tool definitions as advertised by tools/list (name, title, annotations, schemas). */
  async toolDefs() {
    if (!this.connected) await this.connect();
    return (await this.client.listTools()).tools;
  }
  async call(name: string, args: Record<string, unknown> = {}): Promise<ToolResult> {
    if (!this.connected) await this.connect();
    const r: any = await this.client.callTool({ name, arguments: args });
    const text: string = r.content?.[0]?.text ?? "";
    let data: any = text;
    try { data = JSON.parse(text); } catch { /* keep text */ }
    return { isError: !!r.isError, data, text };
  }
  async close() {
    await this.client.close().catch(() => {});
  }
}

/** Raw POST to /mcp (JSON-RPC tools/list) with an arbitrary Authorization header. */
export async function rawMcp(base: string, authorization?: string, extra: Record<string, string> = {}): Promise<Response> {
  return fetch(`${base}/mcp`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      ...(authorization ? { authorization } : {}),
      ...extra,
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }),
  });
}

export const msg = (subject: string, body = "Body of " + subject, from = "Sender <sender@example.org>") =>
  `From: ${from}\r\nTo: owner@example.test\r\nSubject: ${subject}\r\nDate: Fri, 02 Jan 2026 03:04:05 +0000\r\nMessage-ID: <${randomBytes(6).toString("hex")}@example.org>\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n${body}\r\n`;

export function refOf(s: Stack, user: string, folder: string, uid: number) {
  return { mailbox: s.mailbox[user], folder, uidValidity: s.fake.folder(user, folder).uidValidity, uid };
}

/** A server with NO admin yet (fresh data dir) and a known bootstrap token, for setup/login/session tests. */
export interface Bare {
  work: Workdir;
  srv: RunningServer;
  base: string;
  bootstrap: string;
  restart(env?: Record<string, string | undefined>): Promise<void>;
  teardown(): Promise<void>;
}
export async function createBare(o: { env?: Record<string, string | undefined> } = {}): Promise<Bare> {
  const work = makeWorkdir();
  const bootstrap = "bootstrap-" + randomBytes(10).toString("hex");
  const env = { ADMIN_BOOTSTRAP_TOKEN: bootstrap, ...o.env };
  const bare: Bare = {
    work, bootstrap, srv: await startServer({ work, env }), base: "",
    async restart(e) {
      await bare.srv.stop();
      bare.srv = await startServer({ work, env: { ...env, ...e }, port: bare.srv.port });
      bare.base = bare.srv.baseUrl;
    },
    async teardown() { await bare.srv.stop().catch(() => {}); work.cleanup(); },
  };
  bare.base = bare.srv.baseUrl;
  return bare;
}
