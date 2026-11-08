import { createHash, randomBytes } from "node:crypto";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { Browser, location } from "./http.js";
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

export function hiddenFields(html: string): Record<string, string> {
  const out: Record<string, string> = {};
  const un = (s: string) => s.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
  for (const m of html.matchAll(/<input type="hidden" name="([^"]+)" value="([^"]*)"/g)) out[m[1]] = un(m[2]);
  return out;
}

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
  const r = await s.admin.postWithCsrf("/setup", "/setup", { token: s.bootstrap, password: s.adminPassword, password2: s.adminPassword });
  if (r.status !== 302) throw new Error(`setup failed: ${r.status} ${await r.text()}`);
}

export async function adminLogin(b: Browser, password: string): Promise<Response> {
  return b.postWithCsrf("/login", "/login", { password });
}

/** Adds a mailbox through the real UI, runs the connection test, and selects the Drafts folder. */
export async function addMailbox(s: Stack, m: { label: string; host: string; port: number; user: string; pass: string }): Promise<string> {
  const r = await s.admin.postWithCsrf("/mailboxes/new", "/mailboxes", { label: m.label, host: m.host, port: String(m.port), username: m.user, password: m.pass });
  if (r.status !== 302) throw new Error(`add mailbox failed: ${r.status} ${await r.text()}`);
  const id = /\/mailboxes\/([^?/]+)/.exec(location(r))![1];
  const t = await s.admin.postWithCsrf(`/mailboxes/${id}`, `/mailboxes/${id}/test`, {});
  const html = await t.text();
  if (!/Connected\./.test(html)) throw new Error(`mailbox test failed: ${html.replace(/<[^>]+>/g, " ").slice(0, 400)}`);
  const d = await s.admin.postWithCsrf(`/mailboxes/${id}`, `/mailboxes/${id}/drafts`, { drafts_folder: "Drafts" });
  if (d.status !== 302) throw new Error(`set drafts failed: ${d.status}`);
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

/** Drives the consent screen as the logged-in owner; returns the redirect Location (code or error). */
export async function consent(admin: Browser, base: string, o: AuthorizeOpts): Promise<{ location: string; pkce: Pkce }> {
  const p = o.pkce ?? pkce();
  const q = new URLSearchParams({
    response_type: "code", client_id: o.clientId, redirect_uri: o.redirectUri ?? REDIRECT, state: "st-" + randomBytes(4).toString("hex"),
    code_challenge: p.challenge, code_challenge_method: "S256", scope: o.scope ?? "mail:read mail:draft mail:organize",
  });
  if (o.resource) q.set("resource", o.resource);
  const page = await admin.get(`/oauth/authorize?${q}`);
  if (page.status !== 200) return { location: page.headers.get("location") ?? `status:${page.status}`, pkce: p };
  const html = await page.text();
  const form: Record<string, string> = hiddenFields(html);
  for (const [mid, cap] of o.grants) form[`g_${mid}_${cap}`] = "1";
  form.decision = o.decision ?? "approve";
  const r = await admin.post("/oauth/authorize", form);
  return { location: r.headers.get("location") ?? `status:${r.status}`, pkce: p };
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

export async function setGrants(s: Stack, clientId: string, grants: Array<[string, Cap]>): Promise<void> {
  const form: Record<string, string> = {};
  for (const [m, c] of grants) form[`g_${m}_${c}`] = "1";
  const r = await s.admin.postWithCsrf(`/clients/${clientId}`, `/clients/${clientId}/grants`, form);
  if (r.status !== 302) throw new Error(`set grants failed ${r.status}`);
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

/** Creates a mailbox through the UI WITHOUT testing it or choosing a Drafts folder. */
export async function addMailboxRaw(s: Stack, m: { label: string; host: string; port: number; user: string; pass: string }): Promise<string> {
  const r = await s.admin.postWithCsrf("/mailboxes/new", "/mailboxes", { label: m.label, host: m.host, port: String(m.port), username: m.user, password: m.pass });
  if (r.status !== 302) throw new Error(`add mailbox failed: ${r.status}`);
  return /\/mailboxes\/([^?/]+)/.exec(location(r))![1];
}
