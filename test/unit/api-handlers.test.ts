/**
 * Drives the admin API handlers (server/api/**) in-process through a real h3 router and a real SQLite database.
 * requireAdmin / readJsonBody (workstream A) are replaced by trivial stand-ins, so this covers the handlers' own
 * validation, transactions and DTOs, not session or CSRF handling. The mailbox test/drafts cases need a TLS cert that
 * Node already trusts: run with NODE_EXTRA_CA_CERTS=<dir>/cert.pem and <dir>/key.pem next to it (otherwise skipped).
 */
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { createServer, type Server } from "node:http";
import { mkdtempSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { createApp, createRouter, toNodeListener, readBody, send, setResponseStatus, type H3Event } from "h3";
import { randomBytes } from "node:crypto";

vi.mock("../../server/utils/requireAdmin", () => ({ requireAdmin: async () => {} }));
vi.mock("../../server/utils/readJson", () => ({
  readJsonBody: async (e: H3Event) => {
    const b = await readBody(e);
    if (!b || typeof b !== "object" || Array.isArray(b)) {
      const { createError } = await import("h3");
      throw createError({ statusCode: 400, message: "bad body", data: { code: "bad_request" } });
    }
    return b;
  },
}));

const caFile = process.env.NODE_EXTRA_CA_CERTS;
const haveCert = !!caFile && existsSync(join(dirname(caFile), "key.pem"));

let server: Server;
let base = "";
let fake: any;
const dataDir = mkdtempSync(join(tmpdir(), "api-handlers-"));

async function api(method: string, path: string, body?: unknown) {
  const res = await fetch(base + path, { method, headers: body === undefined ? {} : { "content-type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await res.text();
  let json: any = null;
  try { json = text ? JSON.parse(text) : null; } catch { /* not json */ }
  return { status: res.status, json, text, headers: res.headers };
}

beforeAll(async () => {
  Object.assign(process.env, {
    DATA_DIR: dataDir, BASE_URL: "http://localhost:3000", SESSION_SECRET: randomBytes(32).toString("hex"),
    ENCRYPTION_KEY: randomBytes(32).toString("hex"), REGISTRATION_MODE: "admin", ALLOW_PRIVATE_HOSTS: "localhost", SIDECAR_DISABLED: "1",
  });
  const { validateStartup } = await import("../../server/core/config.js");
  validateStartup();
  const routes: [string, string, string][] = [
    ["get", "/api/overview", "overview.get"],
    ["post", "/api/mailboxes", "mailboxes/index.post"],
    ["get", "/api/mailboxes/:id", "mailboxes/[id]/index.get"],
    ["patch", "/api/mailboxes/:id", "mailboxes/[id]/index.patch"],
    ["delete", "/api/mailboxes/:id", "mailboxes/[id]/index.delete"],
    ["post", "/api/mailboxes/:id/test", "mailboxes/[id]/test.post"],
    ["post", "/api/mailboxes/:id/retry", "mailboxes/[id]/retry.post"],
    ["put", "/api/mailboxes/:id/drafts", "mailboxes/[id]/drafts.put"],
    ["post", "/api/clients", "clients/index.post"],
    ["get", "/api/clients/:id", "clients/[id]/index.get"],
    ["put", "/api/clients/:id/grants", "clients/[id]/grants.put"],
    ["post", "/api/clients/:id/rules", "clients/[id]/rules/index.post"],
    ["delete", "/api/clients/:id/rules/:ruleId", "clients/[id]/rules/[ruleId].delete"],
    ["post", "/api/clients/:id/disable", "clients/[id]/disable.post"],
    ["post", "/api/clients/:id/enable", "clients/[id]/enable.post"],
    ["post", "/api/clients/:id/revoke", "clients/[id]/revoke.post"],
    ["post", "/api/tokens/:id/revoke", "tokens/[id]/revoke.post"],
    ["get", "/api/audit", "audit/index.get"],
    ["get", "/api/audit/export.jsonl", "audit/export.jsonl.get"],
    ["get", "/api/audit/export.csv", "audit/export.csv.get"],
    ["get", "/api/oauth/authorize", "oauth/authorize.get"],
    ["post", "/api/oauth/authorize", "oauth/authorize.post"],
  ];
  const router = createRouter();
  for (const [m, p, f] of routes) {
    const mod = await import(/* @vite-ignore */ `../../server/api/${f}.ts`);
    (router as any)[m](p, mod.default);
  }
  // stand-in for server/error.ts (workstream A): { error: { code, message } }
  const app = createApp({
    onError: (err: any, event) => {
      setResponseStatus(event, err.statusCode ?? 500);
      return send(event, JSON.stringify({ error: { code: err.data?.code ?? "internal", message: err.message } }), "application/json");
    },
  });
  app.use(router);
  server = createServer(toNodeListener(app));
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(server.address() as any).port}`;

  if (haveCert) {
    const { FakeImapServer } = await import("../helpers/fakeImap.js");
    fake = new FakeImapServer({ key: readFileSync(join(dirname(caFile!), "key.pem"), "utf8"), cert: readFileSync(caFile!, "utf8") });
    await fake.start();
    fake.addAccount("alice", "pw-alice", ["INBOX", "Drafts", "Archive"]);
  }
});
afterAll(async () => {
  await new Promise<void>((r) => server.close(() => r()));
  await fake?.stop();
  const { closeDb } = await import("../../server/core/db/database.js").then((m) => m as any);
  closeDb?.();
});

const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const PKCE = "A".repeat(43);
let mailboxId = "";
let clientId = "";
let ruleId = "";

describe("mailboxes", () => {
  it("validates and creates (201, no secrets)", async () => {
    expect((await api("POST", "/api/mailboxes", { label: "", host: "h", port: 993, username: "u", password: "p" })).json.error.message).toBe("Label is required (max 100 characters)");
    expect((await api("POST", "/api/mailboxes", { label: "L", host: "h", port: 0, username: "u", password: "p" })).json.error.message).toBe("Port must be 1-65535");
    expect((await api("POST", "/api/mailboxes", { label: "L", host: "h", port: 993, username: "u", password: "" })).json.error.message).toBe("Password is required");
    const r = await api("POST", "/api/mailboxes", { label: "Work", host: "localhost", port: fake?.port ?? 993, username: "alice", password: "pw-alice" });
    expect(r.status).toBe(201);
    expect(Object.keys(r.json).sort()).toEqual(["createdAt", "draftsFolder", "host", "id", "label", "port", "username"]);
    mailboxId = r.json.id;
    expect(r.json.createdAt).toMatch(ISO_RE);
  });
  it("detail: status + empty reach; 404 for unknown", async () => {
    const r = await api("GET", `/api/mailboxes/${mailboxId}`);
    expect(r.json).toMatchObject({ mailbox: { id: mailboxId, label: "Work" }, status: { status: "unknown", lastErrorCode: null }, reach: [] });
    expect((await api("GET", "/api/mailboxes/nope")).status).toBe(404);
  });
  it("PATCH: validates, keeps drafts folder unless target changes, a password resets the status latches", async () => {
    const { getDb } = await import("../../server/core/db/database.js");
    getDb().prepare("UPDATE mailboxes SET status='auth_failed', last_error_code='AUTH', drafts_folder='Drafts' WHERE id=?").run(mailboxId);
    const same = { label: "Work2", host: "localhost", port: fake?.port ?? 993, username: "alice" };
    expect((await api("PATCH", `/api/mailboxes/${mailboxId}`, { ...same, port: "x" })).status).toBe(400);
    let r = await api("PATCH", `/api/mailboxes/${mailboxId}`, { ...same, password: "" });
    expect(r.json).toMatchObject({ label: "Work2", draftsFolder: "Drafts" });
    expect((await api("GET", `/api/mailboxes/${mailboxId}`)).json.status.status).toBe("auth_failed"); // no password: no reset
    await api("PATCH", `/api/mailboxes/${mailboxId}`, { ...same, password: "pw-alice" });
    expect((await api("GET", `/api/mailboxes/${mailboxId}`)).json.status).toMatchObject({ status: "unknown", lastErrorCode: null });
    getDb().prepare("UPDATE mailboxes SET status='auth_failed' WHERE id=?").run(mailboxId);
    expect((await api("POST", `/api/mailboxes/${mailboxId}/retry`)).status).toBe(204);
    expect((await api("GET", `/api/mailboxes/${mailboxId}`)).json.status.status).toBe("unknown");
    expect((await api("PATCH", "/api/mailboxes/nope", same)).status).toBe(404);
    expect((await api("POST", "/api/mailboxes/nope/retry")).status).toBe(404);
  });
  it.skipIf(!haveCert)("test + drafts folder against the fake IMAP server", async () => {
    const t = await api("POST", `/api/mailboxes/${mailboxId}/test`);
    expect(t.json).toMatchObject({ ok: true, folders: ["Archive", "Drafts", "INBOX"] });
    const bad = await api("PUT", `/api/mailboxes/${mailboxId}/drafts`, { folder: "Nope" });
    expect([bad.status, bad.json.error.message]).toEqual([400, "That folder does not exist on the server"]);
    expect((await api("PUT", `/api/mailboxes/${mailboxId}/drafts`, { folder: "" })).json.error.message).toBe("Choose a folder");
    expect((await api("PUT", `/api/mailboxes/${mailboxId}/drafts`, { folder: "Archive" })).status).toBe(204);
    expect((await api("GET", `/api/mailboxes/${mailboxId}`)).json.mailbox.draftsFolder).toBe("Archive");
    fake.accounts.get("alice").pass = "changed"; // credentials rejected: the test result is surfaced
    const failing = await api("POST", `/api/mailboxes/${mailboxId}/test`);
    expect(failing.json.ok).toBe(false);
    expect((await api("PUT", `/api/mailboxes/${mailboxId}/drafts`, { folder: "Drafts" })).status).toBe(400);
    fake.accounts.get("alice").pass = "pw-alice";
    await api("PUT", `/api/mailboxes/${mailboxId}/drafts`, { folder: "Drafts" });
  });
});

describe("clients, grants, rules", () => {
  it("creates a client only in admin mode, with validated redirect URIs", async () => {
    const bad = await api("POST", "/api/clients", { name: "x", redirectUris: ["http://evil.example/cb"] });
    expect([bad.status, bad.json.error.message]).toEqual([400, "Name and 1-10 valid redirect URIs required (https, or http on localhost)"]);
    expect((await api("POST", "/api/clients", { name: "x", redirectUris: [] })).status).toBe(400);
    expect((await api("POST", "/api/clients", { name: "", redirectUris: ["https://a.example/cb"] })).status).toBe(400);
    expect((await api("POST", "/api/clients", { name: "x", redirectUris: Array(11).fill("https://a.example/cb") })).status).toBe(400);
    const r = await api("POST", "/api/clients", { name: " Claude ", redirectUris: ["https://a.example/cb", " http://localhost:9/cb "] });
    expect(r.status).toBe(201);
    expect(r.json).toMatchObject({ clientName: "Claude", disabled: false });
    clientId = r.json.clientId;
  });
  it("detail shows an empty grants matrix, help text and redirect URIs", async () => {
    const r = await api("GET", `/api/clients/${clientId}`);
    expect(r.json.client).toMatchObject({ clientId, redirectUris: ["https://a.example/cb", "http://localhost:9/cb"] });
    expect(r.json.mailboxes).toEqual([{ id: mailboxId, label: "Work2", draftsFolder: "Drafts", granted: { read: false, draft: false, organize: false } }]);
    expect(r.json.help.presetOperations).toEqual({ read: ["search", "read_headers", "read_body"], draft: ["draft"], organize: ["move", "flag"] });
    expect(r.json.help.operations).toHaveLength(6);
    expect((await api("GET", "/api/clients/nope")).status).toBe(404);
  });
  it("PUT grants applies the complete desired set and ignores unknown ids", async () => {
    const put = (grants: unknown) => api("PUT", `/api/clients/${clientId}/grants`, { grants });
    expect((await put([{ mailboxId, capability: "read" }, { mailboxId, capability: "organize" }, { mailboxId: "ghost", capability: "read" }, { mailboxId, capability: "send" }])).status).toBe(204);
    let d = (await api("GET", `/api/clients/${clientId}`)).json;
    expect(d.mailboxes[0].granted).toEqual({ read: true, draft: false, organize: true });
    expect((await api("GET", `/api/mailboxes/${mailboxId}`)).json.reach).toEqual([{ clientId, clientName: "Claude", capabilities: ["read", "organize"] }]);
    await put([{ mailboxId, capability: "draft" }]);
    d = (await api("GET", `/api/clients/${clientId}`)).json;
    expect(d.mailboxes[0].granted).toEqual({ read: false, draft: true, organize: false });
    expect((await api("PUT", `/api/clients/${clientId}/grants`, { grants: "x" })).status).toBe(400);
    expect((await api("PUT", "/api/clients/nope/grants", { grants: [] })).status).toBe(404);
    await put([{ mailboxId, capability: "read" }, { mailboxId, capability: "organize" }, { mailboxId, capability: "draft" }]);
  });
  it("rules: validation messages, create, flip, list, delete", async () => {
    const post = (b: Record<string, unknown>) => api("POST", `/api/clients/${clientId}/rules`, { mailboxId, folder: "INBOX", operation: "move", effect: "deny", ...b });
    expect((await post({ mailboxId: "ghost" })).json.error.message).toBe("Unknown mailbox");
    expect((await post({ folder: "a*b" })).json.error.message).toBe("Invalid folder selector: use an exact path, *, or Prefix/* (no other wildcards)");
    expect((await post({ operation: "send" })).json.error.message).toBe("Unknown operation");
    expect((await post({ effect: "maybe" })).json.error.message).toBe("Effect must be allow or deny");
    const r = await post({});
    expect(r.status).toBe(201);
    expect(r.json).toMatchObject({ mailboxId, folder: "INBOX", operation: "move", effect: "deny", selectorValid: true });
    ruleId = r.json.id;
    const flipped = await post({ effect: "allow" });
    expect([flipped.json.id, flipped.json.effect]).toEqual([ruleId, "allow"]);
    const rules = (await api("GET", `/api/clients/${clientId}`)).json.rules;
    expect(rules.filter((x: any) => x.folder === "INBOX")).toHaveLength(1);
    expect((await api("DELETE", `/api/clients/${clientId}/rules/${ruleId}`)).status).toBe(204);
    expect((await api("DELETE", `/api/clients/${clientId}/rules/${ruleId}`)).status).toBe(204);
    expect((await api("GET", `/api/clients/${clientId}`)).json.rules.some((x: any) => x.id === ruleId)).toBe(false);
  });
});

describe("oauth consent", () => {
  const q = (o: Record<string, string>) => "?" + new URLSearchParams({ client_id: clientId, redirect_uri: "https://a.example/cb", response_type: "code", code_challenge: PKCE, code_challenge_method: "S256", state: "st 1", ...o }).toString();
  const redir = (u: string) => new URL(u);
  it("page errors are 400 with the old messages", async () => {
    expect((await api("GET", "/api/oauth/authorize")).json.error.message).toBe("Missing client_id or redirect_uri");
    expect((await api("GET", "/api/oauth/authorize" + q({ client_id: "ghost" }))).json.error.message).toBe("Unknown or disabled client");
    expect((await api("GET", "/api/oauth/authorize" + q({ redirect_uri: "https://other.example/cb" }))).json.error.message).toBe("redirect_uri is not registered for this client");
  });
  it("protocol errors come back as redirectTo", async () => {
    const e = async (o: Record<string, string>) => { const u = redir((await api("GET", "/api/oauth/authorize" + q(o))).json.redirectTo); return [u.searchParams.get("error"), u.searchParams.get("error_description"), u.searchParams.get("state"), u.searchParams.get("iss")]; };
    expect(await e({ response_type: "token" })).toEqual(["unsupported_response_type", null, "st 1", "http://localhost:3000"]);
    expect((await e({ code_challenge_method: "plain" }))[0]).toBe("invalid_request");
    expect((await e({ code_challenge: "short" }))[0]).toBe("invalid_request");
    expect((await e({ resource: "http://x/mcp" }))[0]).toBe("invalid_target");
    expect((await e({ scope: "mail:nothing" }))[0]).toBe("invalid_scope");
  });
  it("valid request returns the consent data", async () => {
    const r = await api("GET", "/api/oauth/authorize" + q({ scope: "mail:read mail:organize mail:bogus" }));
    expect(r.json).toMatchObject({
      client: { id: clientId, name: "Claude", createdAt: expect.stringMatching(ISO_RE) }, redirectUri: "https://a.example/cb", capabilities: ["read", "organize"],
      mailboxes: [{ id: mailboxId, label: "Work2" }],
      params: { client_id: clientId, response_type: "code", code_challenge: PKCE, code_challenge_method: "S256", resource: "http://localhost:3000/mcp", scope: "mail:read mail:organize", state: "st 1" },
    });
  });
  it("POST re-validates, denies, and only grants requested caps on existing mailboxes", async () => {
    const params = (await api("GET", "/api/oauth/authorize" + q({ scope: "mail:read" }))).json.params;
    const deny = await api("POST", "/api/oauth/authorize", { params, decision: "deny", grants: [] });
    expect(redir(deny.json.redirectTo).searchParams.get("error")).toBe("access_denied");
    const none = await api("POST", "/api/oauth/authorize", { params, decision: "approve", grants: [{ mailboxId: "ghost", capability: "read" }, { mailboxId, capability: "organize" }] });
    expect(redir(none.json.redirectTo).searchParams.get("error_description")).toBe("No permissions were granted");
    expect((await api("POST", "/api/oauth/authorize", { params: { ...params, redirect_uri: "https://evil.example/cb" }, decision: "approve", grants: [] })).status).toBe(400);
    expect((await api("POST", "/api/oauth/authorize", { decision: "approve", grants: [] })).status).toBe(400);
    expect(redir((await api("POST", "/api/oauth/authorize", { params: { ...params, code_challenge_method: "plain" }, decision: "approve", grants: [{ mailboxId, capability: "read" }] })).json.redirectTo).searchParams.get("error")).toBe("invalid_request");

    const { getDb } = await import("../../server/core/db/database.js");
    getDb().prepare("DELETE FROM policy_rules WHERE client_id = ?").run(clientId);
    const ok = await api("POST", "/api/oauth/authorize", { params, decision: "approve", grants: [{ mailboxId, capability: "read" }, { mailboxId, capability: "organize" }] });
    const u = redir(ok.json.redirectTo);
    expect([u.origin + u.pathname, u.searchParams.get("state"), u.searchParams.get("iss"), !!u.searchParams.get("code")]).toEqual(["https://a.example/cb", "st 1", "http://localhost:3000", true]);
    const granted = (await api("GET", `/api/clients/${clientId}`)).json.mailboxes[0].granted;
    expect(granted).toEqual({ read: true, draft: false, organize: false }); // organize was not requested
    const row = getDb().prepare("SELECT scopes, client_id, redirect_uri FROM oauth_codes").get() as any;
    expect(row).toMatchObject({ scopes: "mail:read", client_id: clientId, redirect_uri: "https://a.example/cb" });
  });
});

describe("overview, tokens, audit, lifecycle", () => {
  it("overview reflects clients, grants, active tokens with live reach; token revoke", async () => {
    const { getDb } = await import("../../server/core/db/database.js");
    const db = getDb();
    await api("PUT", `/api/clients/${clientId}/grants`, { grants: [{ mailboxId, capability: "read" }, { mailboxId, capability: "draft" }] });
    const future = new Date(Date.now() + 3600_000).toISOString();
    db.prepare("INSERT INTO oauth_tokens (id, token_hash, client_id, scopes, resource, expires_at) VALUES ('tok1', 'h1', ?, 'mail:read mail:organize', 'r', ?)").run(clientId, future);
    const o = (await api("GET", "/api/overview")).json;
    expect(o.registrationMode).toBe("admin");
    expect(o.mailboxes).toMatchObject([{ id: mailboxId, status: "unknown", clientCount: 1 }]);
    expect(o.clients).toMatchObject([{ clientId, clientName: "Claude", disabled: false }]);
    expect(o.grants).toEqual(expect.arrayContaining([{ clientId, mailboxId, capability: "read" }, { clientId, mailboxId, capability: "draft" }]));
    expect([o.tokens[0].createdAt, o.tokens[0].expiresAt, o.clients[0].createdAt, o.mailboxes[0].createdAt].every((t: string) => ISO_RE.test(t))).toBe(true);
    expect(o.tokens).toMatchObject([{ id: "tok1", clientName: "Claude", reach: [{ mailboxId, mailboxLabel: "Work2", capabilities: ["read"] }] }]);
    expect(JSON.stringify(o)).not.toMatch(/token_hash|tokenHash|password|enc/i);
    expect((await api("POST", "/api/tokens/tok1/revoke")).status).toBe(204);
    expect((await api("GET", "/api/overview")).json.tokens).toEqual([]);
    expect((await api("POST", "/api/tokens/nope/revoke")).status).toBe(404);
  });
  it("audit list, filters, options, pagination clamp, streamed exports", async () => {
    const { insertAuditEvent } = await import("../../server/core/audit/store.js");
    for (let i = 0; i < 55; i++) {
      insertAuditEvent({ ts: `2026-02-01T00:00:${String(i).padStart(2, "0")}.000Z`, requestId: "req-12345678", clientId, mailboxId, folder: "INBOX", uidValidity: 1, uid: i, tool: i % 2 ? "search" : "read_message", outcome: i % 5 ? "ok" : "denied", errorCode: null, durationMs: 3 });
    }
    insertAuditEvent({ ts: "2026-02-02T12:00:00.000Z", requestId: "req-12345678", clientId: null, mailboxId: null, folder: null, uidValidity: null, tool: "late", outcome: "failed", errorCode: "X", durationMs: 1 });
    const p1 = (await api("GET", "/api/audit")).json;
    expect([p1.total, p1.page, p1.pages, p1.pageSize, p1.events.length]).toEqual([56, 1, 2, 50, 50]);
    expect(p1.events[0].tool).toBe("late");
    expect(p1.events[0]).not.toHaveProperty("refs");
    expect(p1.options).toEqual({ clients: [clientId], mailboxes: [mailboxId], tools: ["late", "read_message", "search"], outcomes: ["ok", "denied", "failed", "unknown_outcome"] });
    expect((await api("GET", "/api/audit?page=99")).json.page).toBe(2);
    expect((await api("GET", "/api/audit?outcome=denied")).json.total).toBe(11);
    expect((await api("GET", "/api/audit?from=2026-02-01&to=2026-02-01")).json.total).toBe(55); // bare-date `to` is inclusive
    expect((await api("GET", "/api/audit?to=2026-02-01")).json.total).toBe(55);
    expect((await api("GET", "/api/audit?tool=late")).json.total).toBe(1);
    const jl = await api("GET", "/api/audit/export.jsonl?client=" + clientId);
    expect(jl.headers.get("content-type")).toBe("application/x-ndjson; charset=utf-8");
    expect(jl.headers.get("content-disposition")).toBe('attachment; filename="audit.jsonl"');
    expect(jl.text.trimEnd().split("\n")).toHaveLength(55);
    expect(JSON.parse(jl.text.split("\n")[0]).uid).toBe(0);
    const csv = await api("GET", "/api/audit/export.csv");
    expect(csv.headers.get("content-type")).toBe("text/csv; charset=utf-8");
    expect(csv.text.split("\n")[0]).toBe("id,ts,requestId,clientId,mailboxId,folder,uidValidity,uid,uids,uidsTruncated,tool,outcome,errorCode,cached,reconciled,durationMs");
    expect(csv.text.trimEnd().split("\n")).toHaveLength(57);
  });
  it("disable/enable/revoke client and delete mailbox", async () => {
    const { getDb } = await import("../../server/core/db/database.js");
    const db = getDb();
    const future = new Date(Date.now() + 3600_000).toISOString();
    for (const id of ["t2", "t3"]) db.prepare("INSERT INTO oauth_tokens (id, token_hash, client_id, scopes, resource, expires_at) VALUES (?, ?, ?, 'mail:read', 'r', ?)").run(id, "h" + id, clientId, future);
    expect((await api("GET", `/api/clients/${clientId}`)).json.activeTokenCount).toBe(2);
    expect((await api("POST", `/api/clients/${clientId}/disable`)).status).toBe(204);
    expect((await api("GET", `/api/clients/${clientId}`)).json).toMatchObject({ client: { disabled: true }, activeTokenCount: 0 });
    expect((await api("GET", "/api/oauth/authorize?client_id=" + clientId + "&redirect_uri=https://a.example/cb")).json.error.message).toBe("Unknown or disabled client");
    expect((await api("POST", `/api/clients/${clientId}/enable`)).status).toBe(204);
    expect((await api("GET", `/api/clients/${clientId}`)).json.client.disabled).toBe(false);
    db.prepare("UPDATE oauth_tokens SET revoked = 0 WHERE id = 't2'").run();
    expect((await api("POST", `/api/clients/${clientId}/revoke`)).status).toBe(204);
    const d = (await api("GET", `/api/clients/${clientId}`)).json;
    expect([d.rules, d.activeTokenCount]).toEqual([[], 0]);
    expect((await api("POST", "/api/clients/nope/revoke")).status).toBe(404);

    expect((await api("DELETE", `/api/mailboxes/${mailboxId}`, { confirmLabel: "wrong" })).status).toBe(400);
    expect((await api("DELETE", `/api/mailboxes/${mailboxId}`, {})).status).toBe(400);
    expect((await api("DELETE", "/api/mailboxes/nope", { confirmLabel: "x" })).status).toBe(404);
    expect((await api("DELETE", `/api/mailboxes/${mailboxId}`, { confirmLabel: "Work2" })).status).toBe(204);
    expect((await api("GET", `/api/mailboxes/${mailboxId}`)).status).toBe(404);
  });
});
