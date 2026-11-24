/**
 * Token management API: GET/PATCH /api/tokens/:id. A token's scopes are only a capability ceiling and the
 * per-mailbox reach comes from the client's grants, so PATCH edits both in one transaction.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { randomUUID } from "node:crypto";
import { makeSelfSignedCert } from "../helpers/certs.js";
import { Browser, errorOf, json } from "../helpers/http.js";
import { Mcp, obtainToken, rawMcp, setGrants, sha256hex, type Stack, createStack } from "../helpers/stack.js";
import type { ApiTokenCreated, ClientDetail, MailboxDetail, Overview, TokenDetail } from "../../shared/types/api.js";

const haveOpenssl = !!makeSelfSignedCert();
const ALICE = "alice@example.test";
const BOB = "bob@example.test";

describe.skipIf(!haveOpenssl)("token admin API", () => {
  let s: Stack;
  let A: string;
  let B: string;
  const tokenId = (access: string) => (s.srv.db().prepare("SELECT id FROM oauth_tokens WHERE token_hash = ?").get(sha256hex(access)) as any).id as string;
  const get = (id: string) => s.admin.get(`/api/tokens/${id}`);
  const patch = (id: string, body: unknown) => s.admin.patchWithCsrf(`/api/tokens/${id}`, body);
  const grants = (...g: Array<[string, string]>) => g.map(([mailboxId, capability]) => ({ mailboxId, capability }));

  beforeAll(async () => {
    s = await createStack();
    A = s.mailbox[ALICE];
    B = s.mailbox[BOB];
  });
  afterAll(async () => { await s?.teardown(); });

  it("GET 404s for an unknown or revoked token", async () => {
    expect((await get(randomUUID())).status).toBe(404);
    const { tokens } = await obtainToken(s, [[A, "read"]]);
    const id = tokenId(tokens.access_token);
    expect((await get(id)).status).toBe(200);
    expect((await s.admin.postWithCsrf(`/api/tokens/${id}/revoke`)).status).toBe(204);
    expect((await get(id)).status).toBe(404);
    expect((await patch(id, { capabilities: ["read"], grants: [] })).status).toBe(404);
  });

  it("GET returns the ceiling, the client's per-mailbox grants and the number of sibling tokens", async () => {
    const first = await obtainToken(s, [[A, "read"], [A, "draft"]], { scope: "mail:read mail:draft", name: "detail-tok" });
    await obtainToken(s, [[A, "read"]], { clientId: first.clientId });
    const d = await json<TokenDetail>(await get(tokenId(first.tokens.access_token)));
    expect(d.token.scopes).toEqual(["read", "draft"]);
    expect(d.token.clientName).toBe("detail-tok");
    expect(d.client.clientId).toBe(first.clientId);
    expect(d.otherActiveTokenCount).toBe(1);
    expect(d.mailboxes.find((m) => m.id === A)!.granted).toEqual({ read: true, draft: true, organize: false });
    expect(d.mailboxes.find((m) => m.id === B)!.granted).toEqual({ read: false, draft: false, organize: false });
    const ov = await json<Overview>(await s.admin.get("/api/overview"));
    expect(ov.tokens.find((t) => t.id === d.token.id)!.scopes).toEqual(["read", "draft"]);
  });

  it("PATCH adds a later mailbox to an existing token: same access token reaches it, and a refresh keeps the ceiling", async () => {
    const { clientId, tokens } = await obtainToken(s, [[A, "read"]], { scope: "mail:read" });
    const id = tokenId(tokens.access_token);
    const mcp = await new Mcp(s.base, tokens.access_token).connect();
    try {
      expect((await mcp.call("search_messages", { mailbox: A, folder: "INBOX" })).isError).toBe(false);
      expect((await mcp.call("search_messages", { mailbox: B, folder: "INBOX" })).isError, "no grant on B yet").toBe(true);

      const r = await patch(id, { capabilities: ["read", "organize"], grants: grants([A, "read"], [B, "read"], [B, "organize"]) });
      expect(r.status).toBe(200);
      const d = await json<TokenDetail>(r);
      expect(d.token.scopes).toEqual(["read", "organize"]);
      expect(d.token.reach.find((x) => x.mailboxId === B)!.capabilities).toEqual(["read", "organize"]);
      expect(d.mailboxes.find((m) => m.id === B)!.granted).toEqual({ read: true, draft: false, organize: true });

      expect((await mcp.call("search_messages", { mailbox: B, folder: "INBOX" })).isError, "same access token now reaches B").toBe(false);
    } finally { await mcp.close(); }

    const refresh = await fetch(`${s.base}/oauth/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "refresh_token", client_id: clientId, refresh_token: tokens.refresh_token }) });
    expect(refresh.status).toBe(200);
    const next = (await refresh.json()) as { access_token: string; scope: string };
    expect(next.scope).toBe("mail:read mail:organize");
    const nextDetail = await json<TokenDetail>(await get(tokenId(next.access_token)));
    expect(nextDetail.token.scopes).toEqual(["read", "organize"]);
    // the old (rotated, revoked) row followed the new scopes, so reuse of the old refresh token still revokes the lineage
    const reuse = await fetch(`${s.base}/oauth/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "refresh_token", client_id: clientId, refresh_token: tokens.refresh_token }) });
    expect(reuse.status).toBe(400);
    expect((await rawMcp(s.base, `Bearer ${next.access_token}`)).status, "reuse revoked the lineage").toBe(401);
  });

  it("PATCH rejects empty or invalid capabilities and a missing grants list", async () => {
    const { tokens } = await obtainToken(s, [[A, "read"]]);
    const id = tokenId(tokens.access_token);
    const before = (await json<TokenDetail>(await get(id))).token.scopes;
    for (const body of [
      { capabilities: [], grants: [] },
      { capabilities: ["read", "delete"], grants: [] },
      { capabilities: "read", grants: [] },
      { grants: [] },
      { capabilities: ["read"] },
    ]) {
      const r = await patch(id, body);
      expect(r.status, JSON.stringify(body)).toBe(400);
      expect((await errorOf(r)).code).toBe("validation");
    }
    expect((await json<TokenDetail>(await get(id))).token.scopes, "rejected requests change nothing").toEqual(before);
  });

  it("PATCH requires the CSRF header", async () => {
    const { tokens } = await obtainToken(s, [[A, "read"]]);
    const r = await s.admin.req("PATCH", `/api/tokens/${tokenId(tokens.access_token)}`, { json: { capabilities: ["read"], grants: [] } });
    expect(r.status).toBe(403);
    expect((await errorOf(r)).code).toBe("csrf");
  });

  describe("API tokens created in the admin UI", () => {
    const create = (body: unknown) => s.admin.postWithCsrf("/api/tokens", body);
    const make = async (...g: Array<[string, string]>) => {
      const r = await create({ name: "cron-script", expiresInDays: 30, grants: grants(...g) });
      expect(r.status).toBe(201);
      return json<ApiTokenCreated>(r);
    };
    const overview = async () => json<Overview>(await s.admin.get("/api/overview"));

    it("returns the secret once, stores only its hash, and the token works on /mcp within its grants", async () => {
      const { secret, token } = await make([A, "read"]);
      expect(secret).toMatch(/^i2m_[A-Za-z0-9_-]{43}$/);
      expect(token).toMatchObject({ clientName: "cron-script", kind: "api", scopes: ["read"] });
      const days = (new Date(token.expiresAt).getTime() - Date.now()) / 86_400_000;
      expect(days).toBeGreaterThan(29.9);
      expect(days).toBeLessThanOrEqual(30);

      const row = s.srv.db().prepare("SELECT * FROM oauth_tokens WHERE id = ?").get(token.id) as any;
      expect(row.token_hash).toBe(sha256hex(secret));
      expect(row.refresh_hash).toBeNull();
      expect(JSON.stringify(row)).not.toContain(secret);
      for (const path of ["/api/overview", `/api/tokens/${token.id}`, `/api/clients/${token.clientId}`]) {
        expect(await (await s.admin.get(path)).text(), path).not.toContain(secret);
      }

      const mcp = await new Mcp(s.base, secret).connect();
      try {
        expect((await mcp.call("search_messages", { mailbox: A, folder: "INBOX" })).isError).toBe(false);
        expect((await mcp.call("search_messages", { mailbox: B, folder: "INBOX" })).isError, "no grant on B").toBe(true);
        expect((await mcp.call("create_draft", { mailbox: A, subject: "x", body: "y" })).isError, "no draft capability").toBe(true);
      } finally { await mcp.close(); }

      const ov = await overview();
      expect(ov.tokens.find((t) => t.id === token.id)!.kind).toBe("api");
      expect(ov.clients.find((c) => c.clientId === token.clientId)!.kind).toBe("api");
    });

    it("can be edited like any other token", async () => {
      const { secret, token } = await make([A, "read"]);
      expect((await patch(token.id, { capabilities: ["read"], grants: grants([B, "read"]) })).status).toBe(200);
      const mcp = await new Mcp(s.base, secret).connect();
      try {
        expect((await mcp.call("search_messages", { mailbox: B, folder: "INBOX" })).isError).toBe(false);
        expect((await mcp.call("search_messages", { mailbox: A, folder: "INBOX" })).isError).toBe(true);
      } finally { await mcp.close(); }
    });

    it("stops working when revoked or expired, and its client leaves the lists and reach counts", async () => {
      for (const end of ["revoke", "expire"] as const) {
        const { secret, token } = await make([A, "read"]);
        const reach = async () => (await json<MailboxDetail>(await s.admin.get(`/api/mailboxes/${A}`))).reach.map((r) => r.clientId);
        expect(await reach()).toContain(token.clientId);
        if (end === "revoke") expect((await s.admin.postWithCsrf(`/api/tokens/${token.id}/revoke`)).status).toBe(204);
        else s.srv.db().prepare("UPDATE oauth_tokens SET expires_at = ? WHERE id = ?").run(new Date(Date.now() - 1000).toISOString(), token.id);

        expect((await rawMcp(s.base, `Bearer ${secret}`)).status, end).toBe(401);
        const ov = await overview();
        expect(ov.tokens.map((t) => t.id), end).not.toContain(token.id);
        expect(ov.clients.map((c) => c.clientId), end).not.toContain(token.clientId);
        expect(ov.grants.map((g) => g.clientId), end).not.toContain(token.clientId);
        expect(await reach(), end).not.toContain(token.clientId);
        // the record stays, so audit entries still resolve to a client
        expect((await json<ClientDetail>(await s.admin.get(`/api/clients/${token.clientId}`))).client.kind).toBe("api");
      }
    });

    it("its client cannot enter the OAuth flow", async () => {
      const { secret, token } = await make([A, "read"]);
      const authorize = await s.admin.get(`/api/oauth/authorize?${new URLSearchParams({ client_id: token.clientId, redirect_uri: "https://evil.example/cb", response_type: "code" })}`);
      expect(authorize.status).toBe(400);
      const refresh = await fetch(`${s.base}/oauth/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "refresh_token", client_id: token.clientId, refresh_token: secret }) });
      expect(refresh.status).toBe(400);
    });

    it("rejects bad input without creating anything", async () => {
      const count = () => (s.srv.db().prepare("SELECT (SELECT COUNT(*) FROM oauth_clients) AS c, (SELECT COUNT(*) FROM oauth_tokens) AS t").get()) as { c: number; t: number };
      const before = count();
      const ok = { name: "n", expiresInDays: 30, grants: grants([A, "read"]) };
      for (const body of [
        { ...ok, name: "  " },
        { ...ok, expiresInDays: 31 },
        { ...ok, expiresInDays: "30" },
        { ...ok, expiresInDays: undefined },
        { ...ok, grants: [] },
        { ...ok, grants: grants(["no-such-mailbox", "read"]) },
        { ...ok, grants: grants([A, "delete"]) },
      ]) {
        const r = await create(body);
        expect(r.status, JSON.stringify(body)).toBe(400);
        expect((await errorOf(r)).code).toBe("validation");
      }
      expect(count()).toEqual(before);
    });

    it("requires the CSRF header and an admin session", async () => {
      const body = { name: "n", expiresInDays: 30, grants: grants([A, "read"]) };
      const noCsrf = await s.admin.req("POST", "/api/tokens", { json: body });
      expect(noCsrf.status).toBe(403);
      expect((await errorOf(noCsrf)).code).toBe("csrf");
      const anon = new Browser(s.base);
      expect((await anon.postWithCsrf("/api/tokens", body)).status).toBe(401);
    });
  });

  it("PUT /api/clients/:id/grants is unchanged", async () => {
    const { clientId } = await obtainToken(s, [[A, "read"]]);
    await setGrants(s, clientId, [[B, "read"]]);
    const d = await json<{ mailboxes: { id: string; granted: Record<string, boolean> }[] }>(await s.admin.get(`/api/clients/${clientId}`));
    expect(d.mailboxes.find((m) => m.id === A)!.granted.read).toBe(false);
    expect(d.mailboxes.find((m) => m.id === B)!.granted.read).toBe(true);
  });
});
