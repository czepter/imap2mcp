/**
 * Token management API: GET/PATCH /api/tokens/:id. A token's scopes are only a capability ceiling and the
 * per-mailbox reach comes from the client's grants, so PATCH edits both in one transaction.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { randomUUID } from "node:crypto";
import { makeSelfSignedCert } from "../helpers/certs.js";
import { errorOf, json } from "../helpers/http.js";
import { Mcp, obtainToken, rawMcp, setGrants, sha256hex, type Stack, createStack } from "../helpers/stack.js";
import type { Overview, TokenDetail } from "../../shared/types/api.js";

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

  it("PUT /api/clients/:id/grants is unchanged", async () => {
    const { clientId } = await obtainToken(s, [[A, "read"]]);
    await setGrants(s, clientId, [[B, "read"]]);
    const d = await json<{ mailboxes: { id: string; granted: Record<string, boolean> }[] }>(await s.admin.get(`/api/clients/${clientId}`));
    expect(d.mailboxes.find((m) => m.id === A)!.granted.read).toBe(false);
    expect(d.mailboxes.find((m) => m.id === B)!.granted.read).toBe(true);
  });
});
