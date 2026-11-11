/**
 * Black-box acceptance tests for the client admin API (docs/NUXT_MIGRATION.md): client detail, grants PUT
 * (complete preset set, idempotent), rules (validation, upsert, effect on live tokens), disable / enable / revoke,
 * token revocation, and REGISTRATION_MODE=admin client creation.
 * (How grants constrain tools is covered end to end by policy-matrix.test.ts and v1-policy.test.ts.)
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { randomUUID } from "node:crypto";
import { makeSelfSignedCert } from "../helpers/certs.js";
import { errorOf, json } from "../helpers/http.js";
import {
  consent, createStack, exchange, Mcp, msg, obtainToken, rawMcp, REDIRECT, refOf, registerClient, setGrants, sha256hex, type Stack,
} from "../helpers/stack.js";
import type { ClientDetail, ClientSummary, Overview, Rule } from "../../shared/types/api.js";

const haveOpenssl = !!makeSelfSignedCert();
const ALICE = "alice@example.test";
const BOB = "bob@example.test";

describe.skipIf(!haveOpenssl)("client admin API", () => {
  let s: Stack;
  let A: string; // alice mailbox id
  let B: string;
  const rulesIn = (clientId: string) => s.srv.db().prepare("SELECT * FROM policy_rules WHERE client_id = ?").all(clientId) as any[];
  const detail = async (clientId: string) => {
    const r = await s.admin.get(`/api/clients/${clientId}`);
    expect(r.status).toBe(200);
    return json<ClientDetail>(r);
  };
  const overview = async () => json<Overview>(await s.admin.get("/api/overview"));
  const addRule = (clientId: string, body: Record<string, unknown>) => s.admin.postWithCsrf(`/api/clients/${clientId}/rules`, body);

  beforeAll(async () => {
    s = await createStack();
    A = s.mailbox[ALICE];
    B = s.mailbox[BOB];
  });
  afterAll(async () => { await s?.teardown(); });

  describe("GET /api/clients/:id", () => {
    it("returns ClientDetail with per-mailbox capability state, rules, redirect URIs and the capability help", async () => {
      const id = await registerClient(s.base, ["https://client.example/cb", REDIRECT], "detail-client");
      await setGrants(s, id, [[A, "read"], [A, "draft"], [B, "organize"]]);
      const d = await detail(id);
      expect(d.client).toMatchObject({ clientId: id, clientName: "detail-client", disabled: false, redirectUris: ["https://client.example/cb", REDIRECT] });
      expect(d.client.createdAt).toMatch(/^\d{4}-\d\d-\d\d/);
      expect(d.mailboxes.map((m) => m.id).sort()).toEqual([A, B].sort());
      const a = d.mailboxes.find((m) => m.id === A)!;
      expect(a).toMatchObject({ label: `Box alice`, draftsFolder: "Drafts", granted: { read: true, draft: true, organize: false } });
      expect(d.mailboxes.find((m) => m.id === B)!.granted).toEqual({ read: false, draft: false, organize: true });
      expect(d.rules).toHaveLength(3 + 1 + 2); // read(3 ops) + draft(1) on A, organize(2) on B
      expect(d.activeTokenCount).toBe(0);
      expect(d.help.presetOperations).toEqual({ read: ["search", "read_headers", "read_body"], draft: ["draft"], organize: ["move", "flag"] });
      expect(Object.keys(d.help.capabilities).sort()).toEqual(["draft", "organize", "read"]);
      expect(d.help.operations).toEqual(expect.arrayContaining([{ operation: "search", capability: "read" }, { operation: "flag", capability: "organize" }, { operation: "draft", capability: "draft" }]));
      expect(d.help.operations).toHaveLength(6);
    });

    it("404s (JSON) for an unknown client", async () => {
      const r = await s.admin.get(`/api/clients/${randomUUID()}`);
      expect(r.status).toBe(404);
      expect((await errorOf(r)).code).toBeTruthy();
    });

    it("counts active tokens", async () => {
      const { clientId } = await obtainToken(s, [[A, "read"]]);
      await obtainToken(s, [[A, "read"]], { clientId });
      expect((await detail(clientId)).activeTokenCount).toBe(2);
    });
  });

  describe("PUT /api/clients/:id/grants", () => {
    it("takes the complete desired preset set: adds missing presets, removes the ones left out, idempotent on repeat", async () => {
      const id = await registerClient(s.base, undefined, "grants-client");
      const put = (grants: Array<[string, string]>) => s.admin.putWithCsrf(`/api/clients/${id}/grants`, { grants: grants.map(([mailboxId, capability]) => ({ mailboxId, capability })) });

      expect((await put([[A, "read"], [A, "draft"]])).status).toBe(204);
      expect((await detail(id)).mailboxes.find((m) => m.id === A)!.granted).toEqual({ read: true, draft: true, organize: false });
      const snapshot = rulesIn(id).map((r) => `${r.mailbox_id}|${r.folder}|${r.operation}|${r.effect}`).sort();
      expect(snapshot).toHaveLength(4);

      // same request again: no duplicates, no change
      expect((await put([[A, "read"], [A, "draft"]])).status).toBe(204);
      expect(rulesIn(id).map((r) => `${r.mailbox_id}|${r.folder}|${r.operation}|${r.effect}`).sort()).toEqual(snapshot);
      // order and duplicate entries do not matter
      expect((await put([[A, "draft"], [A, "read"], [A, "read"]])).status).toBe(204);
      expect(rulesIn(id)).toHaveLength(4);

      // narrower set removes what was left out, other mailboxes can be added in the same call
      expect((await put([[A, "read"], [B, "organize"]])).status).toBe(204);
      const d = await detail(id);
      expect(d.mailboxes.find((m) => m.id === A)!.granted).toEqual({ read: true, draft: false, organize: false });
      expect(d.mailboxes.find((m) => m.id === B)!.granted).toEqual({ read: false, draft: false, organize: true });

      // empty set revokes every preset
      expect((await put([])).status).toBe(204);
      expect(rulesIn(id)).toHaveLength(0);
      expect((await detail(id)).mailboxes.every((m) => !m.granted.read && !m.granted.draft && !m.granted.organize)).toBe(true);
    });

    it("never touches advanced rules that are not part of a preset", async () => {
      const id = await registerClient(s.base, undefined, "grants-vs-rules");
      expect((await addRule(id, { mailboxId: A, folder: "Archive", operation: "search", effect: "allow" })).status).toBe(201);
      expect((await addRule(id, { mailboxId: A, folder: "Work/*", operation: "move", effect: "deny" })).status).toBe(201);
      await setGrants(s, id, [[A, "read"]]);
      await setGrants(s, id, []);
      const left = rulesIn(id).map((r) => `${r.folder}|${r.operation}|${r.effect}`).sort();
      expect(left).toEqual(["Archive|search|allow", "Work/*|move|deny"]);
    });

    it("an existing deny survives a grant of the same preset (deny always wins, consent never overrides)", async () => {
      const id = await registerClient(s.base, undefined, "deny-wins");
      expect((await addRule(id, { mailboxId: A, folder: "*", operation: "read_body", effect: "deny" })).status).toBe(201);
      await setGrants(s, id, [[A, "read"]]);
      const rb = rulesIn(id).filter((r) => r.operation === "read_body");
      expect(rb).toHaveLength(1);
      expect(rb[0].effect).toBe("deny");
      expect((await detail(id)).mailboxes.find((m) => m.id === A)!.granted.read, "preset is not fully active while read_body is denied").toBe(false);
    });

    it("ignores or rejects unknown mailboxes and capabilities without creating anything and without a 5xx", async () => {
      const id = await registerClient(s.base, undefined, "grants-junk");
      for (const grants of [
        [{ mailboxId: randomUUID(), capability: "read" }],
        [{ mailboxId: A, capability: "admin" }],
        [{ mailboxId: A }],
        [{ capability: "read" }],
        "read",
        [null],
      ]) {
        const r = await s.admin.putWithCsrf(`/api/clients/${id}/grants`, { grants });
        expect(r.status, JSON.stringify(grants)).toBeLessThan(500);
        expect([204, 400]).toContain(r.status);
      }
      expect((await s.admin.putWithCsrf(`/api/clients/${id}/grants`, {})).status).toBeLessThan(500);
      expect(rulesIn(id)).toHaveLength(0);
      expect((await s.admin.putWithCsrf(`/api/clients/${randomUUID()}/grants`, { grants: [] })).status).toBe(404);
    });
  });

  describe("rules", () => {
    let id: string;
    beforeAll(async () => { id = await registerClient(s.base, undefined, "rules-client"); });

    it("POST creates a rule: 201 + Rule DTO, trimmed folder, shown in the client detail", async () => {
      const r = await addRule(id, { mailboxId: A, folder: "  Archive/*  ", operation: "read_headers", effect: "allow" });
      expect(r.status).toBe(201);
      const rule = await json<Rule>(r);
      expect(rule).toEqual({ id: expect.stringMatching(/\S/), mailboxId: A, folder: "Archive/*", operation: "read_headers", effect: "allow", selectorValid: true, createdAt: expect.any(String) });
      expect((await detail(id)).rules).toEqual(expect.arrayContaining([rule]));
    });

    it("the same (mailbox, folder, operation) is updated, not duplicated: the effect flips", async () => {
      const first = await json<Rule>(await addRule(id, { mailboxId: A, folder: "Receipts", operation: "search", effect: "allow" }));
      expect((await addRule(id, { mailboxId: A, folder: "Receipts", operation: "search", effect: "deny" })).status).toBe(201);
      const rows = rulesIn(id).filter((x) => x.folder === "Receipts" && x.operation === "search");
      expect(rows).toHaveLength(1);
      expect(rows[0].effect).toBe("deny");
      const shown = (await detail(id)).rules.filter((x) => x.folder === "Receipts");
      expect(shown).toHaveLength(1);
      expect(shown[0]).toMatchObject({ effect: "deny", selectorValid: true });
      void first;
    });

    it("validates with the old messages and stores nothing on failure", async () => {
      const before = rulesIn(id).length;
      const ok = { mailboxId: A, folder: "Work", operation: "search", effect: "allow" };
      const SELECTOR = "Invalid folder selector: use an exact path, *, or Prefix/* (no other wildcards)";
      const cases: Array<[Record<string, unknown>, string]> = [
        [{ mailboxId: randomUUID() }, "Unknown mailbox"],
        [{ mailboxId: "" }, "Unknown mailbox"],
        [{ folder: "" }, SELECTOR],
        [{ folder: "   " }, SELECTOR],
        [{ folder: "a*b" }, SELECTOR],
        [{ folder: "*/x" }, SELECTOR],
        [{ folder: "/*" }, SELECTOR],
        [{ folder: "Pre*/*" }, SELECTOR],
        [{ folder: "Wor\u0001k" }, SELECTOR],
        [{ folder: "x".repeat(256) }, SELECTOR],
        [{ operation: "delete" }, "Unknown operation"],
        [{ operation: "" }, "Unknown operation"],
        [{ effect: "maybe" }, "Effect must be allow or deny"],
        [{ effect: "ALLOW" }, "Effect must be allow or deny"],
      ];
      for (const [patch, message] of cases) {
        const r = await addRule(id, { ...ok, ...patch });
        expect(r.status, JSON.stringify(patch).slice(0, 50)).toBe(400);
        expect((await errorOf(r)).message, JSON.stringify(patch).slice(0, 50)).toBe(message);
      }
      expect(rulesIn(id)).toHaveLength(before);
      expect((await addRule(randomUUID(), ok)).status).toBe(404);
    });

    it("selectorValid is false for a malformed legacy selector (it never matches)", async () => {
      s.srv.db().prepare("INSERT INTO policy_rules (id, client_id, mailbox_id, folder, operation, effect) VALUES (?, ?, ?, ?, 'move', 'allow')").run(randomUUID(), id, A, "bad*selector");
      const bad = (await detail(id)).rules.find((r) => r.folder === "bad*selector")!;
      expect(bad.selectorValid).toBe(false);
    });

    it("DELETE removes exactly that rule (204); another client's URL cannot delete it; unknown rule ids do not 5xx", async () => {
      const rule = await json<Rule>(await addRule(id, { mailboxId: B, folder: "Temp", operation: "flag", effect: "deny" }));
      const other = await registerClient(s.base, undefined, "rules-other");
      const wrongOwner = await s.admin.delWithCsrf(`/api/clients/${other}/rules/${rule.id}`);
      expect(wrongOwner.status).toBeLessThan(500);
      expect(rulesIn(id).some((r) => r.id === rule.id), "rule of client A must survive a delete issued under client B").toBe(true);
      const r = await s.admin.delWithCsrf(`/api/clients/${id}/rules/${rule.id}`);
      expect(r.status).toBe(204);
      expect(rulesIn(id).some((x) => x.id === rule.id)).toBe(false);
      expect((await s.admin.delWithCsrf(`/api/clients/${id}/rules/${randomUUID()}`)).status).toBeLessThan(500);
    });

    it("a deny rule takes effect on the very next call of an already-issued token, and removing it restores access", async () => {
      const m = s.fake.addMessage(ALICE, "INBOX", msg("rule probe", "rule probe body"));
      const { clientId, tokens } = await obtainToken(s, [[A, "read"]]);
      const mcp = await new Mcp(s.base, tokens.access_token).connect();
      const ref = refOf(s, ALICE, "INBOX", m.uid);
      const before = await mcp.call("read_message", { ref });
      expect(before.isError).toBe(false);
      expect(before.text).toContain("rule probe body");
      const rule = await json<Rule>(await addRule(clientId, { mailboxId: A, folder: "INBOX", operation: "read_body", effect: "deny" }));
      const denied = await mcp.call("read_message", { ref }); // headers stay readable, the body does not
      expect(denied.text).not.toContain("rule probe body");
      expect(denied.isError ? true : (denied.data.body ?? "") === "").toBe(true);
      expect((await mcp.call("search_messages", { mailbox: A, folder: "INBOX" })).isError, "other operations stay allowed").toBe(false);
      expect((await s.admin.delWithCsrf(`/api/clients/${clientId}/rules/${rule.id}`)).status).toBe(204);
      const after = await mcp.call("read_message", { ref });
      expect(after.isError).toBe(false);
      expect(after.text).toContain("rule probe body");
      await mcp.close();
    });
  });

  describe("disable, enable, revoke, token revocation", () => {
    it("disable: 204, revokes every token at once, keeps the grants, blocks new authorizations; enable lifts the block but not the revocation", async () => {
      const { clientId, tokens } = await obtainToken(s, [[A, "read"]]);
      const second = (await obtainToken(s, [[A, "read"]], { clientId })).tokens;
      expect((await rawMcp(s.base, `Bearer ${tokens.access_token}`)).status).toBe(200);
      const grantsBefore = rulesIn(clientId).length;
      expect(grantsBefore).toBeGreaterThan(0);

      const r = await s.admin.postWithCsrf(`/api/clients/${clientId}/disable`);
      expect(r.status).toBe(204);
      expect(await r.text()).toBe("");
      for (const t of [tokens, second]) expect((await rawMcp(s.base, `Bearer ${t.access_token}`)).status).toBe(401);
      // the refresh token is dead too
      const refresh = await fetch(`${s.base}/oauth/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "refresh_token", client_id: clientId, refresh_token: tokens.refresh_token }) });
      expect(refresh.status).toBeGreaterThanOrEqual(400);
      expect(rulesIn(clientId)).toHaveLength(grantsBefore);
      expect((await detail(clientId)).client.disabled).toBe(true);
      expect((await overview()).clients.find((c) => c.clientId === clientId)!.disabled).toBe(true);
      expect((await overview()).tokens.some((t) => t.clientId === clientId)).toBe(false);
      expect((await consent(s.admin, s.base, { clientId, grants: [[A, "read"]] })).location, "a disabled client cannot start an authorization").toBe("status:400");

      expect((await s.admin.postWithCsrf(`/api/clients/${clientId}/enable`)).status).toBe(204);
      expect((await detail(clientId)).client.disabled).toBe(false);
      expect((await rawMcp(s.base, `Bearer ${tokens.access_token}`)).status, "enabling does not resurrect revoked tokens").toBe(401);
      const fresh = (await obtainToken(s, [[A, "read"]], { clientId })).tokens;
      expect((await rawMcp(s.base, `Bearer ${fresh.access_token}`)).status).toBe(200);
    });

    it("revoke: 204, removes every rule and revokes every token, but the client record and the IMAP credentials stay", async () => {
      const { clientId, tokens } = await obtainToken(s, [[A, "read"], [A, "organize"], [B, "read"]]);
      await addRule(clientId, { mailboxId: A, folder: "Work", operation: "search", effect: "deny" });
      expect(rulesIn(clientId).length).toBeGreaterThan(0);
      const r = await s.admin.postWithCsrf(`/api/clients/${clientId}/revoke`);
      expect(r.status).toBe(204);
      expect(rulesIn(clientId)).toHaveLength(0);
      expect((await rawMcp(s.base, `Bearer ${tokens.access_token}`)).status).toBe(401);
      expect((await detail(clientId)).client.disabled, "revoke is not disable").toBe(false);
      expect((s.srv.db().prepare("SELECT COUNT(*) n FROM mailboxes").get() as any).n).toBe(2);
      expect((await s.admin.postWithCsrf(`/api/clients/${randomUUID()}/revoke`)).status).toBe(404);
    });

    it("POST /api/tokens/:id/revoke revokes that token only", async () => {
      const first = await obtainToken(s, [[A, "read"]]);
      const second = (await obtainToken(s, [[A, "read"]], { clientId: first.clientId })).tokens;
      const idOf = (tok: string) => (s.srv.db().prepare("SELECT id FROM oauth_tokens WHERE token_hash = ?").get(sha256hex(tok)) as any).id as string;
      expect((await overview()).tokens.some((t) => t.id === idOf(first.tokens.access_token))).toBe(true);
      const r = await s.admin.postWithCsrf(`/api/tokens/${idOf(first.tokens.access_token)}/revoke`);
      expect(r.status).toBe(204);
      expect((await rawMcp(s.base, `Bearer ${first.tokens.access_token}`)).status).toBe(401);
      expect((await rawMcp(s.base, `Bearer ${second.access_token}`)).status).toBe(200);
      const ov = await overview();
      expect(ov.tokens.some((t) => t.id === idOf(first.tokens.access_token))).toBe(false);
      expect(ov.tokens.some((t) => t.id === idOf(second.access_token))).toBe(true);
    });

    it("the overview's token reach is the token's scope ceiling intersected with the live grants", async () => {
      const { clientId, tokens } = await obtainToken(s, [[A, "read"], [A, "draft"], [B, "read"]]);
      const id = (s.srv.db().prepare("SELECT id FROM oauth_tokens WHERE token_hash = ?").get(sha256hex(tokens.access_token)) as any).id as string;
      const reachOf = async () => (await overview()).tokens.find((t) => t.id === id)!;
      const t0 = await reachOf();
      expect(t0.clientId).toBe(clientId);
      expect(t0.reach.find((r) => r.mailboxId === A)!.capabilities.sort()).toEqual(["draft", "read"]);
      await setGrants(s, clientId, [[A, "read"], [B, "organize"]]); // organize was never consented: it is outside the ceiling
      const t1 = await reachOf();
      expect(t1.reach.find((r) => r.mailboxId === A)!.capabilities).toEqual(["read"]);
      const b = t1.reach.find((r) => r.mailboxId === B);
      expect(b?.capabilities ?? [], "B only has organize, which the token cannot use").toEqual([]);
    });
  });

  describe("wire format", () => {
    it("every timestamp in the client, rule, token and mailbox DTOs is ISO-8601 UTC (shared/types/api.ts)", async () => {
      const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;
      const { clientId } = await obtainToken(s, [[A, "read"]], { name: "iso-client" });
      await addRule(clientId, { mailboxId: A, folder: "Work", operation: "search", effect: "allow" });
      const ov = await overview();
      const d = await detail(clientId);
      const stamps: Array<[string, string]> = [
        ["overview.clients[].createdAt", ov.clients.find((c) => c.clientId === clientId)!.createdAt],
        ["overview.mailboxes[].createdAt", ov.mailboxes[0].createdAt],
        ["overview.tokens[].createdAt", ov.tokens.find((t) => t.clientId === clientId)!.createdAt],
        ["overview.tokens[].expiresAt", ov.tokens.find((t) => t.clientId === clientId)!.expiresAt],
        ["client.createdAt", d.client.createdAt],
        ["rules[].createdAt", d.rules[0].createdAt],
      ];
      for (const [name, v] of stamps) expect(v, name).toMatch(ISO);
    });
  });

  describe("overview", () => {
    it("lists mailboxes, clients, flat grants and tokens, with the registration mode, and carries no secret", async () => {
      const { clientId, tokens } = await obtainToken(s, [[A, "read"]], { name: "overview-client" });
      const ov = await overview();
      expect(ov.registrationMode).toBe("dynamic");
      expect(ov.mailboxes.map((m) => m.id).sort()).toEqual([A, B].sort());
      expect(ov.clients.find((c) => c.clientId === clientId)).toMatchObject({ clientName: "overview-client", disabled: false });
      expect(ov.grants).toEqual(expect.arrayContaining([{ clientId, mailboxId: A, capability: "read" }]));
      expect(ov.grants.every((g) => ["read", "draft", "organize"].includes(g.capability))).toBe(true);
      expect(ov.tokens.some((t) => t.clientId === clientId && t.clientName === "overview-client")).toBe(true);
      const text = JSON.stringify(ov);
      for (const secret of [tokens.access_token, tokens.refresh_token, sha256hex(tokens.access_token), ...Object.values(s.imapPasswords)]) expect(text.includes(secret)).toBe(false);
      void exchange;
    });
  });
});

describe.skipIf(!haveOpenssl)("REGISTRATION_MODE=admin: admin-created clients", () => {
  let s: Stack;
  beforeAll(async () => { s = await createStack({ accounts: [ALICE], env: { REGISTRATION_MODE: "admin" } }); });
  afterAll(async () => { await s?.teardown(); });

  it("the session reports the mode and the admin can create a client that is then usable for the OAuth flow", async () => {
    expect((await s.admin.session()).registrationMode).toBe("admin");
    const r = await s.admin.postWithCsrf("/api/clients", { name: "  Admin made  ", redirectUris: [REDIRECT, "https://app.example/cb"] });
    expect([200, 201]).toContain(r.status);
    const c = await json<ClientSummary>(r);
    expect(c).toMatchObject({ clientName: "Admin made", disabled: false });
    expect(c.clientId).toMatch(/\S{8,}/);
    expect(c.createdAt).toMatch(/^\d{4}-\d\d-\d\d/);
    const d = await json<ClientDetail>(await s.admin.get(`/api/clients/${c.clientId}`));
    expect(d.client.redirectUris).toEqual([REDIRECT, "https://app.example/cb"]);
    expect(d.rules).toEqual([]); // creating a client grants nothing
    const ov = await json<Overview>(await s.admin.get("/api/overview"));
    expect(ov.registrationMode).toBe("admin");
    expect(ov.clients.some((x) => x.clientId === c.clientId)).toBe(true);

    const A = s.mailbox[ALICE];
    const done = await consent(s.admin, s.base, { clientId: c.clientId, grants: [[A, "read"]] });
    const code = new URL(done.location).searchParams.get("code");
    expect(code, done.location).toBeTruthy();
    expect((await exchange(s.base, c.clientId, code!, done.pkce.verifier)).status).toBe(200);
    // a redirect URI that was not registered still never gets a redirect
    expect((await consent(s.admin, s.base, { clientId: c.clientId, grants: [[A, "read"]], redirectUri: "https://evil.example/cb" })).location).toBe("status:400");
  });

  it("validates name and redirect URIs (1-10, https or loopback http, no fragments) with the old message", async () => {
    const MSG = "Name and 1-10 valid redirect URIs required (https, or http on localhost)";
    const before = ((await json<Overview>(await s.admin.get("/api/overview"))).clients).length;
    const bad: Array<Record<string, unknown>> = [
      { name: "", redirectUris: [REDIRECT] },
      { name: "   ", redirectUris: [REDIRECT] },
      { name: "x", redirectUris: [] },
      { name: "x", redirectUris: ["http://evil.example/cb"] },
      { name: "x", redirectUris: ["javascript:alert(1)"] },
      { name: "x", redirectUris: ["https://x.example/cb#frag"] },
      { name: "x", redirectUris: ["not a url"] },
      { name: "x", redirectUris: [REDIRECT, "ftp://x.example/"] },
      { name: "x", redirectUris: Array.from({ length: 11 }, (_, i) => `https://x.example/cb${i}`) },
    ];
    for (const body of bad) {
      const r = await s.admin.postWithCsrf("/api/clients", body);
      expect(r.status, JSON.stringify(body).slice(0, 80)).toBe(400);
      expect((await errorOf(r)).message).toBe(MSG);
    }
    expect((await json<Overview>(await s.admin.get("/api/overview"))).clients).toHaveLength(before);
    const ten = await s.admin.postWithCsrf("/api/clients", { name: "ten", redirectUris: Array.from({ length: 10 }, (_, i) => `https://x.example/cb${i}`) });
    expect([200, 201]).toContain(ten.status);
  });

  it("dynamic registration is refused while the admin can still create clients", async () => {
    const r = await fetch(`${s.base}/oauth/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ redirect_uris: [REDIRECT] }) });
    expect(r.status).toBe(403);
  });
});

describe.skipIf(!haveOpenssl)("REGISTRATION_MODE=dynamic: the admin cannot create clients through the API", () => {
  it("POST /api/clients is 403 and creates nothing", async () => {
    const s = await createStack({ accounts: [ALICE], skipMailboxes: true });
    try {
      const r = await s.admin.postWithCsrf("/api/clients", { name: "nope", redirectUris: [REDIRECT] });
      expect(r.status).toBe(403);
      expect((await errorOf(r)).code).not.toBe("csrf");
      expect((s.srv.db().prepare("SELECT COUNT(*) n FROM oauth_clients").get() as any).n).toBe(0);
    } finally { await s.teardown(); }
  });
});
