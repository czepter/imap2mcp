/**
 * Black-box acceptance tests for the consent API (GET/POST /api/oauth/authorize, docs/NUXT_MIGRATION.md): the old
 * server-rendered consent screen's behaviour, every validation error (page errors are 400 JSON, protocol errors the
 * client must hear about come back as { redirectTo }), approve / deny, "nothing ticked means no access", the
 * requested-capability ceiling, and unregistered redirect URIs.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createHash } from "node:crypto";
import { makeSelfSignedCert } from "../helpers/certs.js";
import { Browser, errorOf, json } from "../helpers/http.js";
import {
  addMailboxRaw, authorizeQuery, createStack, exchange, pkce, registerClient, REDIRECT, type Pkce, type Stack,
} from "../helpers/stack.js";
import type { AuthorizeRequest } from "../../shared/types/api.js";

const haveOpenssl = !!makeSelfSignedCert();
const ALICE = "alice@example.test";
const BOB = "bob@example.test";
const SECOND = "http://localhost:8765/second";

describe.skipIf(!haveOpenssl)("consent API", () => {
  let s: Stack;
  let A: string;
  let B: string;
  let clientId: string;
  const q = (o: Record<string, string | undefined> = {}, p: Pkce = pkce()) => {
    const base = authorizeQuery({ clientId, pkce: p });
    for (const [k, v] of Object.entries(o)) v === undefined ? base.delete(k) : base.set(k, v);
    return base;
  };
  const get = (query: URLSearchParams) => s.admin.get(`/api/oauth/authorize?${query}`);
  const redirectOf = async (r: Response): Promise<URL> => {
    const body = (await r.json()) as { redirectTo?: string };
    expect(body.redirectTo, "expected a { redirectTo } body").toBeTruthy();
    return new URL(body.redirectTo!);
  };
  /** GET to fetch the validated params, then POST them back with a decision. */
  async function decide(query: URLSearchParams, decision: "approve" | "deny", grants: Array<[string, string]>, override: Record<string, unknown> = {}) {
    const g = await get(query);
    expect(g.status).toBe(200);
    const req = await json<AuthorizeRequest>(g);
    return s.admin.postWithCsrf("/api/oauth/authorize", { params: { ...req.params, ...override }, decision, grants: grants.map(([mailboxId, capability]) => ({ mailboxId, capability })) });
  }
  const codesCount = () => (s.srv.db().prepare("SELECT COUNT(*) n FROM oauth_codes WHERE client_id = ?").get(clientId) as any).n as number;
  const rulesOf = (id = clientId) => (s.srv.db().prepare("SELECT mailbox_id m, operation o FROM policy_rules WHERE client_id = ?").all(id) as any[]).map((r) => `${r.m === A ? "A" : r.m === B ? "B" : r.m}:${r.o}`).sort();

  beforeAll(async () => {
    s = await createStack();
    A = s.mailbox[ALICE];
    B = s.mailbox[BOB];
    clientId = await registerClient(s.base, [REDIRECT, SECOND], "consent-client");
  });
  afterAll(async () => { await s?.teardown(); });

  describe("GET: describes the request", () => {
    it("returns AuthorizeRequest: client, redirect, requested capabilities, mailboxes (with Drafts state) and the normalised params to echo", async () => {
      const p = pkce();
      const query = q({ state: "xyz-1", scope: "mail:organize mail:read" }, p);
      const r = await get(query);
      expect(r.status).toBe(200);
      expect(r.headers.get("cache-control")).toMatch(/no-store/);
      const a = await json<AuthorizeRequest>(r);
      expect(a.client).toMatchObject({ id: clientId, name: "consent-client" });
      expect(a.client.createdAt).toMatch(/^\d{4}-\d\d-\d\d/);
      expect(a.redirectUri).toBe(REDIRECT);
      expect(a.capabilities).toEqual(["read", "organize"]); // canonical order, only what was asked for
      expect(a.mailboxes.map((m) => m.id).sort()).toEqual([A, B].sort());
      expect(a.mailboxes.find((m) => m.id === A)).toMatchObject({ label: "Box alice", draftsFolder: "Drafts" });
      expect(a.params).toEqual({
        client_id: clientId, redirect_uri: REDIRECT, state: "xyz-1", response_type: "code", code_challenge: p.challenge,
        code_challenge_method: "S256", resource: `${s.base}/mcp`, scope: "mail:organize mail:read", // as requested; only the capability list is canonical
      });
    });

    it("defaults: no resource means this server's /mcp, no scope means all three capabilities, no state stays absent", async () => {
      const a = await json<AuthorizeRequest>(await get(q({ scope: undefined, state: undefined, resource: undefined })));
      expect(a.params.resource).toBe(`${s.base}/mcp`);
      expect(a.params.scope).toBe("mail:read mail:draft mail:organize");
      expect(a.capabilities).toEqual(["read", "draft", "organize"]);
      expect(a.params.state).toBeUndefined();
    });

    it("unknown scope tokens are dropped when at least one capability remains; the client name falls back for unnamed clients", async () => {
      const a = await json<AuthorizeRequest>(await get(q({ scope: "mail:read mail:bogus openid" })));
      expect(a.capabilities).toEqual(["read"]);
      expect(a.params.scope).toBe("mail:read");
    });

    it("lists a mailbox without a Drafts folder as such (the draft column is unavailable for it)", async () => {
      const nd = await addMailboxRaw(s, { label: "No drafts yet", host: "localhost", port: s.fake.port, user: ALICE, pass: s.imapPasswords[ALICE] });
      const a = await json<AuthorizeRequest>(await get(q()));
      expect(a.mailboxes.find((m) => m.id === nd)).toMatchObject({ label: "No drafts yet", draftsFolder: null });
      expect((await s.admin.delWithCsrf(`/api/mailboxes/${nd}`, { confirmLabel: "No drafts yet" })).status).toBe(204);
    });
  });

  describe("validation errors", () => {
    it("page errors (nothing safe to redirect to) are 400 JSON errors with the old messages and never carry a redirectTo", async () => {
      const page = async (query: URLSearchParams, message: string) => {
        const r = await get(query);
        expect(r.status, message).toBe(400);
        const text = await r.clone().text();
        expect(text).not.toContain("redirectTo");
        expect((await errorOf(r)).message).toBe(message);
      };
      await page(q({ client_id: undefined }), "Missing client_id or redirect_uri");
      await page(q({ redirect_uri: undefined }), "Missing client_id or redirect_uri");
      await page(q({ client_id: "" }), "Missing client_id or redirect_uri");
      await page(q({ client_id: "no-such-client" }), "Unknown or disabled client");
      for (const uri of ["http://localhost:1/not-registered", REDIRECT + "/x", REDIRECT + "?a=1", "HTTP://LOCALHOST:8765/callback", "https://evil.example/cb", "javascript:alert(1)"]) {
        await page(q({ redirect_uri: uri }), "redirect_uri is not registered for this client");
      }
      // a bad redirect_uri wins over protocol errors: an unregistered URI must never receive a redirect
      await page(q({ redirect_uri: "https://evil.example/cb", code_challenge: undefined, response_type: "token" }), "redirect_uri is not registered for this client");
    });

    it.each<[string, Record<string, string | undefined>, string, string | null]>([
      ["response_type=token", { response_type: "token" }, "unsupported_response_type", null],
      ["response_type missing", { response_type: undefined }, "unsupported_response_type", null],
      ["no code_challenge", { code_challenge: undefined }, "invalid_request", "PKCE with code_challenge_method=S256 is required"],
      ["code_challenge_method=plain", { code_challenge_method: "plain" }, "invalid_request", "PKCE with code_challenge_method=S256 is required"],
      ["code_challenge_method missing", { code_challenge_method: undefined }, "invalid_request", "PKCE with code_challenge_method=S256 is required"],
      ["code_challenge too short", { code_challenge: "abc" }, "invalid_request", "PKCE with code_challenge_method=S256 is required"],
      ["code_challenge too long", { code_challenge: "A".repeat(44) }, "invalid_request", "PKCE with code_challenge_method=S256 is required"],
      ["code_challenge with illegal characters", { code_challenge: "+".repeat(43) }, "invalid_request", "PKCE with code_challenge_method=S256 is required"],
      ["foreign resource", { resource: "https://evil.example/mcp" }, "invalid_target", "Unknown resource"],
      ["resource with trailing slash", { resource: "BASE/mcp/" }, "invalid_target", "Unknown resource"],
      ["only unknown scopes", { scope: "openid profile" }, "invalid_scope", null],
      ["scope with a foreign namespace", { scope: "mail:delete" }, "invalid_scope", null],
    ])("protocol error %s comes back as { redirectTo } with error, state and iss", async (_n, patch, error, description) => {
      const fixed = Object.fromEntries(Object.entries(patch).map(([k, v]) => [k, v?.replace("BASE", s.base)]));
      const r = await get(q({ state: "keep-me", ...fixed }));
      const u = await redirectOf(r);
      expect(`${u.origin}${u.pathname}`).toBe(REDIRECT);
      expect(u.searchParams.get("error")).toBe(error);
      if (description) expect(u.searchParams.get("error_description")).toBe(description);
      expect(u.searchParams.get("state")).toBe("keep-me");
      expect(u.searchParams.get("iss")).toBe(s.base);
      expect(u.searchParams.get("code")).toBeNull();
    });

    it("the same protocol errors are reported by POST (parameters can be tampered with between GET and POST)", async () => {
      const cases: Array<[Record<string, unknown>, string]> = [
        [{ code_challenge_method: "plain" }, "invalid_request"],
        [{ resource: "https://evil.example/mcp" }, "invalid_target"],
        [{ scope: "nonsense" }, "invalid_scope"],
        [{ response_type: "token" }, "unsupported_response_type"],
      ];
      for (const [override, error] of cases) {
        const before = codesCount();
        const r = await decide(q({ state: "post-state" }), "approve", [[A, "read"]], override);
        const u = await redirectOf(r);
        expect(u.searchParams.get("error"), JSON.stringify(override)).toBe(error);
        expect(u.searchParams.get("state")).toBe("post-state");
        expect(u.searchParams.get("code")).toBeNull();
        expect(codesCount()).toBe(before);
      }
      const bad = await decide(q(), "approve", [[A, "read"]], { redirect_uri: "https://evil.example/cb" });
      expect(bad.status).toBe(400);
      expect(await bad.text()).not.toContain("redirectTo");
      const missing = await decide(q(), "approve", [[A, "read"]], { client_id: "" });
      expect(missing.status).toBe(400);
      const unknown = await decide(q(), "approve", [[A, "read"]], { client_id: "no-such-client" });
      expect(unknown.status).toBe(400);
      expect(rulesOf(), "no failed attempt may grant anything").toEqual([]);
    });
  });

  describe("POST: decisions", () => {
    it("deny: redirect with access_denied, state and iss; no code, no grants", async () => {
      const r = await decide(q({ state: "deny-state" }), "deny", [[A, "read"], [A, "organize"]]);
      expect(r.status).toBe(200);
      const u = await redirectOf(r);
      expect(u.searchParams.get("error")).toBe("access_denied");
      expect(u.searchParams.get("state")).toBe("deny-state");
      expect(u.searchParams.get("iss")).toBe(s.base);
      expect(u.searchParams.get("code")).toBeNull();
      expect(codesCount()).toBe(0);
      expect(rulesOf()).toEqual([]);
    });

    it("anything other than an explicit approve is a denial", async () => {
      for (const decision of [undefined, "", "APPROVE", "yes", "approved", 1]) {
        const g = await json<AuthorizeRequest>(await get(q()));
        const r = await s.admin.postWithCsrf("/api/oauth/authorize", { params: g.params, grants: [{ mailboxId: A, capability: "read" }], ...(decision === undefined ? {} : { decision }) });
        const u = await redirectOf(r);
        expect(u.searchParams.get("error"), String(decision)).toBe("access_denied");
      }
      expect(codesCount()).toBe(0);
      expect(rulesOf()).toEqual([]);
    });

    it("approve with nothing ticked means no access: access_denied 'No permissions were granted', no code, no grants", async () => {
      const r = await decide(q({ state: "none" }), "approve", []);
      const u = await redirectOf(r);
      expect(u.searchParams.get("error")).toBe("access_denied");
      expect(u.searchParams.get("error_description")).toBe("No permissions were granted");
      expect(u.searchParams.get("state")).toBe("none");
      expect(u.searchParams.get("code")).toBeNull();
      expect(codesCount()).toBe(0);
      expect(rulesOf()).toEqual([]);
    });

    it("unknown mailboxes, unknown capabilities and malformed entries count as nothing ticked", async () => {
      for (const grants of [
        [{ mailboxId: "no-such-mailbox", capability: "read" }],
        [{ mailboxId: A, capability: "admin" }],
        [{ mailboxId: A }],
        [null],
        "read",
        undefined,
      ]) {
        const g = await json<AuthorizeRequest>(await get(q()));
        const r = await s.admin.postWithCsrf("/api/oauth/authorize", { params: g.params, decision: "approve", ...(grants === undefined ? {} : { grants }) });
        expect(r.status, JSON.stringify(grants)).toBeLessThan(500);
        const body = (await r.json()) as { redirectTo?: string };
        if (body.redirectTo) {
          const u = new URL(body.redirectTo);
          expect(u.searchParams.get("code"), JSON.stringify(grants)).toBeNull();
          expect(u.searchParams.get("error")).toBe("access_denied");
        }
      }
      expect(codesCount()).toBe(0);
      expect(rulesOf()).toEqual([]);
    });

    it("approve: the redirect carries code, state and iss, grants become preset rules, and the code is single-use and bound to the PKCE verifier and the granted scopes", async () => {
      const p = pkce();
      const r = await decide(q({ state: "ok-state" }, p), "approve", [[A, "read"], [A, "draft"], [B, "organize"]]);
      expect(r.status).toBe(200);
      expect(r.headers.get("cache-control")).toMatch(/no-store/);
      const u = await redirectOf(r);
      expect(`${u.origin}${u.pathname}`).toBe(REDIRECT);
      expect(u.searchParams.get("state")).toBe("ok-state");
      expect(u.searchParams.get("iss")).toBe(s.base);
      expect(u.searchParams.get("error")).toBeNull();
      const code = u.searchParams.get("code")!;
      expect(code).toMatch(/^[A-Za-z0-9_-]{20,}$/);
      expect(rulesOf()).toEqual(["A:draft", "A:read_body", "A:read_headers", "A:search", "B:flag", "B:move"].sort());
      // the code is stored hashed
      expect(s.srv.db().prepare("SELECT 1 FROM oauth_codes WHERE code_hash = ?").get(createHash("sha256").update(code).digest("hex"))).toBeTruthy();
      expect(JSON.stringify(s.srv.db().prepare("SELECT * FROM oauth_codes").all())).not.toContain(code);
      // wrong verifier burns it; the right one afterwards fails too
      expect((await exchange(s.base, clientId, code, pkce().verifier)).status).toBe(400);
      expect((await exchange(s.base, clientId, code, p.verifier)).status).toBe(400);

      const p2 = pkce();
      const u2 = await redirectOf(await decide(q({}, p2), "approve", [[A, "read"], [A, "draft"], [B, "organize"]]));
      const tok = await exchange(s.base, clientId, u2.searchParams.get("code")!, p2.verifier);
      expect(tok.status).toBe(200);
      expect((((await tok.json()) as any).scope as string).split(" ").sort()).toEqual(["mail:draft", "mail:organize", "mail:read"]);
      expect(rulesOf(), "re-approving the same grants adds nothing").toHaveLength(6);
    });

    it("the token scope is exactly the granted capabilities, not everything that was requested", async () => {
      const id = await registerClient(s.base, [REDIRECT], "narrow");
      const p = pkce();
      const query = authorizeQuery({ clientId: id, pkce: p }); // requests read + draft + organize
      const g = await json<AuthorizeRequest>(await get(query));
      const r = await s.admin.postWithCsrf("/api/oauth/authorize", { params: g.params, decision: "approve", grants: [{ mailboxId: A, capability: "read" }] });
      const code = (await redirectOf(r)).searchParams.get("code")!;
      const tok = (await (await exchange(s.base, id, code, p.verifier)).json()) as any;
      expect(tok.scope).toBe("mail:read");
      expect(rulesOf(id)).toEqual(["A:read_body", "A:read_headers", "A:search"]);
    });

    it("requested-capability ceiling: ticks for capabilities the client did not ask for are ignored", async () => {
      const id = await registerClient(s.base, [REDIRECT], "ceiling");
      const p = pkce();
      const query = authorizeQuery({ clientId: id, pkce: p, scope: "mail:read" });
      const g = await json<AuthorizeRequest>(await get(query));
      expect(g.capabilities).toEqual(["read"]);
      const r = await s.admin.postWithCsrf("/api/oauth/authorize", { params: g.params, decision: "approve", grants: [{ mailboxId: A, capability: "read" }, { mailboxId: A, capability: "organize" }, { mailboxId: B, capability: "draft" }] });
      const code = (await redirectOf(r)).searchParams.get("code")!;
      expect(rulesOf(id)).toEqual(["A:read_body", "A:read_headers", "A:search"]);
      const tok = (await (await exchange(s.base, id, code, p.verifier)).json()) as any;
      expect(tok.scope).toBe("mail:read");

      // ticking only things that were not requested grants nothing at all
      const id2 = await registerClient(s.base, [REDIRECT], "ceiling-2");
      const g2 = await json<AuthorizeRequest>(await get(authorizeQuery({ clientId: id2, pkce: pkce(), scope: "mail:read" })));
      const r2 = await s.admin.postWithCsrf("/api/oauth/authorize", { params: g2.params, decision: "approve", grants: [{ mailboxId: A, capability: "organize" }] });
      const u2 = await redirectOf(r2);
      expect(u2.searchParams.get("error")).toBe("access_denied");
      expect(u2.searchParams.get("code")).toBeNull();
      expect(rulesOf(id2)).toEqual([]);
    });

    it("the redirect goes to the registered URI that was asked for, keeping an existing query string", async () => {
      const id = await registerClient(s.base, [SECOND + "?tenant=7", REDIRECT], "two-uris");
      const query = authorizeQuery({ clientId: id, pkce: pkce(), redirectUri: SECOND + "?tenant=7" });
      const g = await json<AuthorizeRequest>(await get(query));
      expect(g.redirectUri).toBe(SECOND + "?tenant=7");
      const u = await redirectOf(await s.admin.postWithCsrf("/api/oauth/authorize", { params: g.params, decision: "approve", grants: [{ mailboxId: A, capability: "read" }] }));
      expect(`${u.origin}${u.pathname}`).toBe(SECOND);
      expect(u.searchParams.get("tenant")).toBe("7");
      expect(u.searchParams.get("code")).toBeTruthy();
    });

    it("a disabled client cannot be authorized (GET and POST are 400), even with a previously valid request", async () => {
      const id = await registerClient(s.base, [REDIRECT], "to-disable");
      const g = await json<AuthorizeRequest>(await get(authorizeQuery({ clientId: id, pkce: pkce() })));
      expect((await s.admin.postWithCsrf(`/api/clients/${id}/disable`)).status).toBe(204);
      const again = await s.admin.get(`/api/oauth/authorize?${authorizeQuery({ clientId: id, pkce: pkce() })}`);
      expect(again.status).toBe(400);
      expect((await errorOf(again)).message).toBe("Unknown or disabled client");
      const post = await s.admin.postWithCsrf("/api/oauth/authorize", { params: g.params, decision: "approve", grants: [{ mailboxId: A, capability: "read" }] });
      expect(post.status).toBe(400);
      expect(rulesOf(id)).toEqual([]);
    });
  });

  describe("access control", () => {
    it("both endpoints need the admin session; POST also needs the CSRF header", async () => {
      const anon = new Browser(s.base);
      const get401 = await anon.get(`/api/oauth/authorize?${q()}`);
      expect(get401.status).toBe(401);
      expect(await get401.text()).not.toContain("redirectTo");
      const g = await json<AuthorizeRequest>(await get(q()));
      const body = { params: g.params, decision: "approve", grants: [{ mailboxId: A, capability: "read" }] };
      const post401 = await anon.withCsrf("POST", "/api/oauth/authorize", body);
      expect(post401.status).toBe(401);
      expect(await post401.text()).not.toContain("redirectTo");

      const before = codesCount();
      const noCsrf = await s.admin.post("/api/oauth/authorize", body);
      expect(noCsrf.status).toBe(403);
      expect(await noCsrf.text()).not.toContain("redirectTo");
      expect(codesCount()).toBe(before);
      expect(rulesOf("someone-else")).toEqual([]);
    });
  });

  describe("no mailboxes configured", () => {
    it("GET still describes the request with an empty mailbox list; approving yields access_denied", async () => {
      const s2 = await createStack({ accounts: [ALICE], skipMailboxes: true });
      try {
        const id = await registerClient(s2.base, [REDIRECT], "empty");
        const g = await json<AuthorizeRequest>(await s2.admin.get(`/api/oauth/authorize?${authorizeQuery({ clientId: id, pkce: pkce() })}`));
        expect(g.mailboxes).toEqual([]);
        const r = await s2.admin.postWithCsrf("/api/oauth/authorize", { params: g.params, decision: "approve", grants: [{ mailboxId: "x", capability: "read" }] });
        const u = new URL(((await r.json()) as any).redirectTo);
        expect(u.searchParams.get("error")).toBe("access_denied");
        expect(u.searchParams.get("code")).toBeNull();
      } finally { await s2.teardown(); }
    });
  });
});
