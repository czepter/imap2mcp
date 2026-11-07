/**
 * Version 0 acceptance criterion 4: default deny; client x mailbox x capability matrix; draft/organize do not imply
 * read; grant edits in the admin UI take effect on the very next call of an already-issued token.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { makeSelfSignedCert } from "../helpers/certs.js";
import { createStack, obtainToken, setGrants, Mcp, msg, refOf, ALL_CAPS, type Cap, type Stack } from "../helpers/stack.js";

const haveOpenssl = !!makeSelfSignedCert();
if (!haveOpenssl) console.warn("SKIPPED policy-matrix: openssl not available to create the fixture TLS certificate");

const A = "alice@example.test";
const B = "bob@example.test";

type Op = { name: string; cap: Cap; run: (s: Stack, mcp: Mcp, user: string, mailboxId: string) => ReturnType<Mcp["call"]> };
const freshRef = (s: Stack, user: string) => {
  const m = s.fake.addMessage(user, "INBOX", msg("matrix " + Math.random()));
  return refOf(s, user, "INBOX", m.uid);
};
const OPS: Op[] = [
  { name: "list_folders", cap: "read", run: (_s, c, _u, id) => c.call("list_folders", { mailbox: id }) },
  { name: "search_messages", cap: "read", run: (_s, c, _u, id) => c.call("search_messages", { mailbox: id, folder: "INBOX" }) },
  { name: "read_message", cap: "read", run: (s, c, u) => c.call("read_message", { ref: freshRef(s, u) }) },
  { name: "create_draft", cap: "draft", run: (_s, c, _u, id) => c.call("create_draft", { mailbox: id, subject: "m", body: "b" }) },
  { name: "set_flags", cap: "organize", run: (s, c, u) => c.call("set_flags", { refs: [freshRef(s, u)], add: ["\\Flagged"] }) },
  { name: "move_message", cap: "organize", run: (s, c, u) => c.call("move_message", { ref: freshRef(s, u), destination: "Archive" }) },
];

describe.skipIf(!haveOpenssl)("policy: default deny and the client x mailbox x capability matrix", () => {
  let s: Stack;
  let M: Record<string, string>; // user -> mailbox id
  beforeAll(async () => {
    s = await createStack();
    M = { [A]: s.mailbox[A], [B]: s.mailbox[B] };
  });
  afterAll(async () => { await s?.teardown(); });

  const clients: Array<{ name: string; grants: Array<[string, Cap]> }> = [
    { name: "K1 read A + organize A + draft B", grants: [[A, "read"], [A, "organize"], [B, "draft"]] },
    { name: "K2 draft A only", grants: [[A, "draft"]] },
    { name: "K3 read B only", grants: [[B, "read"]] },
    { name: "K4 organize B only", grants: [[B, "organize"]] },
    { name: "K5 everything everywhere", grants: [A, B].flatMap((u) => ALL_CAPS.map((c) => [u, c] as [string, Cap])) },
  ];

  for (const k of clients) {
    describe(k.name, () => {
      let mcp: Mcp;
      beforeAll(async () => {
        const { tokens } = await obtainToken(s, k.grants.map(([u, c]) => [M[u], c] as [string, Cap]), { name: k.name });
        mcp = await new Mcp(s.base, tokens.access_token).connect();
      });
      afterAll(async () => { await mcp?.close(); });

      for (const user of [A, B]) {
        for (const op of OPS) {
          const allowed = k.grants.some(([u, c]) => u === user && c === op.cap);
          it(`${op.name} on ${user.split("@")[0]}: ${allowed ? "allowed" : "FORBIDDEN"}`, async () => {
            const wireBefore = s.fake.commands.filter((c) => c.user === user).length;
            const r = await op.run(s, mcp, user, M[user]);
            if (allowed) {
              expect(r.isError, r.text).toBe(false);
            } else {
              expect(r.isError).toBe(true);
              expect(r.data.code).toBe("FORBIDDEN");
              // a denied call never reaches the mailbox (freshRef adds via the fake directly, not over IMAP)
              expect(s.fake.commands.filter((c) => c.user === user).length).toBe(wireBefore);
              expect(r.text).not.toMatch(/matrix|localhost|example\.test/);
            }
          });
        }
      }

      it("list_mailboxes reveals only granted mailboxes and their capabilities", async () => {
        const r = await mcp.call("list_mailboxes");
        const expected = new Map<string, Set<string>>();
        for (const [u, c] of k.grants) expected.set(M[u], (expected.get(M[u]) ?? new Set()).add(c));
        expect(new Map(r.data.mailboxes.map((m: any) => [m.id, new Set(m.capabilities)]))).toEqual(expected);
      });
    });
  }

  it("unknown mailbox ids are FORBIDDEN, indistinguishable from an ungranted one", async () => {
    const { tokens } = await obtainToken(s, [[M[A], "read"]]);
    const c = await new Mcp(s.base, tokens.access_token).connect();
    const ghost = await c.call("list_folders", { mailbox: "00000000-0000-0000-0000-000000000000" });
    const other = await c.call("list_folders", { mailbox: M[B] });
    expect(ghost.data).toEqual(other.data);
    expect(ghost.data.code).toBe("FORBIDDEN");
    await c.close();
  });

  it("organize on one mailbox does not authorize moving a message of another mailbox", async () => {
    const { tokens } = await obtainToken(s, [[M[B], "organize"]]);
    const c = await new Mcp(s.base, tokens.access_token).connect();
    const victim = s.fake.addMessage(A, "INBOX", msg("victim"));
    const r = await c.call("move_message", { ref: refOf(s, A, "INBOX", victim.uid), destination: "Archive" });
    expect(r.data.code).toBe("FORBIDDEN");
    expect(s.fake.folder(A, "INBOX").messages.includes(victim)).toBe(true);
    // a destination cannot name another mailbox: it is a folder name inside the source mailbox
    const own = s.fake.addMessage(B, "INBOX", msg("own"));
    const bad = await c.call("move_message", { ref: refOf(s, B, "INBOX", own.uid), destination: `${M[A]}/Archive` });
    expect(bad.isError).toBe(true);
    expect(s.fake.folder(B, "INBOX").messages.includes(own)).toBe(true);
    await c.close();
  });

  describe("grant changes apply to already-issued tokens on the next call", () => {
    it("removing a capability takes effect immediately; re-adding restores it without a new token", async () => {
      const { clientId, tokens } = await obtainToken(s, [[M[A], "read"], [M[A], "organize"]]);
      const c = await new Mcp(s.base, tokens.access_token).connect();
      const ref = freshRef(s, A);
      expect((await c.call("read_message", { ref })).isError).toBe(false);
      expect((await c.call("set_flags", { refs: [ref], add: ["\\Flagged"] })).isError).toBe(false);

      await setGrants(s, clientId, [[M[A], "read"]]); // drop organize in the UI
      expect((await c.call("set_flags", { refs: [ref], add: ["\\Answered"] })).data.code).toBe("FORBIDDEN");
      expect((await c.call("read_message", { ref })).isError).toBe(false); // read untouched
      expect(s.fake.folder(A, "INBOX").messages.find((m) => m.uid === ref.uid)!.flags.has("\\Answered")).toBe(false);

      await setGrants(s, clientId, []); // drop everything
      expect((await c.call("read_message", { ref })).data.code).toBe("FORBIDDEN");
      expect((await c.call("list_mailboxes")).data.mailboxes).toEqual([]);

      await setGrants(s, clientId, [[M[A], "read"], [M[A], "organize"]]); // restore
      expect((await c.call("set_flags", { refs: [ref], add: ["\\Answered"] })).isError).toBe(false);
      await c.close();
    });

    it("a grant added later never widens an existing token beyond its consented scopes", async () => {
      const { clientId, tokens } = await obtainToken(s, [[M[A], "read"]]);
      const c = await new Mcp(s.base, tokens.access_token).connect();
      await setGrants(s, clientId, [[M[A], "read"], [M[A], "organize"], [M[A], "draft"], [M[B], "read"]]);
      const ref = freshRef(s, A);
      expect((await c.call("set_flags", { refs: [ref], add: ["\\Flagged"] })).data.code).toBe("FORBIDDEN");
      expect((await c.call("create_draft", { mailbox: M[A], subject: "s", body: "b" })).data.code).toBe("FORBIDDEN");
      // read on A is within the scope; read on B has a grant row now and read is in the token's scopes
      expect((await c.call("read_message", { ref })).isError).toBe(false);
      await c.close();
    });

    it("a client's grants are not shared with other clients", async () => {
      const a = await obtainToken(s, [[M[A], "read"]]);
      const bare = await obtainToken(s, [[M[B], "read"]]);
      const c = await new Mcp(s.base, bare.tokens.access_token).connect();
      expect((await c.call("list_folders", { mailbox: M[A] })).data.code).toBe("FORBIDDEN");
      expect(a.clientId).not.toBe(bare.clientId);
      await c.close();
    });

    it("deleting a mailbox removes its grants: calls fail closed", async () => {
      const id = M[B];
      const { tokens } = await obtainToken(s, [[id, "read"]]);
      const c = await new Mcp(s.base, tokens.access_token).connect();
      expect((await c.call("list_folders", { mailbox: id })).isError).toBe(false);
      const r = await s.admin.postWithCsrf(`/mailboxes/${id}`, `/mailboxes/${id}/delete`, {});
      expect(r.status).toBe(302);
      expect((await c.call("list_folders", { mailbox: id })).data.code).toBe("FORBIDDEN");
      expect(s.srv.db().prepare("SELECT COUNT(*) n FROM policy_rules WHERE mailbox_id = ?").get(id)).toEqual({ n: 0 });
      await c.close();
    });
  });
});
