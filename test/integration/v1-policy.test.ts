/**
 * Version 1 acceptance criterion 1 (policy refinement), end to end: real HTTP/OAuth, real server process, the Go
 * sidecar serving reads, the fake IMAP-over-TLS server. Rules are installed straight into policy_rules (the exact
 * contract in docs/DESIGN_V1.md) so each case controls the rule set precisely.
 */
import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import { makeSelfSignedCert } from "../helpers/certs.js";
import { msg, sleep, type Stack } from "../helpers/stack.js";
import { ALICE, allowAll, createV1Stack, folderOf, haveSidecar, newClient, poll, setRules, subjects, tryCall, type Client, type Rule } from "../helpers/v1.js";

// polling tests wait on the sidecar's 5 s implicit sync / reconcile interval; the default 30 s per-test budget is too tight on a busy host
vi.setConfig({ testTimeout: 120_000, hookTimeout: 120_000 });

const ok = !!makeSelfSignedCert() && haveSidecar;
if (!makeSelfSignedCert()) console.warn("SKIPPED v1 policy: openssl not available");

// First command of the write path on Node's own IMAP connection: SELECT of the source folder, or (when the pooled
// connection already has it selected) the existence check `UID FETCH <uid> UID`. The sidecar never fetches with only UID.
const writeConnPrelude = (line: string) => /^(SELECT |UID FETCH [\d,:*]+ \(?UID\)?$)/i.test(line);

const READ_OPS = ["search", "read_headers", "read_body"] as const;
const allow = (folder: string, ...ops: string[]): Rule[] => ops.map((o) => [folder, o, "allow"] as Rule);
const deny = (folder: string, ...ops: string[]): Rule[] => ops.map((o) => [folder, o, "deny"] as Rule);

describe.skipIf(!ok)("v1 policy end to end", () => {
  let s: Stack;
  let box: string;
  const clients: Client[] = [];

  beforeAll(async () => {
    s = await createV1Stack();
    box = s.mailbox[ALICE];
    for (const f of ["Work", "Work/Clients", "Work/Clients/Acme"]) s.fake.addFolder(ALICE, f);
    s.fake.addMessage(ALICE, "INBOX", msg("inbox visible zebra", "inbox body zebra"));
    s.fake.addMessage(ALICE, "Archive", msg("archive SECRETSUBJECT zebra", "archive body BODYSECRET zebra"));
    s.fake.addMessage(ALICE, "Sent", msg("sent headers zebra", "sent body zebra"));
    s.fake.addMessage(ALICE, "Work/Clients", msg("clients zebra", "clients body"));
    s.fake.addMessage(ALICE, "Work/Clients/Acme", msg("acme zebra", "acme body"));
  });
  afterAll(async () => {
    for (const c of clients) await c.mcp.close();
    await s?.teardown();
  });
  // OAuth registration is rate limited, so one long-lived client is re-ruled per test (policy is read live on every call);
  // only the tests that disable a client create their own.
  let shared: Client | undefined;
  const mk = async (rules: Rule[], name?: string) => {
    if (!shared) {
      shared = await newClient(s, box, rules, name);
      clients.push(shared);
    } else setRules(s, shared.clientId, box, rules);
    return shared;
  };
  const fresh = async (rules: Rule[], name?: string) => {
    const c = await newClient(s, box, rules, name);
    clients.push(c);
    return c;
  };
  /** Finds a message by subject; new mail can take up to the sidecar's 5 s implicit sync to show up. */
  const find = async (c: Client, folder: string, subject: string) => {
    const r = await poll(async () => {
      const x = await c.mcp.call("search_messages", { mailbox: box, folder, subject });
      expect(x.isError, x.text).toBe(false);
      return x.data.messages.length ? x : null;
    }, 20_000);
    return r.data.messages[0];
  };

  describe("denied search-result leakage", () => {
    const leakRules = [...allow("*", ...READ_OPS), ...deny("Archive", "search")];

    it("a folder-less search never returns, counts or contacts a folder where search is denied", async () => {
      const c = await mk(leakRules, "leak");
      s.fake.clearLog();
      const r = await c.mcp.call("search_messages", { mailbox: box, text: "zebra" });
      expect(r.isError, r.text).toBe(false);
      const folders = new Set(r.data.messages.map(folderOf));
      expect(folders.has("Archive")).toBe(false);
      expect(folders.has("INBOX")).toBe(true);
      expect(r.text).not.toMatch(/SECRETSUBJECT|BODYSECRET|archive/i);
      // a reported total (if the tool has one) must not include the denied folder's hit either
      if (r.data.total !== undefined) expect(r.data.total).toBe(r.data.messages.length);
      // and nothing touched Archive on the IMAP side in this window
      const touched = s.fake.commands.filter((x) => x.user === ALICE && (x.selected === "Archive" || /Archive/.test(x.line)));
      expect(touched, JSON.stringify(touched)).toEqual([]);
    });

    it("body text search cannot reveal denied-folder content (counts, snippets, errors)", async () => {
      const c = await mk(leakRules);
      s.fake.clearLog();
      const r = await c.mcp.call("search_messages", { mailbox: box, text: "BODYSECRET" });
      expect(r.isError, r.text).toBe(false);
      expect(r.data.messages).toEqual([]);
      if (r.data.total !== undefined) expect(r.data.total).toBe(0);
      expect(s.fake.commands.filter((x) => x.user === ALICE && (x.selected === "Archive" || /Archive/.test(x.line)))).toEqual([]);
    });

    // requestId is unique per call by design (v2); every other byte of the payload must be identical.
    const norm = (t: string, f: string) => t.replace(/"requestId":"[^"]*"/, '"requestId":"<R>"').split(f).join("<F>");
    it("an explicit search of a denied folder gives the same answer as a folder that does not exist", async () => {
      const c = await mk(leakRules);
      const denied = await c.mcp.call("search_messages", { mailbox: box, folder: "Archive", subject: "zebra" });
      const missing = await c.mcp.call("search_messages", { mailbox: box, folder: "NoSuchFolderQ", subject: "zebra" });
      expect(denied.isError).toBe(true);
      expect(missing.isError).toBe(true);
      // docs/DESIGN_V1.md: "error messages never reveal whether a denied folder exists"
      expect(denied.data.code).toBe(missing.data.code);
      expect(norm(denied.text, "Archive")).toBe(norm(missing.text, "NoSuchFolderQ"));
    });

    it("with a default-deny client, an existing but unlisted folder and a missing folder are indistinguishable", async () => {
      const c = await mk(allow("INBOX", ...READ_OPS));
      const denied = await c.mcp.call("search_messages", { mailbox: box, folder: "Archive", subject: "zebra" });
      const missing = await c.mcp.call("search_messages", { mailbox: box, folder: "NoSuchFolderQ", subject: "zebra" });
      expect(denied.isError && missing.isError).toBe(true);
      expect(denied.data.code).toBe(missing.data.code);
      expect(norm(denied.text, "Archive")).toBe(norm(missing.text, "NoSuchFolderQ"));
    });

    it("list_folders hides folders with no read-type allow", async () => {
      const c2 = await mk([...allow("INBOX", ...READ_OPS)], "folders");
      const r = await c2.mcp.call("list_folders", { mailbox: box });
      expect(r.isError, r.text).toBe(false);
      expect(r.data.folders.map((f: any) => f.path)).toEqual(["INBOX"]);
    });

    it("search allowed but read_headers denied: no results from that folder, folder-less or explicit", async () => {
      const c2 = await mk([...allow("*", ...READ_OPS), ...deny("Sent", "read_headers")], "nohdr");
      const all = await c2.mcp.call("search_messages", { mailbox: box, text: "zebra" });
      expect(all.isError, all.text).toBe(false);
      expect(new Set(all.data.messages.map(folderOf)).has("Sent")).toBe(false);
      expect(all.text).not.toContain("sent headers");
      const one = await c2.mcp.call("search_messages", { mailbox: box, folder: "Sent", subject: "zebra" });
      expect(one.text).not.toContain("sent headers");
      expect(one.isError || one.data.messages.length === 0).toBe(true);
    });

    it("read_message returns headers but no body when read_body is denied", async () => {
      const c2 = await mk([...allow("*", "search", "read_headers"), ...deny("*", "read_body")], "nobody");
      const m = await find(c2, "Archive", "SECRETSUBJECT");
      const r = await c2.mcp.call("read_message", { ref: m.ref });
      expect(r.text).not.toContain("BODYSECRET");
      if (!r.isError) {
        expect(r.data.subject).toContain("SECRETSUBJECT");
        expect(r.data.body ?? "").toBe("");
      }
      const bodyOnly = await c2.mcp.call("read_message", { ref: m.ref, include: ["body"] });
      expect(bodyOnly.text).not.toContain("BODYSECRET");
    });
  });

  describe("cached data is not served after a policy change", () => {
    it("tightening rules takes effect on the very next call even though the sidecar cache is warm", async () => {
      const c = await mk(allowAll(), "cache");
      const m = await find(c, "Archive", "SECRETSUBJECT");
      expect((await c.mcp.call("read_message", { ref: m.ref })).data.body).toContain("BODYSECRET");
      expect((await c.mcp.call("search_messages", { mailbox: box, text: "zebra" })).data.messages.length).toBeGreaterThanOrEqual(4);

      setRules(s, c.clientId, box, [...allowAll(), ...deny("Archive", "search", "read_headers", "read_body")]);

      const read = await c.mcp.call("read_message", { ref: m.ref });
      expect(read.isError).toBe(true);
      expect(read.text).not.toMatch(/SECRETSUBJECT|BODYSECRET/);
      const search = await c.mcp.call("search_messages", { mailbox: box, folder: "Archive", subject: "SECRETSUBJECT" });
      expect(search.isError).toBe(true);
      const all = await c.mcp.call("search_messages", { mailbox: box, text: "zebra" });
      expect(all.text).not.toMatch(/SECRETSUBJECT|BODYSECRET/);
      expect(all.data.messages.map(folderOf)).not.toContain("Archive");

      // widening again works (the cache was not poisoned or dropped incorrectly)
      setRules(s, c.clientId, box, allowAll());
      expect((await c.mcp.call("read_message", { ref: m.ref })).data.body).toContain("BODYSECRET");
    });

    it("dropping only read_body hides a previously readable body", async () => {
      const c = await mk(allowAll(), "cache-body");
      const m = await find(c, "INBOX", "inbox visible");
      expect((await c.mcp.call("read_message", { ref: m.ref })).data.body).toContain("inbox body zebra");
      setRules(s, c.clientId, box, [...allow("*", "search", "read_headers")]);
      const r = await c.mcp.call("read_message", { ref: m.ref });
      expect(r.text).not.toContain("inbox body zebra");
    });
  });

  describe("cross-folder move needs both folders", () => {
    const mkMsg = (folder: string, subject: string) => s.fake.addMessage(ALICE, folder, msg(subject));
    const readRules = allow("*", ...READ_OPS);

    it("allowed on source only: refused, nothing moved on the server", async () => {
      mkMsg("INBOX", "move-src-only");
      const c = await mk([...readRules, ...allow("INBOX", "move")], "mv1");
      const m = await find(c, "INBOX", "move-src-only");
      s.fake.clearLog();
      const r = await c.mcp.call("move_message", { ref: m.ref, destination: "Archive" });
      expect(r.isError).toBe(true);
      expect(r.data.code).toBe("FORBIDDEN");
      expect(s.fake.countCommands(ALICE, /\b(MOVE|COPY)\b/)).toBe(0);
      expect(s.fake.folder(ALICE, "Archive").messages.some((x) => x.raw.toString().includes("move-src-only"))).toBe(false);
    });

    it("allowed on destination only: refused", async () => {
      mkMsg("INBOX", "move-dst-only");
      const c = await mk([...readRules, ...allow("Archive", "move")], "mv2");
      const m = await find(c, "INBOX", "move-dst-only");
      s.fake.clearLog();
      const r = await c.mcp.call("move_message", { ref: m.ref, destination: "Archive" });
      expect(r.isError).toBe(true);
      expect(r.data.code).toBe("FORBIDDEN");
      expect(s.fake.countCommands(ALICE, /\b(MOVE|COPY)\b/)).toBe(0);
    });

    it("allowed on both: moves, and the original is gone", async () => {
      const src = mkMsg("INBOX", "move-both");
      const c = await mk([...readRules, ...allow("INBOX", "move"), ...allow("Archive", "move")], "mv3");
      const m = await find(c, "INBOX", "move-both");
      const r = await c.mcp.call("move_message", { ref: m.ref, destination: "Archive" });
      expect(r.isError, r.text).toBe(false);
      expect(r.data.moved).toBe(true);
      expect(s.fake.folder(ALICE, "INBOX").messages.some((x) => x.uid === src.uid)).toBe(false);
      expect(s.fake.folder(ALICE, "Archive").messages.some((x) => x.raw.toString().includes("move-both"))).toBe(true);
    });

    it("explicit deny on the destination beats a wildcard allow", async () => {
      mkMsg("INBOX", "move-denied-dst");
      const c = await mk([...readRules, ...allow("*", "move"), ...deny("Archive", "move")], "mv4");
      const m = await find(c, "INBOX", "move-denied-dst");
      const r = await c.mcp.call("move_message", { ref: m.ref, destination: "Archive" });
      expect(r.isError).toBe(true);
      expect(r.data.code).toBe("FORBIDDEN");
      expect(s.fake.folder(ALICE, "INBOX").messages.some((x) => x.raw.toString().includes("move-denied-dst"))).toBe(true);
      // the same client may still move into a folder that is not denied
      const ok2 = await c.mcp.call("move_message", { ref: m.ref, destination: "Sent" });
      expect(ok2.isError, ok2.text).toBe(false);
    });

    it("flag permission does not imply move permission", async () => {
      mkMsg("INBOX", "flag-not-move");
      const c = await mk([...readRules, ...allow("*", "flag")], "mv5");
      const m = await find(c, "INBOX", "flag-not-move");
      const r = await c.mcp.call("move_message", { ref: m.ref, destination: "Archive" });
      expect(r.data.code).toBe("FORBIDDEN");
      const f = await c.mcp.call("set_flags", { refs: [m.ref], add: ["\\Flagged"] });
      expect(f.isError, f.text).toBe(false);
    });
  });

  describe("deny precedence and selectors", () => {
    it("deny wins over allow regardless of specificity or insertion order", async () => {
      // exact allow + prefix deny
      const a = await mk([...allow("Work/Clients", ...READ_OPS), ...deny("Work/*", "search")], "dp1");
      const r1 = await a.mcp.call("search_messages", { mailbox: box, folder: "Work/Clients", subject: "clients" });
      expect(r1.isError).toBe(true);
      // wildcard allow + exact deny
      const b = await mk([...allow("*", ...READ_OPS), ...deny("INBOX", "search")], "dp2");
      expect((await b.mcp.call("search_messages", { mailbox: box, folder: "INBOX", subject: "visible" })).isError).toBe(true);
      expect((await b.mcp.call("search_messages", { mailbox: box, folder: "Sent", subject: "sent headers" })).isError).toBe(false);
      // deny in one operation leaves other operations alone
      const m = await find(b, "Sent", "sent headers");
      expect((await b.mcp.call("read_message", { ref: m.ref })).isError).toBe(false);
    });

    it("a prefix selector covers sub-folders and nothing outside the prefix", async () => {
      const c = await mk([...allow("Work/*", ...READ_OPS)], "glob");
      expect((await c.mcp.call("search_messages", { mailbox: box, folder: "Work/Clients/Acme", subject: "acme" })).isError).toBe(false);
      expect((await c.mcp.call("search_messages", { mailbox: box, folder: "Work/Clients", subject: "clients" })).isError).toBe(false);
      expect((await c.mcp.call("search_messages", { mailbox: box, folder: "INBOX", subject: "visible" })).isError).toBe(true);
      const f = await c.mcp.call("list_folders", { mailbox: box });
      expect(f.data.folders.map((x: any) => x.path).every((p: string) => p.startsWith("Work/"))).toBe(true);
    });

    it("selectors are case-sensitive and invalid selectors fail closed", async () => {
      const lower = await mk([...allow("inbox", ...READ_OPS)], "case");
      expect((await lower.mcp.call("search_messages", { mailbox: box, folder: "INBOX", subject: "visible" })).isError).toBe(true);
      for (const bad of ["IN*", "?NBOX", "[A-Z]NBOX", "**", "", " INBOX", "INBOX/"]) {
        const c = await mk([...allow(bad, ...READ_OPS)], "bad");
        const r = await c.mcp.call("search_messages", { mailbox: box, folder: "INBOX", subject: "visible" });
        expect(r.isError, `selector ${JSON.stringify(bad)} must not match INBOX`).toBe(true);
      }
    });

    it("no rules at all is default deny", async () => {
      const c = await mk([], "empty");
      const r = await c.mcp.call("search_messages", { mailbox: box, folder: "INBOX", subject: "visible" });
      expect(r.isError).toBe(true);
    });
  });

  describe("revocation", () => {
    it("removing a rule blocks the next call, well within 5 s, with an already issued token", async () => {
      const c = await mk(allowAll(), "rev1");
      expect((await c.mcp.call("search_messages", { mailbox: box, folder: "INBOX", subject: "visible" })).isError).toBe(false);
      const t0 = Date.now();
      setRules(s, c.clientId, box, []);
      const r = await c.mcp.call("search_messages", { mailbox: box, folder: "INBOX", subject: "visible" });
      const dt = Date.now() - t0;
      expect(r.isError).toBe(true);
      expect(dt).toBeLessThan(5000);
    });

    it("disabling the client ('revoke client') blocks all further calls within 5 s", async () => {
      const c = await fresh(allowAll(), "rev2");
      expect((await c.mcp.call("list_mailboxes")).isError).toBe(false);
      const t0 = Date.now();
      const r = await s.admin.postWithCsrf(`/clients/${c.clientId}`, `/clients/${c.clientId}/disable`, {});
      expect(r.status).toBe(302);
      const after = await tryCall(c.mcp, "search_messages", { mailbox: box, folder: "INBOX", subject: "visible" });
      expect(Date.now() - t0).toBeLessThan(5000);
      expect(after.isError).toBe(true);
      expect(after.text).not.toContain("inbox visible");
      // raw HTTP confirms it is an authentication failure, not a tool error
      const raw = await fetch(`${s.base}/mcp`, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${c.token}` },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }),
      });
      expect(raw.status).toBe(401);
    });

    it("a pending move is re-authorized right before the write: revoked in flight => nothing is moved", async () => {
      const victim = s.fake.addMessage(ALICE, "INBOX", msg("pending-move-victim"));
      const c = await mk([...allow("*", ...READ_OPS), ...allow("*", "move")], "pend1");
      const m = await find(c, "INBOX", "pending-move-victim");
      s.fake.clearLog();
      const hold = s.fake.holdNext(writeConnPrelude);
      const call = c.mcp.call("move_message", { ref: m.ref, destination: "Archive" });
      await Promise.race([hold.arrived, sleep(10_000).then(() => { throw new Error("move never reached the write connection"); })]);
      setRules(s, c.clientId, box, allow("*", ...READ_OPS)); // move revoked while the call is in flight
      hold.release();
      const r = await call;
      expect(r.isError).toBe(true);
      expect(r.data.code).toBe("FORBIDDEN");
      expect(s.fake.countCommands(ALICE, /\b(MOVE|COPY)\b/)).toBe(0);
      expect(s.fake.folder(ALICE, "INBOX").messages.some((x) => x.uid === victim.uid)).toBe(true);
    });

    it("a pending set_flags is re-authorized right before the write", async () => {
      const victim = s.fake.addMessage(ALICE, "INBOX", msg("pending-flag-victim"));
      const c = await mk([...allow("*", ...READ_OPS), ...allow("*", "flag")], "pend2");
      const m = await find(c, "INBOX", "pending-flag-victim");
      s.fake.clearLog();
      const hold = s.fake.holdNext(writeConnPrelude);
      const call = c.mcp.call("set_flags", { refs: [m.ref], add: ["\\Flagged"] });
      await Promise.race([hold.arrived, sleep(10_000).then(() => { throw new Error("set_flags never reached the write connection"); })]);
      setRules(s, c.clientId, box, allow("*", ...READ_OPS));
      hold.release();
      const r = await call;
      // either the whole call is refused or the single outcome is an error; never a successful write
      const succeeded = r.isError ? 0 : r.data.succeeded;
      expect(succeeded).toBe(0);
      expect(s.fake.countCommands(ALICE, /\bSTORE\b/)).toBe(0);
      expect(s.fake.folder(ALICE, "INBOX").messages.find((x) => x.uid === victim.uid)!.flags.has("\\Flagged")).toBe(false);
    });

    it("a revoked client cannot use a cached reference to read what it read before", async () => {
      const c = await fresh(allowAll(), "rev3");
      const m = await find(c, "INBOX", "inbox visible");
      expect((await c.mcp.call("read_message", { ref: m.ref })).isError).toBe(false);
      await s.admin.postWithCsrf(`/clients/${c.clientId}`, `/clients/${c.clientId}/disable`, {});
      const t = await tryCall(c.mcp, "read_message", { ref: m.ref });
      expect(t.isError).toBe(true);
      await poll(async () => (await tryCall(c.mcp, "list_mailboxes")).isError, 5000);
    });
  });
});
