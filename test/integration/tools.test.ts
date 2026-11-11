/**
 * Version 0 acceptance criterion 5: core tools against a real IMAP-over-TLS fixture.
 * search/read leave unread state alone; create_draft appends (never sends); move needs organize on the
 * mailbox and uses UID-scoped removal; set_flags set/clear.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { makeSelfSignedCert } from "../helpers/certs.js";
import { createStack, addMailboxRaw, obtainToken, Mcp, msg, refOf, ACCOUNTS, type Stack } from "../helpers/stack.js";

const haveOpenssl = !!makeSelfSignedCert();
if (!haveOpenssl) console.warn("SKIPPED tools: openssl not available to create the fixture TLS certificate");

const ALICE = "alice@example.test";

describe.skipIf(!haveOpenssl)("core tools", () => {
  let s: Stack;
  let box: string;
  let mcp: Mcp;
  beforeAll(async () => {
    s = await createStack();
    box = s.mailbox[ALICE];
    const { tokens } = await obtainToken(s, [[box, "read"], [box, "draft"], [box, "organize"]]);
    mcp = await new Mcp(s.base, tokens.access_token).connect();
  });
  afterAll(async () => { await mcp?.close(); await s?.teardown(); });

  const log = () => s.fake.commandsFor(ALICE);

  it("exposes exactly the v0 tool set (and no send/delete tool)", async () => {
    expect((await mcp.tools()).sort()).toEqual(["create_draft", "list_folders", "list_mailboxes", "move_message", "read_message", "search_messages", "set_flags"]);
  });

  it("list_mailboxes returns ids and labels only, no connection details", async () => {
    const r = await mcp.call("list_mailboxes");
    expect(r.data.mailboxes).toHaveLength(1);
    expect(Object.keys(r.data.mailboxes[0]).sort()).toEqual(["capabilities", "id", "label"]);
    expect(r.text).not.toMatch(/localhost|example\.test|imap_|password/i);
  });

  it("list_folders shows the server's folders", async () => {
    const r = await mcp.call("list_folders", { mailbox: box });
    expect(r.isError).toBe(false);
    expect(r.data.folders.map((f: any) => f.path).sort()).toEqual(["Archive", "Drafts", "INBOX", "Sent"]);
  });

  describe("search + read", () => {
    it("finds and reads messages without changing unread state", async () => {
      s.fake.addMessage(ALICE, "INBOX", msg("Quarterly report", "Numbers inside. needle-42", "Boss <boss@corp.example>"));
      s.fake.addMessage(ALICE, "INBOX", msg("Lunch?", "Pizza at noon", "Pal <pal@friends.example>"));
      s.fake.addMessage(ALICE, "INBOX", msg("Seen already", "old news", "Pal <pal@friends.example>"), ["\\Seen"]);
      s.fake.clearLog();

      const bySubject = await mcp.call("search_messages", { mailbox: box, folder: "INBOX", subject: "Quarterly" });
      expect(bySubject.data.messages.map((m: any) => m.subject)).toEqual(["Quarterly report"]);
      const byFrom = await mcp.call("search_messages", { mailbox: box, folder: "INBOX", from: "friends.example" });
      expect(byFrom.data.total).toBe(2);
      const unseen = await mcp.call("search_messages", { mailbox: box, folder: "INBOX", unseen: true });
      expect(unseen.data.messages.map((m: any) => m.subject).sort()).toEqual(["Lunch?", "Quarterly report"]);

      const ref = bySubject.data.messages[0].ref;
      expect(ref).toMatchObject({ mailbox: box, folder: "INBOX", uidValidity: s.fake.folder(ALICE, "INBOX").uidValidity });
      const read = await mcp.call("read_message", { ref });
      expect(read.isError).toBe(false);
      expect(read.data.subject).toBe("Quarterly report");
      expect(read.data.body).toContain("needle-42");
      expect(read.data.from[0]).toMatchObject({ name: "Boss", address: "boss@corp.example" });
      expect(read.data.truncated).toBe(false);

      // read state untouched, on the server and on the wire
      for (const m of s.fake.folder(ALICE, "INBOX").messages.slice(0, 2)) expect(m.flags.has("\\Seen")).toBe(false);
      const again = await mcp.call("search_messages", { mailbox: box, folder: "INBOX", unseen: true });
      expect(again.data.total).toBe(2);
      const wire = log().join("\n");
      expect(wire).not.toMatch(/BODY\[/); // only BODY.PEEK[...]
      expect(wire).not.toMatch(/RFC822(?!\.SIZE|\.HEADER)/);
      expect(wire).not.toMatch(/\bSTORE\b/);
      expect(wire).toMatch(/BODY\.PEEK\[/);
    });

    it("pages with a cap of 50 and a cursor", async () => {
      for (let i = 0; i < 55; i++) s.fake.addMessage(ALICE, "Archive", msg(`bulk ${i}`));
      const p1 = await mcp.call("search_messages", { mailbox: box, folder: "Archive", limit: 50 });
      expect(p1.data.messages).toHaveLength(50);
      expect(p1.data.total).toBe(55);
      expect(p1.data.nextCursor).toBeTruthy();
      const p2 = await mcp.call("search_messages", { mailbox: box, folder: "Archive", cursor: p1.data.nextCursor });
      expect(p2.data.messages).toHaveLength(5);
      expect(p2.data.nextCursor).toBeNull();
      const over = await mcp.call("search_messages", { mailbox: box, folder: "Archive", limit: 51 }).catch((e) => ({ isError: true, text: String(e) }));
      expect(over.isError).toBe(true);
      s.fake.folder(ALICE, "Archive").messages.length = 0;
    });

    it("caps the body at 200 KB and flags truncation", async () => {
      s.fake.addMessage(ALICE, "Sent", msg("huge", "x".repeat(300 * 1024)));
      const found = await mcp.call("search_messages", { mailbox: box, folder: "Sent", subject: "huge" });
      const read = await mcp.call("read_message", { ref: found.data.messages[0].ref });
      expect(read.data.truncated).toBe(true);
      expect(read.data.body.length).toBeLessThanOrEqual(200 * 1024);
      s.fake.folder(ALICE, "Sent").messages.length = 0;
    });

    it("unknown folder and unknown uid give NOT_FOUND, not a crash", async () => {
      const nf = await mcp.call("search_messages", { mailbox: box, folder: "NoSuchFolder" });
      expect(nf.isError).toBe(true);
      const missing = await mcp.call("read_message", { ref: refOf(s, ALICE, "INBOX", 9999) });
      expect(missing.isError).toBe(true);
      expect(missing.data.code).toBe("NOT_FOUND");
    });

    it("a stale UIDVALIDITY yields STALE_REFERENCE", async () => {
      const m = s.fake.addMessage(ALICE, "Sent", msg("stale probe"));
      const ref = refOf(s, ALICE, "Sent", m.uid);
      s.fake.bumpUidValidity(ALICE, "Sent");
      s.fake.dropConnections(); // a real folder re-creation is only visible after (re)select
      const r = await mcp.call("read_message", { ref });
      expect(r.isError).toBe(true);
      expect(r.data.code).toBe("STALE_REFERENCE");
      const mv = await mcp.call("move_message", { ref, destination: "Archive" });
      expect(mv.data.code).toBe("STALE_REFERENCE");
      s.fake.folder(ALICE, "Sent").messages.length = 0;
    });
  });

  describe("create_draft", () => {
    it("appends to the configured Drafts folder, flagged \\Draft, and does not send", async () => {
      s.fake.clearLog();
      const before = { inbox: s.fake.folder(ALICE, "INBOX").messages.length, sent: s.fake.folder(ALICE, "Sent").messages.length };
      const r = await mcp.call("create_draft", { mailbox: box, to: ["friend@example.org"], subject: "Draft subject ü", body: "Draft body line" });
      expect(r.isError).toBe(false);
      expect(r.data.ref).toMatchObject({ mailbox: box, folder: "Drafts" });

      const drafts = s.fake.folder(ALICE, "Drafts").messages;
      expect(drafts).toHaveLength(1);
      expect(drafts[0].flags.has("\\Draft")).toBe(true);
      const raw = drafts[0].raw.toString();
      expect(raw).toMatch(/^To: friend@example\.org/m);
      expect(raw).toContain("Draft body line");
      // nothing else changed: no send, no copy to Sent, INBOX untouched
      expect(s.fake.folder(ALICE, "Sent").messages.length).toBe(before.sent);
      expect(s.fake.folder(ALICE, "INBOX").messages.length).toBe(before.inbox);
      const appends = log().filter((l) => /^APPEND/.test(l));
      expect(appends).toHaveLength(1);
      expect(appends[0]).toMatch(/^APPEND "?Drafts"?/);
      // the returned ref points at the draft
      const back = await mcp.call("read_message", { ref: r.data.ref });
      expect(back.data.subject).toBe("Draft subject ü");
    });

    it("the target folder cannot be chosen by the caller", async () => {
      const r = await mcp.call("create_draft", { mailbox: box, subject: "x", body: "y", folder: "INBOX", drafts_folder: "INBOX" }).catch((e) => ({ isError: true, data: String(e) }));
      // either the extra arg is ignored (draft lands in Drafts) or rejected; never in INBOX
      expect(s.fake.folder(ALICE, "INBOX").messages.some((m) => m.flags.has("\\Draft"))).toBe(false);
      void r;
    });

    it("refuses when the mailbox has no Drafts folder selected", async () => {
      const id = await addMailboxRaw(s, { label: "NoDrafts", host: "localhost", port: s.fake.port, user: ALICE, pass: s.imapPasswords[ALICE] });
      const { tokens } = await obtainToken(s, [[id, "draft"]]);
      const c = await new Mcp(s.base, tokens.access_token).connect();
      const d = await c.call("create_draft", { mailbox: id, subject: "s", body: "b" });
      expect(d.isError).toBe(true);
      expect(d.data.code).toBe("INVALID_INPUT");
      await c.close();
    });
  });

  describe("move_message", () => {
    it("moves one message INBOX -> Archive using UID MOVE and returns identifiers only", async () => {
      const m = s.fake.addMessage(ALICE, "INBOX", msg("to archive", "secret body text"));
      const keep = s.fake.addMessage(ALICE, "INBOX", msg("stays"));
      s.fake.clearLog();
      const r = await mcp.call("move_message", { ref: refOf(s, ALICE, "INBOX", m.uid), destination: "Archive" });
      expect(r.isError).toBe(false);
      expect(r.data.moved).toBe(true);
      expect(r.data.newRef).toMatchObject({ mailbox: box, folder: "Archive" });
      expect(r.text).not.toContain("secret body text"); // no content returned
      expect(s.fake.folder(ALICE, "Archive").messages.some((x) => x.raw.toString().includes("secret body text"))).toBe(true);
      expect(s.fake.folder(ALICE, "INBOX").messages.some((x) => x.uid === m.uid)).toBe(false);
      expect(s.fake.folder(ALICE, "INBOX").messages.some((x) => x.uid === keep.uid)).toBe(true);
      expect(log().some((l) => /^UID MOVE /.test(l))).toBe(true);
      expect(log().some((l) => /^EXPUNGE\b/.test(l))).toBe(false);
    });

    it("unknown destination: NOT_FOUND and the message stays", async () => {
      const m = s.fake.addMessage(ALICE, "INBOX", msg("stay put"));
      const r = await mcp.call("move_message", { ref: refOf(s, ALICE, "INBOX", m.uid), destination: "Nope/Nowhere" });
      expect(r.isError).toBe(true);
      expect(r.data.code).toBe("NOT_FOUND");
      expect(s.fake.folder(ALICE, "INBOX").messages.some((x) => x.uid === m.uid)).toBe(true);
    });

    it("destination equal to source is rejected", async () => {
      const m = s.fake.addMessage(ALICE, "INBOX", msg("same"));
      const r = await mcp.call("move_message", { ref: refOf(s, ALICE, "INBOX", m.uid), destination: "INBOX" });
      expect(r.data.code).toBe("INVALID_INPUT");
    });

    it("without MOVE capability falls back to COPY + UID-scoped removal and never plain EXPUNGE", async () => {
      const s2 = await createStack({ move: false, accounts: [ALICE] });
      try {
        const b = s2.mailbox[ALICE];
        const mover = s2.fake.addMessage(ALICE, "INBOX", msg("mover"));
        // a bystander already flagged \Deleted by the user: a plain EXPUNGE would destroy it
        const bystander = s2.fake.addMessage(ALICE, "INBOX", msg("bystander marked deleted by user"), ["\\Deleted"]);
        const { tokens } = await obtainToken(s2, [[b, "organize"]]);
        const c = await new Mcp(s2.base, tokens.access_token).connect();
        s2.fake.clearLog();
        const r = await c.call("move_message", { ref: refOf(s2, ALICE, "INBOX", mover.uid), destination: "Archive" });
        expect(r.isError, r.text).toBe(false);
        const wire = s2.fake.commandsFor(ALICE);
        expect(wire.some((l) => /^EXPUNGE\b/.test(l))).toBe(false);
        expect(wire.some((l) => /^UID EXPUNGE /.test(l))).toBe(true);
        expect(s2.fake.folder(ALICE, "INBOX").messages.map((m) => m.uid)).toEqual([bystander.uid]);
        expect(s2.fake.folder(ALICE, "Archive").messages).toHaveLength(1);
        await c.close();
      } finally { await s2.teardown(); }
    });
  });

  describe("set_flags", () => {
    it("sets and clears flags and keywords, per-message outcomes", async () => {
      const a = s.fake.addMessage(ALICE, "INBOX", msg("flag a"));
      const b = s.fake.addMessage(ALICE, "INBOX", msg("flag b"));
      const refs = [refOf(s, ALICE, "INBOX", a.uid), refOf(s, ALICE, "INBOX", b.uid)];

      const set = await mcp.call("set_flags", { refs, add: ["\\Flagged", "\\Seen", "Followup"] });
      expect(set.isError, set.text).toBe(false);
      expect(set.data.succeeded).toBe(2);
      for (const m of [a, b]) for (const f of ["\\Flagged", "\\Seen", "Followup"]) expect(m.flags.has(f)).toBe(true);

      const clear = await mcp.call("set_flags", { refs: [refs[0]], remove: ["\\Flagged", "\\Seen"] });
      expect(clear.data.succeeded).toBe(1);
      expect(a.flags.has("\\Flagged")).toBe(false);
      expect(a.flags.has("\\Seen")).toBe(false);
      expect(a.flags.has("Followup")).toBe(true);
      expect(b.flags.has("\\Flagged")).toBe(true); // untouched sibling

      // messages are never removed by flagging
      expect(s.fake.folder(ALICE, "INBOX").messages.includes(a)).toBe(true);
    });

    it("refuses \\Deleted and \\Recent and malformed flags", async () => {
      const a = s.fake.addMessage(ALICE, "INBOX", msg("flag c"));
      const ref = refOf(s, ALICE, "INBOX", a.uid);
      for (const f of ["\\Deleted", "\\deleted", "\\Recent", "\\Bogus", "bad flag", "x)y"]) {
        const r = await mcp.call("set_flags", { refs: [ref], add: [f] });
        expect(r.isError, f).toBe(true);
        expect(r.data.code, f).toBe("INVALID_INPUT");
      }
      expect(a.flags.has("\\Deleted")).toBe(false);
    });

    it("reports NOT_FOUND per message and caps batches at 25", async () => {
      const a = s.fake.addMessage(ALICE, "INBOX", msg("flag d"));
      const r = await mcp.call("set_flags", { refs: [refOf(s, ALICE, "INBOX", a.uid), refOf(s, ALICE, "INBOX", 31337)], add: ["\\Flagged"] });
      expect(r.data.succeeded).toBe(1);
      expect(r.data.failed).toBe(1);
      expect(r.data.results[1]).toMatchObject({ status: "error", code: "NOT_FOUND" });
      const many = Array.from({ length: 26 }, (_, i) => refOf(s, ALICE, "INBOX", a.uid + i));
      const big = await mcp.call("set_flags", { refs: many, add: ["\\Flagged"] }).catch((e) => ({ isError: true, data: { code: "INVALID_INPUT" }, text: String(e) }));
      expect(big.isError).toBe(true);
    });
  });
});

// keep ACCOUNTS import used for readers who extend this file
void ACCOUNTS;
