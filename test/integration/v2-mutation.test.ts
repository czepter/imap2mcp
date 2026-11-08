/**
 * Version 2 acceptance criterion 3 (mutation safety): disconnects during draft append, move and flag operations never
 * replay an ambiguous write. Asserted on the fake server's command log: exactly ONE APPEND / MOVE / STORE reaches the
 * server in every scenario, and the tool answers either "reconciled" (server state verified) or UNKNOWN_OUTCOME.
 * Read-only retries are bounded (<= 2 retries) and everything finishes inside the 30 s budget.
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from "vitest";
import { msg, sleep, type Stack } from "../helpers/stack.js";
import { allowAll, newClient, setRules, type Client } from "../helpers/v1.js";
import { ALICE, canRunV2, createV2Stack, errorLeakNeedles, expectNoLeak, expectStructuredError, WRITE_RE } from "../helpers/v2.js";

vi.setConfig({ testTimeout: 120_000, hookTimeout: 120_000 });

const BUDGET_MS = 33_000;

describe.skipIf(!canRunV2)("v2 mutation safety (criterion 3)", () => {
  let s: Stack;
  let box: string;
  let c: Client;
  let needles: string[];

  const writes = (re: RegExp) => s.fake.commands.filter((x) => re.test(x.line)).length;
  const allWrites = () => s.fake.commands.filter((x) => WRITE_RE.test(x.line)).map((x) => x.line.split(" ").slice(0, 2).join(" "));
  const drafts = () => s.fake.folder(ALICE, "Drafts").messages;
  const header = (raw: Buffer, name: string) => new RegExp(`^${name}: (.*)$`, "im").exec(raw.toString("utf8"))?.[1]?.trim();
  /** a fresh message in INBOX and its ref */
  async function seed(subject: string) {
    const m = s.fake.addMessage(ALICE, "INBOX", msg(subject));
    const r = await c.mcp.call("search_messages", { mailbox: box, folder: "INBOX", subject });
    // the sidecar may need a sync to see it; fall back to constructing the ref (read path is not under test here)
    const ref = r.data?.messages?.find((x: any) => x.ref.uid === m.uid)?.ref ?? { mailbox: box, folder: "INBOX", uidValidity: s.fake.folder(ALICE, "INBOX").uidValidity, uid: m.uid };
    return { m, ref };
  }
  const draft = (subject: string) => c.mcp.call("create_draft", { mailbox: box, subject, body: "draft body " + subject, to: ["to@example.org"] });

  beforeAll(async () => {
    s = await createV2Stack();
    box = s.mailbox[ALICE];
    c = await newClient(s, box, allowAll(), "v2-mutation");
    needles = errorLeakNeedles(s, [c.token]);
    s.fake.addMessage(ALICE, "INBOX", msg("warmup"));
    expect((await c.mcp.call("search_messages", { mailbox: box, folder: "INBOX" })).isError).toBe(false);
  });
  afterAll(async () => {
    await c?.mcp.close();
    await s?.teardown();
  });
  beforeEach(() => {
    s.fake.clearFaults();
    s.fake.clearLog();
    s.fake.refuseConnections = false;
  });

  describe("create_draft (APPEND)", () => {
    it("APPEND applied, connection lost before the reply: verified by Message-ID search => success with reconciled:true; one APPEND", async () => {
      const n0 = drafts().length;
      const h = s.fake.inject(/^APPEND /i, { kind: "drop-after-apply" });
      const t0 = Date.now();
      const r = await draft("append-applied");
      expect(Date.now() - t0).toBeLessThan(BUDGET_MS);
      expect(h.hits).toBe(1);
      expect(r.isError, r.text).toBe(false);
      expect(r.data.reconciled).toBe(true);
      expect(drafts().length - n0).toBe(1);
      const stored = drafts()[drafts().length - 1];
      expect(r.data.ref).toMatchObject({ mailbox: box, folder: "Drafts", uidValidity: s.fake.folder(ALICE, "Drafts").uidValidity, uid: stored.uid });
      expect(header(stored.raw, "Message-ID")).toBe(r.data.messageId);
      expect(writes(/^APPEND /i), "APPEND count").toBe(1);
      expect(s.fake.commands.some((x) => /SEARCH/i.test(x.line) && /Message-ID/i.test(x.line)), "verification by Message-ID").toBe(true);
      await sleep(1_500);
      expect(writes(/^APPEND /i), "no late replay").toBe(1);
      expect(drafts().length - n0).toBe(1);
    });

    it("APPEND never applied (connection dropped on receipt): UNKNOWN_OUTCOME, not retryable, no re-APPEND; the draft really is absent", async () => {
      const n0 = drafts().length;
      const h = s.fake.inject(/^APPEND /i, { kind: "drop" });
      const r = await draft("append-lost");
      expect(h.hits).toBe(1);
      expectStructuredError(r, "UNKNOWN_OUTCOME", { retryable: false });
      expectNoLeak(r.text, needles, "UNKNOWN_OUTCOME payload");
      expect(writes(/^APPEND /i)).toBe(1);
      await sleep(1_500);
      expect(writes(/^APPEND /i), "no late replay").toBe(1);
      expect(drafts().length).toBe(n0);
    });

    it("APPEND applied but the verification cannot run: UNKNOWN_OUTCOME (the draft DOES exist once), still a single APPEND", async () => {
      const n0 = drafts().length;
      const h = s.fake.inject(/^APPEND /i, { kind: "drop-after-apply" });
      const v = s.fake.inject((l) => h.hits > 0 && /SEARCH.*HEADER|^(SELECT|EXAMINE)/i.test(l), { kind: "drop" }, Infinity);
      const t0 = Date.now();
      const r = await draft("append-unverifiable");
      v.remove();
      expect(Date.now() - t0).toBeLessThan(BUDGET_MS);
      expectStructuredError(r, "UNKNOWN_OUTCOME", { retryable: false });
      expect(writes(/^APPEND /i)).toBe(1);
      expect(drafts().length - n0).toBe(1);
    });

    it("server stops answering the APPEND: returns inside 30 s with UNKNOWN_OUTCOME and never re-sends it", async () => {
      const n0 = drafts().length;
      const h = s.fake.inject(/^APPEND /i, { kind: "hang" });
      const t0 = Date.now();
      const r = await draft("append-hang");
      expect(Date.now() - t0).toBeLessThan(BUDGET_MS);
      expect(h.hits).toBe(1);
      expectStructuredError(r, "UNKNOWN_OUTCOME", { retryable: false });
      expectNoLeak(r.text, needles, "hang UNKNOWN_OUTCOME payload");
      expect(writes(/^APPEND /i)).toBe(1);
      expect(drafts().length).toBe(n0);
      s.fake.dropConnections();
    }, 120_000);

    it("response cut mid-way: success(reconciled) or UNKNOWN_OUTCOME, never a second APPEND or a duplicate draft", async () => {
      const n0 = drafts().length;
      s.fake.inject(/^APPEND /i, { kind: "drop-mid-response", bytes: 12 });
      const r = await draft("append-midway");
      expect(writes(/^APPEND /i)).toBe(1);
      expect(drafts().length - n0).toBe(1); // it was applied
      if (r.isError) expectStructuredError(r, "UNKNOWN_OUTCOME", { retryable: false });
      else expect(r.data.ref.uid).toBe(drafts()[drafts().length - 1].uid);
    });

    it("policy is rechecked before the reconcile read: a revocation mid-failure must not read the Drafts folder", async () => {
      const n0 = drafts().length;
      const h = s.fake.inject(/^APPEND /i, { kind: "drop-after-apply" });
      // slow down the reconnect so there is a window between the failure and the verification
      s.fake.loginDelay = () => (h.hits > 0 ? 2_500 : 0);
      const p = draft("append-revoked");
      const deadline = Date.now() + 10_000;
      while (h.hits === 0 && Date.now() < deadline) await sleep(20);
      expect(h.hits).toBe(1);
      const searchesBefore = writes(/SEARCH.*HEADER/i);
      setRules(s, c.clientId, box, []); // revoke everything
      const r = await p;
      setRules(s, c.clientId, box, allowAll());
      s.fake.loginDelay = 0;
      expect(r.isError, r.text).toBe(true);
      expect(["UNKNOWN_OUTCOME", "FORBIDDEN"]).toContain(r.data.code);
      expect(writes(/^APPEND /i)).toBe(1);
      expect(writes(/SEARCH.*HEADER/i) - searchesBefore, "no reconcile SEARCH after revocation").toBe(0);
      expect(drafts().length - n0).toBe(1);
    });
  });

  describe("move_message", () => {
    it("MOVE applied, connection lost before the reply: verified (destination has it, source gone) => success reconciled; exactly one MOVE, no COPY/STORE/EXPUNGE", async () => {
      const { m, ref } = await seed("move-applied");
      const mid = header(m.raw, "Message-ID")!;
      s.fake.clearLog();
      const h = s.fake.inject(/MOVE /i, { kind: "drop-after-apply" });
      const t0 = Date.now();
      const r = await c.mcp.call("move_message", { ref, destination: "Archive" });
      expect(Date.now() - t0).toBeLessThan(BUDGET_MS);
      expect(h.hits).toBe(1);
      expect(r.isError, r.text).toBe(false);
      expect(r.data.reconciled).toBe(true);
      expect(s.fake.folder(ALICE, "INBOX").messages.some((x) => x.uid === ref.uid)).toBe(false);
      expect(s.fake.folder(ALICE, "Archive").messages.filter((x) => header(x.raw, "Message-ID") === mid)).toHaveLength(1);
      expect(allWrites()).toEqual(["UID MOVE"]);
      await sleep(1_000);
      expect(allWrites()).toEqual(["UID MOVE"]);
    });

    it("MOVE never applied: UNKNOWN_OUTCOME with likelyNotApplied:true, message still in the source, still no replay", async () => {
      const { ref } = await seed("move-lost");
      s.fake.clearLog();
      const h = s.fake.inject(/MOVE /i, { kind: "drop" });
      const r = await c.mcp.call("move_message", { ref, destination: "Archive" });
      expect(h.hits).toBe(1);
      expectStructuredError(r, "UNKNOWN_OUTCOME", { retryable: false });
      expect(r.data.likelyNotApplied).toBe(true);
      expectNoLeak(r.text, needles, "move UNKNOWN_OUTCOME payload");
      expect(s.fake.folder(ALICE, "INBOX").messages.some((x) => x.uid === ref.uid)).toBe(true);
      expect(allWrites()).toEqual(["UID MOVE"]);
      await sleep(1_000);
      expect(allWrites()).toEqual(["UID MOVE"]);
    });

    it("MOVE applied but verification impossible: UNKNOWN_OUTCOME (no likelyNotApplied claim), one MOVE", async () => {
      const { ref } = await seed("move-unverifiable");
      s.fake.clearLog();
      const h = s.fake.inject(/MOVE /i, { kind: "drop-after-apply" });
      const v = s.fake.inject((l) => h.hits > 0 && /^(SELECT|EXAMINE|LOGIN|UID SEARCH|UID FETCH)/i.test(l), { kind: "drop" }, Infinity);
      const r = await c.mcp.call("move_message", { ref, destination: "Archive" });
      v.remove();
      expectStructuredError(r, "UNKNOWN_OUTCOME", { retryable: false });
      expect(r.data.likelyNotApplied).not.toBe(true);
      expect(allWrites()).toEqual(["UID MOVE"]);
    });
  });

  describe("set_flags", () => {
    it("STORE applied, connection lost before the reply: re-FETCH shows the flag => per-message ok, reconciled; one STORE", async () => {
      const { ref } = await seed("flag-applied");
      s.fake.clearLog();
      const h = s.fake.inject(/STORE /i, { kind: "drop-after-apply" });
      const t0 = Date.now();
      const r = await c.mcp.call("set_flags", { refs: [ref], add: ["\\Flagged"] });
      expect(Date.now() - t0).toBeLessThan(BUDGET_MS);
      expect(h.hits).toBe(1);
      expect(r.isError, r.text).toBe(false);
      expect(r.data.results[0].status).toBe("ok");
      expect(r.data.results[0].reconciled === true || r.data.reconciled === true, "marked reconciled").toBe(true);
      expect(s.fake.folder(ALICE, "INBOX").messages.find((x) => x.uid === ref.uid)!.flags.has("\\Flagged")).toBe(true);
      expect(writes(/STORE /i), "STORE count").toBe(1);
      await sleep(1_000);
      expect(writes(/STORE /i)).toBe(1);
    });

    it("STORE never applied: per-message UNKNOWN_OUTCOME (flag verifiably absent), one STORE", async () => {
      const { ref } = await seed("flag-lost");
      s.fake.clearLog();
      const h = s.fake.inject(/STORE /i, { kind: "drop" });
      const r = await c.mcp.call("set_flags", { refs: [ref], add: ["\\Flagged"] });
      expect(h.hits).toBe(1);
      expect(r.data.results[0].status).toBe("error");
      expect(r.data.results[0].code).toBe("UNKNOWN_OUTCOME");
      expect(r.data.failed).toBe(1);
      expectNoLeak(r.text, needles, "set_flags payload");
      expect(s.fake.folder(ALICE, "INBOX").messages.find((x) => x.uid === ref.uid)!.flags.has("\\Flagged")).toBe(false);
      expect(writes(/STORE /i)).toBe(1);
      await sleep(1_000);
      expect(writes(/STORE /i)).toBe(1);
    });

    it("batch of three where the connection drops: each message is reconciled or UNKNOWN_OUTCOME, never re-STOREd", async () => {
      const refs = [];
      for (let i = 0; i < 3; i++) refs.push((await seed(`flag-batch-${i}`)).ref);
      s.fake.clearLog();
      s.fake.inject(/STORE /i, { kind: "drop-after-apply" });
      const r = await c.mcp.call("set_flags", { refs, add: ["\\Flagged"] });
      expect(r.data.results).toHaveLength(3);
      for (const x of r.data.results) expect(x.status === "ok" || x.code === "UNKNOWN_OUTCOME").toBe(true);
      expect(writes(/STORE /i)).toBe(1); // one UID set, one STORE (first and only)
    });
  });

  describe("read-only retries are bounded", () => {
    let ref: any;
    beforeAll(async () => {
      s.fake.clearFaults();
      ref = (await seed("read-target")).ref;
    });

    it("one transient drop is retried transparently (the user sees the body)", async () => {
      s.fake.clearLog();
      const h = s.fake.inject(/FETCH .*BODY/i, { kind: "drop" }, 1);
      const r = await c.mcp.call("read_message", { ref, include: ["body"] });
      expect(r.isError, r.text).toBe(false);
      expect(r.data.body).toContain("Body of read-target");
      expect(h.hits).toBe(1);
    });

    it("a persistent failure is attempted at most 1 + 2 times and then reported as a retryable structured error inside the budget", async () => {
      s.fake.clearLog();
      const h = s.fake.inject(/FETCH .*BODY/i, { kind: "drop" }, Infinity);
      const t0 = Date.now();
      const r = await c.mcp.call("read_message", { ref, include: ["body"] });
      const took = Date.now() - t0;
      h.remove();
      expect(took, `took ${took} ms`).toBeLessThan(BUDGET_MS);
      expectStructuredError(r, ["UPSTREAM_ERROR", "TIMEOUT", "UNAVAILABLE"], { retryable: true });
      expect(h.hits, "body fetch attempts (1 try + at most 2 retries)").toBeGreaterThanOrEqual(2);
      expect(h.hits, "body fetch attempts (1 try + at most 2 retries)").toBeLessThanOrEqual(3);
      await sleep(1_000);
      expect(h.hits, "no background retries after the call returned").toBeLessThanOrEqual(3);
    });
  });
});
