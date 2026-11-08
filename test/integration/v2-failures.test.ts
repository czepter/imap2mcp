/**
 * Version 2 acceptance criterion 1 (failure contracts), end to end over real HTTP/OAuth with the real Go sidecar:
 * injected authentication failures, timeouts, malformed replies, quota errors and unavailable folders each produce the
 * documented structured error {code,message,requestId,retryable,operatorAction?}; nothing about the host, the user name,
 * credentials, raw server text or stack traces reaches the client; the process stays alive; and every operation returns
 * within 30 s.
 */
import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import { msg, sleep, type Stack } from "../helpers/stack.js";
import { allowAll, newClient, poll, type Client, type Rule } from "../helpers/v1.js";
import {
  ALICE, BOB, canRunV2, createV2Stack, errorLeakNeedles, expectNoLeak, expectStructuredError, mailboxStatus, rawToolCall, until, writeCommands,
} from "../helpers/v2.js";

vi.setConfig({ testTimeout: 120_000, hookTimeout: 120_000 });

const SRV = "SRVTEXT-" + Math.random().toString(36).slice(2, 10); // raw server text that must never be relayed
const BUDGET_MS = 33_000; // 30 s upstream budget + HTTP/process overhead

describe.skipIf(!canRunV2)("v2 failure contracts (criterion 1)", () => {
  let s: Stack;
  let box: string;
  let bobBox: string;
  let c: Client;
  let cBob: Client;
  let ref: { mailbox: string; folder: string; uidValidity: number; uid: number };
  let needles: string[];

  const body = (cl: Client = c, r = ref) => cl.mcp.call("read_message", { ref: r, include: ["body"] });
  const alive = () => s.srv.proc.exitCode === null && s.srv.proc.signalCode === null;

  beforeAll(async () => {
    s = await createV2Stack();
    box = s.mailbox[ALICE];
    bobBox = s.mailbox[BOB];
    for (let i = 0; i < 3; i++) s.fake.addMessage(ALICE, "INBOX", msg(`inbox-${i}`, `inbody-${i}`));
    s.fake.addMessage(BOB, "INBOX", msg("bob-1", "bobbody"));
    s.fake.addFolder(ALICE, "Cold"); // never synced before its fault is armed
    s.fake.addMessage(ALICE, "Cold", msg("cold-1"));
    s.fake.addFolder(ALICE, "Secret");
    s.fake.addMessage(ALICE, "Secret", msg("secret-1"));
    const rules: Rule[] = [...allowAll("*"), ["Secret", "search", "deny"], ["Secret", "read_headers", "deny"], ["Secret", "read_body", "deny"]];
    c = await newClient(s, box, rules, "v2-failures");
    cBob = await newClient(s, bobBox, allowAll(), "v2-failures-bob");
    const first = await c.mcp.call("search_messages", { mailbox: box, folder: "INBOX" });
    expect(first.isError, first.text).toBe(false);
    ref = first.data.messages[0].ref;
    expect((await cBob.mcp.call("search_messages", { mailbox: bobBox, folder: "INBOX" })).isError).toBe(false);
    needles = errorLeakNeedles(s, [SRV, c.token, cBob.token]);
  });
  afterAll(async () => {
    await c?.mcp.close();
    await cBob?.mcp.close();
    await s?.teardown();
  });

  it("injected authentication failure: AUTH_FAILED with operatorAction, no leakage, no retry storm, other mailboxes unaffected", async () => {
    s.fake.loginRejectText = `NO [AUTHENTICATIONFAILED] ${SRV} invalid credentials for ${BOB}`;
    s.fake.rejectLogins = (u) => u === BOB;
    s.fake.dropConnections();
    const t0 = Date.now();
    // the sidecar reconnects on demand, is rejected, and must say so structurally
    const r = await until(async () => {
      const x = await body(cBob, { mailbox: bobBox, folder: "INBOX", uidValidity: s.fake.folder(BOB, "INBOX").uidValidity, uid: 1 });
      return x.data?.code === "AUTH_FAILED" ? x : null;
    }, 20_000, "AUTH_FAILED from read_message");
    expect(Date.now() - t0).toBeLessThan(BUDGET_MS);
    expectStructuredError(r, "AUTH_FAILED", { retryable: false, operatorAction: true });
    expectNoLeak(r.text, needles, "AUTH_FAILED payload");
    // the draft path is a Node-side write: also answered without a blind retry
    const d = await cBob.mcp.call("create_draft", { mailbox: bobBox, subject: "x", body: "y", to: ["a@b.example"] });
    expectStructuredError(d, "AUTH_FAILED", { retryable: false, operatorAction: true });
    expectNoLeak(d.text, needles, "create_draft AUTH_FAILED");
    expect(writeCommands(s.fake).filter((x) => x.startsWith("APPEND"))).toHaveLength(0);
    // alice is untouched
    expect((await c.mcp.call("search_messages", { mailbox: box, folder: "INBOX" })).isError).toBe(false);
    await until(() => mailboxStatus(s, bobBox).status === "auth_failed", 20_000, "mailbox status auth_failed");
    expect(alive()).toBe(true);
    s.fake.rejectLogins = false;
    s.fake.loginRejectText = "NO [AUTHENTICATIONFAILED] bad credentials";
  });

  it("injected timeout (server hangs on a body fetch): TIMEOUT within 30 s, retryable, then recovery; process stays alive", async () => {
    const h = s.fake.inject(/FETCH .*BODY/i, { kind: "hang" }, Infinity);
    const t0 = Date.now();
    const r = await body();
    const took = Date.now() - t0;
    h.remove();
    expect(took, `took ${took} ms`).toBeLessThan(BUDGET_MS);
    expect(h.hits).toBeGreaterThanOrEqual(1);
    expectStructuredError(r, "TIMEOUT", { retryable: true });
    expectNoLeak(r.text, needles, "TIMEOUT payload");
    expect(alive()).toBe(true);
    s.fake.dropConnections(); // unstick whatever the hung connection still holds server-side
    const again = await until(async () => { const x = await body(); return x.isError ? null : x; }, 30_000, "recovery after the hang");
    expect(again.data.body).toContain("inbody-");
  }, 120_000);

  it("accept-then-stall (no greeting): the call still ends within 30 s with a structured retryable error", async () => {
    s.fake.stallGreeting = true;
    s.fake.dropConnections();
    const t0 = Date.now();
    const r = await body();
    const took = Date.now() - t0;
    s.fake.stallGreeting = false;
    expect(took, `took ${took} ms`).toBeLessThan(BUDGET_MS);
    expectStructuredError(r, ["TIMEOUT", "UPSTREAM_ERROR", "UNAVAILABLE"], { retryable: true });
    expectNoLeak(r.text, needles, "stall payload");
    expect(alive()).toBe(true);
    const again = await until(async () => { const x = await body(); return x.isError ? null : x; }, 30_000, "recovery after the stall");
    expect(again.isError).toBe(false);
  }, 120_000);

  it("malformed server reply: PROTOCOL_ERROR, not retryable, no raw bytes echoed, recovers once the server behaves", async () => {
    const h = s.fake.inject(/FETCH .*BODY/i, { kind: "malformed", raw: `* 1 FETCH (UID ((( ${SRV} {zz}\r\n{tag} OK ${SRV}\r\n` }, Infinity);
    const t0 = Date.now();
    const r = await body();
    h.remove();
    expect(Date.now() - t0).toBeLessThan(BUDGET_MS);
    expectStructuredError(r, "PROTOCOL_ERROR", { retryable: false });
    expectNoLeak(r.text, needles, "PROTOCOL_ERROR payload");
    expect(alive()).toBe(true);
    const again = await until(async () => { const x = await body(); return x.isError ? null : x; }, 20_000, "recovery after malformed reply");
    expect(again.isError).toBe(false);
  });

  it("quota error on APPEND (NO [OVERQUOTA]): QUOTA_EXCEEDED, definitive (not UNKNOWN_OUTCOME), exactly one APPEND, nothing stored", async () => {
    for (const code of ["NO [OVERQUOTA]", "NO [LIMIT]"]) {
      s.fake.clearLog();
      const before = s.fake.folder(ALICE, "Drafts").messages.length;
      const h = s.fake.inject(/^APPEND /i, { kind: "reply", text: `${code} ${SRV} mailbox is full` });
      const r = await c.mcp.call("create_draft", { mailbox: box, subject: "quota", body: "quota body", to: ["q@example.org"] });
      expect(h.hits).toBe(1);
      expectStructuredError(r, "QUOTA_EXCEEDED", { retryable: false });
      expectNoLeak(r.text, needles, `${code} payload`);
      expect(writeCommands(s.fake).filter((x) => x.startsWith("APPEND")), code).toHaveLength(1);
      expect(s.fake.folder(ALICE, "Drafts").messages.length).toBe(before);
    }
    expect(alive()).toBe(true);
  });

  it("unavailable folder (SELECT NO [UNAVAILABLE]): FOLDER_UNAVAILABLE, distinct from NOT_FOUND; policy-denied folders still answer NOT_FOUND", async () => {
    const h = s.fake.inject(/^(SELECT|EXAMINE) "?(Cold|Secret)"?/i, { kind: "reply", text: `NO [UNAVAILABLE] ${SRV} try later` }, Infinity);
    const r = await c.mcp.call("search_messages", { mailbox: box, folder: "Cold" });
    expectStructuredError(r, "FOLDER_UNAVAILABLE", { retryable: false });
    expectNoLeak(r.text, needles, "FOLDER_UNAVAILABLE payload");
    const missing = await c.mcp.call("search_messages", { mailbox: box, folder: "DoesNotExist" });
    expectStructuredError(missing, "NOT_FOUND");
    // the denied folder must not become an oracle even though the server would say UNAVAILABLE
    s.fake.clearLog();
    const denied = await c.mcp.call("search_messages", { mailbox: box, folder: "Secret" });
    expectStructuredError(denied, "NOT_FOUND");
    expect(denied.data.code).toBe(missing.data.code);
    expect(s.fake.commands.filter((x) => /Secret/.test(x.line) || x.selected === "Secret")).toHaveLength(0);
    h.remove();
    expect(alive()).toBe(true);
  });

  it("every error response carries a request id that matches X-Request-Id; a valid incoming id is honored, an invalid one replaced", async () => {
    const mine = "req-" + Math.random().toString(36).slice(2, 12);
    const r = await rawToolCall(s.base, c.token, "search_messages", { mailbox: box, folder: "NopeFolder" }, { "x-request-id": mine });
    expect(r.status).toBe(200);
    expect(r.isError).toBe(true);
    expect(r.requestId).toBe(mine);
    expect(r.data.requestId).toBe(mine);
    const bad = await rawToolCall(s.base, c.token, "search_messages", { mailbox: box, folder: "NopeFolder" }, { "x-request-id": "bad id with spaces!" });
    expect(bad.requestId).toMatch(/^[A-Za-z0-9_-]{8,64}$/);
    expect(bad.requestId).not.toBe("bad id with spaces!");
    expect(bad.data.requestId).toBe(bad.requestId);
    const gen = await rawToolCall(s.base, c.token, "list_mailboxes");
    expect(gen.requestId).toMatch(/^[0-9a-f-]{36}$/i);
    // logs carry the id of the failing call (diagnosability) ...
    await poll(() => s.srv.output().includes(mine), 5_000);
    // ... and never a secret
    expectNoLeak(s.srv.output(), [...Object.values(s.imapPasswords), s.work.keyHex, s.work.sessionSecret, c.token, cBob.token], "server log");
  });

  it("a flood of failing calls does not terminate the process, and it keeps serving afterwards", async () => {
    const h = s.fake.inject(/FETCH .*BODY/i, { kind: "drop" }, Infinity);
    const rs = await Promise.all(Array.from({ length: 8 }, () => body()));
    h.remove();
    for (const r of rs) expectStructuredError(r, ["UPSTREAM_ERROR", "TIMEOUT", "UNAVAILABLE"]);
    expect(alive()).toBe(true);
    await sleep(500);
    const hz = await fetch(`${s.base}/healthz`);
    expect(hz.status).toBe(200);
    const ok = await until(async () => { const x = await body(); return x.isError ? null : x; }, 20_000, "recovery after flood");
    expect(ok.isError).toBe(false);
  });
});
