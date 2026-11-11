/**
 * Version 2 acceptance criterion 2 (recovery), end to end with the real sidecar and scaled timers
 * (RECONNECT_INITIAL_MS=200, RECONNECT_MAX_MS=2000, IDLE_RENEW_SECS=2; the fake enforces a 5 s server-side IDLE limit):
 *  - connection drop => capped exponential backoff with jitter, observed as the fake server's accept log;
 *  - IDLE is renewed before the provider deadline; untagged EXISTS triggers a sync without any tool call;
 *  - IDLE drop and server auto-logout => reconnect + full reconcile of missed changes (new mail, expunges, flag changes);
 *  - authentication failure stops credential retries (LOGIN count on the fake), tools answer AUTH_FAILED without touching
 *    the server, and the UI Retry / a credential edit resumes.
 * The real-timer "resume within 90 s" proof is in v2-slow.test.ts.
 */
import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import { msg, sleep, type Stack } from "../helpers/stack.js";
import { allowAll, newClient, type Client } from "../helpers/v1.js";
import {
  ALICE, BOB, canRunV2, createV2Stack, expectStructuredError, mailboxStatus, uiEditCredentials, uiRetry, until, dbAll,
} from "../helpers/v2.js";

vi.setConfig({ testTimeout: 120_000, hookTimeout: 120_000 });

const RENEW_SECS = 2;
const IDLE_MAX_MS = 5_000;
const INITIAL = 200;
const CAP = 2_000;
const JITTER_SLACK = 700; // connect + TLS + scheduling on a busy host

describe.skipIf(!canRunV2)("v2 recovery: backoff, IDLE, reconcile, auth latch (criterion 2)", () => {
  let s: Stack;
  let box: string;
  let bobBox: string;
  let c: Client;
  let cBob: Client;

  const search = (folder = "INBOX", args: Record<string, unknown> = {}) => c.mcp.call("search_messages", { mailbox: box, folder, limit: 50, ...args });
  const subjects = (r: { data: any }): string[] => (r.data?.messages ?? []).map((m: any) => m.subject as string);

  beforeAll(async () => {
    s = await createV2Stack({
      env: { IDLE_RENEW_SECS: String(RENEW_SECS) },
      fake: (f) => { f.idleCap = true; f.idleMaxMs = IDLE_MAX_MS; },
    });
    box = s.mailbox[ALICE];
    bobBox = s.mailbox[BOB];
    for (let i = 0; i < 4; i++) s.fake.addMessage(ALICE, "INBOX", msg(`base-${i}`));
    s.fake.addMessage(BOB, "INBOX", msg("bob-base"));
    c = await newClient(s, box, allowAll(), "v2-recovery");
    cBob = await newClient(s, bobBox, allowAll(), "v2-recovery-bob");
    expect((await search()).isError).toBe(false); // opens the mailbox in the sidecar
    expect((await cBob.mcp.call("search_messages", { mailbox: bobBox, folder: "INBOX" })).isError).toBe(false);
  });
  afterAll(async () => {
    await c?.mcp.close();
    await cBob?.mcp.close();
    await s?.teardown();
  });

  it("IDLE is established on INBOX and renewed before the server's deadline (no server-side IDLE timeout, no reconnect churn)", async () => {
    await until(() => s.fake.activeIdle(ALICE, "INBOX") >= 1, 15_000, "sidecar IDLE on INBOX");
    const n0 = s.fake.idleSessions.filter((x) => x.user === ALICE).length;
    const connects0 = s.fake.connectLog.length;
    await sleep(3 * IDLE_MAX_MS); // 15 s: three server deadlines
    const sessions = s.fake.idleSessions.filter((x) => x.user === ALICE && x.folder === "INBOX");
    expect(sessions.length - n0, "IDLE re-issued during the window").toBeGreaterThanOrEqual(4);
    const done = sessions.filter((x) => x.end !== undefined);
    expect(done.length).toBeGreaterThanOrEqual(3);
    for (const x of done) {
      expect(x.endedBy, `IDLE session ended by ${x.endedBy}`).toBe("done");
      expect(x.end! - x.start, "IDLE session length").toBeLessThan(IDLE_MAX_MS - 500);
      expect(x.end! - x.start, "renewed about every IDLE_RENEW_SECS").toBeLessThan((RENEW_SECS + 1.5) * 1000);
    }
    expect(sessions.some((x) => x.endedBy === "timeout")).toBe(false);
    expect(s.fake.connectLog.length - connects0, "no reconnects while IDLE is healthy").toBe(0);
  });

  it("an untagged EXISTS during IDLE makes the sidecar sync the folder with no tool call and without waiting for the reconcile timer", async () => {
    s.fake.resetFetchStats();
    s.fake.externalDeliver(ALICE, "INBOX", 3, (i) => `idle-push-${i}`);
    expect(s.fake.notifyIdle(ALICE, "INBOX")).toBeGreaterThanOrEqual(1);
    await until(() => s.fake.fetchTotal(ALICE, "INBOX", "envelope") >= 3, 8_000, "incremental sync after EXISTS (no tool call made)");
    const r = await search();
    expect(subjects(r).filter((x) => x.startsWith("idle-push-")).sort()).toEqual(["idle-push-0", "idle-push-1", "idle-push-2"]);
  });

  it("IDLE drop: mail delivered meanwhile is reconciled after the sidecar re-establishes IDLE (no tool call needed)", async () => {
    const before = s.fake.idleSessions.length;
    s.fake.resetFetchStats();
    s.fake.externalDeliver(ALICE, "INBOX", 2, (i) => `after-idle-drop-${i}`);
    expect(s.fake.dropIdleConnections()).toBeGreaterThanOrEqual(1);
    await until(() => s.fake.idleSessions.length > before && s.fake.activeIdle(ALICE, "INBOX") >= 1, 15_000, "IDLE re-established");
    await until(() => s.fake.fetchTotal(ALICE, "INBOX", "envelope") >= 2, 15_000, "reconcile fetched the missed mail");
    expect(subjects(await search()).filter((x) => x.startsWith("after-idle-drop-"))).toHaveLength(2);
  });

  it("server-side auto-logout (BYE) of an idle connection: sidecar reconnects, re-IDLEs, serves correct data", async () => {
    const lo0 = s.fake.autoLogouts;
    const conn0 = s.fake.connectLog.length;
    s.fake.autoLogoutMs = 1_200; // shorter than the renew interval: the server will hang up on us
    await until(() => s.fake.autoLogouts > lo0, 10_000, "server auto-logout fired");
    s.fake.autoLogoutMs = 0;
    await until(() => s.fake.connectLog.length > conn0 && s.fake.activeIdle(ALICE, "INBOX") >= 1, 15_000, "reconnect + IDLE after BYE");
    s.fake.externalDeliver(ALICE, "INBOX", 1, () => "after-bye");
    s.fake.notifyIdle(ALICE, "INBOX");
    await until(async () => subjects(await search()).includes("after-bye"), 15_000, "post-BYE mail visible");
  });

  it("connection drop with the server refusing: capped exponential backoff with jitter, then resume and reconcile missed changes", async () => {
    // changes that happen while we are offline: new mail, an expunge and a flag change
    const victim = s.fake.folder(ALICE, "INBOX").messages.find((m) => m.uid === 1)!.uid;
    const flagged = s.fake.folder(ALICE, "INBOX").messages.find((m) => m.uid === 2)!.uid;
    s.fake.refuseConnections = true;
    const t0 = Date.now();
    s.fake.dropConnections();
    s.fake.externalDeliver(ALICE, "INBOX", 2, (i) => `offline-arrival-${i}`);
    s.fake.externalExpunge(ALICE, "INBOX", [victim]);
    s.fake.externalSetFlags(ALICE, "INBOX", flagged, ["\\Flagged"]);

    await sleep(9_000);
    const attempts = s.fake.connectLog.filter((x) => x.ts >= t0 && x.refused).map((x) => x.ts);
    const gaps = attempts.slice(1).map((t, i) => t - attempts[i]);
    // bounded: not a hot loop, not silent
    expect(attempts.length, `attempts: ${gaps.join(",")}`).toBeGreaterThanOrEqual(4);
    expect(attempts.length).toBeLessThanOrEqual(40);
    // capped: no gap above MAX (+ connect time); and the cap is actually approached (growth happened)
    for (const g of gaps) expect(g, `gaps ${gaps.join(",")}`).toBeLessThanOrEqual(CAP + JITTER_SLACK);
    expect(Math.max(...gaps), `gaps ${gaps.join(",")}`).toBeGreaterThan(INITIAL * 1.5);
    // jittered: gaps are not a fixed sequence
    expect(Math.max(...gaps) - Math.min(...gaps), `gaps ${gaps.join(",")}`).toBeGreaterThan(50);
    const during = mailboxStatus(s, box);
    expect(["degraded", "ok", "unknown"]).toContain(during.status); // never auth_failed for a network problem
    expect(during.status).not.toBe("auth_failed");

    // connectivity returns: resume within a few capped delays (scaled analogue of "within 90 s")
    s.fake.resetFetchStats();
    const t1 = Date.now();
    s.fake.refuseConnections = false;
    await until(() => s.fake.connectLog.some((x) => x.ts >= t1 && !x.refused), CAP + 4_000, "successful reconnect");
    // the full reconcile runs on its own: new mail fetched before any tool call
    await until(() => s.fake.fetchTotal(ALICE, "INBOX", "envelope") >= 2, 10_000, "reconcile fetched offline arrivals without a tool call");
    const r = await search();
    const subj = subjects(r);
    expect(subj.filter((x) => x.startsWith("offline-arrival-")).sort()).toEqual(["offline-arrival-0", "offline-arrival-1"]);
    expect(subj).not.toContain("base-0"); // the expunged message is gone
    const f = r.data.messages.find((m: any) => m.ref.uid === flagged);
    expect(f.flags).toContain("\\Flagged");
    await until(() => mailboxStatus(s, box).status === "ok", 15_000, "mailbox status back to ok");
    expect(mailboxStatus(s, box).last_ok_at).toBeTruthy();
  });

  it("authentication failure stops credential retries; tools answer AUTH_FAILED without contacting the server; UI Retry resumes", async () => {
    s.fake.rejectLogins = (u) => u === BOB;
    const t0 = Date.now();
    s.fake.dropConnections();
    // the first call after the drop makes the sidecar log in and be rejected
    await until(async () => {
      const r = await cBob.mcp.call("read_message", { ref: { mailbox: bobBox, folder: "INBOX", uidValidity: s.fake.folder(BOB, "INBOX").uidValidity, uid: 1 }, include: ["body"] });
      return r.data?.code === "AUTH_FAILED";
    }, 20_000, "AUTH_FAILED");
    await until(() => mailboxStatus(s, bobBox).status === "auth_failed", 15_000, "status auth_failed persisted");
    expect(mailboxStatus(s, bobBox).last_error_code).toBeTruthy();

    // 1) credential attempts stop: with a 200 ms..2 s backoff a retry loop would add dozens of LOGINs in 8 s
    const settled = s.fake.loginAttemptsSince(t0, BOB);
    expect(settled).toBeGreaterThanOrEqual(1);
    expect(settled, "LOGIN attempts until the latch engaged").toBeLessThanOrEqual(4);
    await sleep(8_000);
    expect(s.fake.loginAttemptsSince(t0, BOB), "LOGIN attempts must not grow after auth_failed").toBe(settled);

    // 2) tools answer AUTH_FAILED immediately and make no connection at all
    const conn0 = s.fake.connectLog.length;
    const cmd0 = s.fake.commands.length;
    for (const [name, args] of [
      ["search_messages", { mailbox: bobBox, folder: "INBOX", text: "anything" }],
      ["read_message", { ref: { mailbox: bobBox, folder: "INBOX", uidValidity: s.fake.folder(BOB, "INBOX").uidValidity, uid: 1 } }],
      ["list_folders", { mailbox: bobBox }],
      ["create_draft", { mailbox: bobBox, subject: "s", body: "b", to: ["a@b.example"] }],
    ] as const) {
      const t = Date.now();
      const r = await cBob.mcp.call(name, args as any);
      expect(Date.now() - t, `${name} answered quickly`).toBeLessThan(3_000);
      expectStructuredError(r, "AUTH_FAILED", { retryable: false, operatorAction: true });
    }
    expect(s.fake.connectLog.length - conn0, "no TCP connection for AUTH_FAILED answers").toBe(0);
    expect(s.fake.commands.length - cmd0).toBe(0);
    expect(s.fake.loginAttemptsSince(t0, BOB)).toBe(settled);
    // other mailboxes keep working
    expect((await search()).isError).toBe(false);

    // 3) the admin page shows the state and offers Retry
    const detail = (await (await s.admin.get(`/api/mailboxes/${bobBox}`)).json()) as any;
    expect(detail.status.status).toBe("auth_failed");
    expect(typeof detail.status.lastErrorCode === "string" && detail.status.lastErrorCode.length > 0).toBe(true);
    const ov = (await (await s.admin.get("/api/overview")).json()) as any;
    expect(ov.mailboxes.find((m: any) => m.id === bobBox).status).toBe("auth_failed");

    // 4) Retry while the server still rejects: one more bounded attempt, then latched again (no loop)
    const t1 = Date.now();
    const rr = await uiRetry(s, bobBox);
    expect(rr.status).toBe(204);
    await sleep(6_000);
    expect(s.fake.loginAttemptsSince(t1, BOB), "a Retry causes a bounded number of attempts").toBeLessThanOrEqual(4);
    await until(async () => (await cBob.mcp.call("list_folders", { mailbox: bobBox })).data?.code === "AUTH_FAILED", 15_000, "latched again");
    const settled2 = s.fake.loginAttemptsSince(t1, BOB);
    await sleep(5_000);
    expect(s.fake.loginAttemptsSince(t1, BOB)).toBe(settled2);

    // 5) the provider is fixed + Retry => resumes
    s.fake.rejectLogins = false;
    expect((await uiRetry(s, bobBox)).status).toBe(204);
    await until(async () => !(await cBob.mcp.call("list_folders", { mailbox: bobBox })).isError, 20_000, "tools work after Retry");
    await until(() => mailboxStatus(s, bobBox).status === "ok", 15_000, "status ok after Retry");
  });

  it("a credential edit also resumes a latched mailbox (server-side password change, then the owner enters the new one)", async () => {
    const newPw = "Rotated-" + Math.random().toString(36).slice(2, 12);
    s.fake.accounts.get(BOB)!.pass = newPw; // provider rotated the password
    const t0 = Date.now();
    s.fake.dropConnections();
    await until(async () => (await cBob.mcp.call("list_folders", { mailbox: bobBox })).data?.code === "AUTH_FAILED", 20_000, "AUTH_FAILED after password rotation");
    const settled = s.fake.loginAttemptsSince(t0, BOB);
    await sleep(5_000);
    expect(s.fake.loginAttemptsSince(t0, BOB)).toBe(settled);
    const r = await uiEditCredentials(s, bobBox, BOB, newPw);
    expect(r.status).toBe(200);
    await until(async () => !(await cBob.mcp.call("list_folders", { mailbox: bobBox })).isError, 20_000, "tools work after credential edit");
    await until(() => mailboxStatus(s, bobBox).status === "ok", 15_000, "status ok after edit");
    // the (encrypted) stored password was replaced, not the plaintext leaked into logs
    expect(s.srv.output()).not.toContain(newPw);
    const row = dbAll<{ n: number }>(s, "SELECT COUNT(*) n FROM mailboxes WHERE id = ?", bobBox)[0];
    expect(row.n).toBe(1);
  });
});
