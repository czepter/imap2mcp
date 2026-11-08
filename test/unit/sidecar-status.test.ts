import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SidecarService, type OpenParams } from "../../src/sidecar/service.js";
import { SidecarRpcError } from "../../src/sidecar/errors.js";
import { StatusPoller, toMailboxStatus, type SidecarStatus, type StatusSource } from "../../src/sidecar/status.js";
import { SIDECAR_ENV_KNOBS, createSidecarFromConfig } from "../../src/sidecar/index.js";

let db: Database.Database;
const T0 = Date.parse("2026-11-08T12:00:00.000Z");
let clock = T0;
const now = () => new Date(clock);

function schema(withStatusColumns: boolean): Database.Database {
  const d = new Database(":memory:");
  d.exec(`CREATE TABLE mailboxes (id TEXT PRIMARY KEY, label TEXT NOT NULL DEFAULT 'x'${
    withStatusColumns ? ", status TEXT NOT NULL DEFAULT 'unknown', last_error_code TEXT, last_ok_at TEXT, next_retry_at TEXT" : ""})`);
  d.prepare("INSERT INTO mailboxes (id) VALUES ('a'), ('b')").run();
  return d;
}
const row = (id: string) => db.prepare("SELECT status, last_error_code, last_ok_at, next_retry_at FROM mailboxes WHERE id=?").get(id) as
  { status: string; last_error_code: string | null; last_ok_at: string | null; next_retry_at: string | null };

class FakeSource implements StatusSource {
  ids = ["a"];
  statuses = new Map<string, SidecarStatus | Error>();
  calls = 0;
  trackedMailboxIds() { return this.ids; }
  async status(id: string): Promise<SidecarStatus> {
    this.calls++;
    const s = this.statuses.get(id);
    if (!s) throw new Error("no status");
    if (s instanceof Error) throw s;
    return s;
  }
}
const st = (p: Partial<SidecarStatus>): SidecarStatus => ({ state: "connected", since: "2026-11-08T11:00:00.000Z", idle: true, reconnects: 0, ...p });

beforeEach(() => { db = schema(true); clock = T0; });
afterEach(() => { db.close(); });

describe("toMailboxStatus", () => {
  it("maps sidecar states to persisted statuses", () => {
    expect(toMailboxStatus("connected")).toBe("ok");
    expect(toMailboxStatus("reconnecting")).toBe("degraded");
    expect(toMailboxStatus("auth_failed")).toBe("auth_failed");
    expect(toMailboxStatus("closed")).toBeNull();
  });
});

describe("StatusPoller", () => {
  const make = (src: StatusSource, extra: object = {}) => new StatusPoller({ source: src, db: () => db, now, ...extra });

  it("persists ok / degraded / auth_failed with error code, last_ok_at and next_retry_at", async () => {
    const src = new FakeSource();
    const p = make(src);
    src.statuses.set("a", st({}));
    await p.pollOnce();
    expect(row("a")).toEqual({ status: "ok", last_error_code: null, last_ok_at: new Date(T0).toISOString(), next_retry_at: null });

    clock += 1000;
    src.statuses.set("a", st({ state: "reconnecting", lastErrorCode: "TIMEOUT", nextRetryAt: "2026-11-08T12:00:09.000Z", idle: false }));
    await p.pollOnce();
    expect(row("a")).toEqual({ status: "degraded", last_error_code: "TIMEOUT", last_ok_at: new Date(T0).toISOString(), next_retry_at: "2026-11-08T12:00:09.000Z" });

    clock += 1000;
    src.statuses.set("a", st({ state: "connected" }));
    await p.pollOnce();
    expect(row("a")).toEqual({ status: "ok", last_error_code: null, last_ok_at: new Date(clock).toISOString(), next_retry_at: null });

    src.statuses.set("a", st({ state: "auth_failed", lastErrorCode: "AUTH_FAILED" }));
    await p.pollOnce();
    expect(row("a")).toMatchObject({ status: "auth_failed", last_error_code: "AUTH_FAILED", next_retry_at: null });
  });

  it("does not rewrite a healthy row on every poll (last_ok_at refreshed at most every okRefreshMs)", async () => {
    const src = new FakeSource();
    const p = make(src, { okRefreshMs: 60_000 });
    src.statuses.set("a", st({}));
    await p.pollOnce();
    const first = row("a").last_ok_at;
    clock += 5000;
    await p.pollOnce();
    expect(row("a").last_ok_at).toBe(first);
    clock += 61_000;
    await p.pollOnce();
    expect(row("a").last_ok_at).not.toBe(first);
  });

  it("never clears auth_failed by itself; the operator reset to 'unknown' (Retry) lets it resume", async () => {
    const src = new FakeSource();
    const p = make(src);
    db.prepare("UPDATE mailboxes SET status='auth_failed', last_error_code='AUTH_FAILED' WHERE id='a'").run();
    src.statuses.set("a", st({ state: "connected" }));
    await p.pollOnce();
    expect(row("a").status).toBe("auth_failed");
    db.prepare("UPDATE mailboxes SET status='unknown' WHERE id='a'").run();
    await p.pollOnce();
    expect(row("a")).toMatchObject({ status: "ok", last_error_code: null });
  });

  it("ignores closed mailboxes, unknown rows and sidecar errors (keeps last persisted state)", async () => {
    const src = new FakeSource();
    src.ids = ["a", "b", "ghost"];
    src.statuses.set("a", st({ state: "closed" }));
    src.statuses.set("b", new Error("sidecar down"));
    src.statuses.set("ghost", st({}));
    const p = make(src);
    await p.pollOnce();
    expect(row("a").status).toBe("unknown");
    expect(row("b").status).toBe("unknown");
  });

  it("is a no-op until the status columns exist (migration 0002 not applied) and starts working once they do", async () => {
    db.close();
    db = schema(false);
    const src = new FakeSource();
    src.statuses.set("a", st({}));
    const p = make(src);
    await expect(p.pollOnce()).resolves.toBeUndefined();
    expect(src.calls).toBe(0);
    db.exec("ALTER TABLE mailboxes ADD COLUMN status TEXT NOT NULL DEFAULT 'unknown'; ALTER TABLE mailboxes ADD COLUMN last_error_code TEXT; ALTER TABLE mailboxes ADD COLUMN last_ok_at TEXT; ALTER TABLE mailboxes ADD COLUMN next_retry_at TEXT;");
    await p.pollOnce();
    expect(row("a").status).toBe("ok");
  });

  it("does not poll without opened mailboxes, and never throws when the database is unavailable", async () => {
    const src = new FakeSource();
    src.ids = [];
    await make(src).pollOnce();
    expect(src.calls).toBe(0);
    src.ids = ["a"];
    src.statuses.set("a", st({}));
    const broken = new StatusPoller({ source: src, db: () => { throw new Error("db closed"); }, now });
    await expect(broken.pollOnce()).resolves.toBeUndefined();
  });

  it("start() polls on the interval and stop() ends it; overlapping polls are skipped", async () => {
    vi.useFakeTimers();
    try {
      const src = new FakeSource();
      src.statuses.set("a", st({}));
      let release!: () => void;
      const gate = new Promise<void>((r) => { release = r; });
      const slow: StatusSource = { trackedMailboxIds: () => src.ids, status: async (id) => { src.calls++; await gate; return src.statuses.get(id) as SidecarStatus; } };
      const p = new StatusPoller({ source: slow, db: () => db, intervalMs: 5000, now });
      p.start();
      await vi.advanceTimersByTimeAsync(5000);
      await vi.advanceTimersByTimeAsync(5000); // second tick while the first is still waiting
      expect(src.calls).toBe(1);
      release();
      await vi.advanceTimersByTimeAsync(0);
      expect(row("a").status).toBe("ok");
      p.stop();
      await vi.advanceTimersByTimeAsync(20_000);
      expect(src.calls).toBe(1);
    } finally { vi.useRealTimers(); }
  });
});

describe("SidecarService status / retry plumbing", () => {
  const params = async (id: string): Promise<OpenParams> => ({ mailboxId: id, host: "h", ip: "203.0.113.5", port: 993, servername: "h", user: "u", pass: "pw" });

  function service(call: (m: string, p: Record<string, unknown>) => unknown): SidecarService {
    const s = new SidecarService({ bin: "unused", socketPath: "/nonexistent/sock", openParams: params, log: () => {} });
    s.supervisor.state = "ready";
    s.supervisor.generation = 1;
    (s.supervisor.client as unknown as { call: unknown }).call = vi.fn(async (m: string, p: Record<string, unknown>) => call(m, p));
    return s;
  }

  it("status() calls the status RPC without opening the mailbox", async () => {
    const calls: string[] = [];
    const s = service((m) => { calls.push(m); return st({}); });
    expect((await s.status("a")).state).toBe("connected");
    expect(calls).toEqual(["status"]);
  });

  it("tracks opened mailboxes and remembers an open refused for bad credentials", async () => {
    let reject = true;
    const s = service((m, p) => {
      if (m === "open" && p.mailboxId === "bad" && reject) throw new SidecarRpcError(-32020, "upstream authentication failed");
      return { ok: true };
    });
    await s.callMailbox("good", "listFolders");
    await expect(s.callMailbox("bad", "listFolders")).rejects.toBeInstanceOf(SidecarRpcError);
    expect(s.trackedMailboxIds().sort()).toEqual(["bad", "good"]);
    reject = false;
    await s.callMailbox("bad", "listFolders");
    expect(s.trackedMailboxIds().sort()).toEqual(["bad", "good"]);
    await s.closeMailbox("good");
    expect(s.trackedMailboxIds()).toEqual(["bad"]);
  });

  it("a call after an authentication failure (operator Retry / credential edit) lifts the sidecar latch first, once", async () => {
    const calls: string[] = [];
    let failing = true;
    const s = service((m, p) => {
      calls.push(`${m}:${String(p.mailboxId)}`);
      if (m === "listFolders" && failing) throw new SidecarRpcError(-32020, "upstream authentication failed");
      return { ok: true };
    });
    await expect(s.callMailbox("a", "listFolders")).rejects.toBeInstanceOf(SidecarRpcError);
    expect(s.trackedMailboxIds()).toEqual(["a"]);
    calls.length = 0;
    failing = false;
    await s.callMailbox("a", "listFolders"); // the Node tool layer let a call through again => Retry happened
    expect(calls).toEqual(["retry:a", "open:a", "listFolders:a"]);
    calls.length = 0;
    await s.callMailbox("a", "listFolders");
    expect(calls).toEqual(["listFolders:a"]); // healthy again: no retry on later calls
  });

  it("retryMailbox() sends `retry` and forces the next call to re-open with the stored credentials", async () => {
    const calls: string[] = [];
    const s = service((m, p) => { calls.push(`${m}:${String(p.mailboxId)}`); return { ok: true }; });
    await s.callMailbox("a", "listFolders");
    calls.length = 0;
    await s.retryMailbox("a");
    await s.callMailbox("a", "listFolders");
    expect(calls).toEqual(["retry:a", "open:a", "listFolders:a"]);
  });
});

describe("environment knobs", () => {
  it("forwards IDLE_RENEW_SECS and RECONNECT_* to the sidecar child", () => {
    expect(SIDECAR_ENV_KNOBS).toEqual(expect.arrayContaining(["IDLE_RENEW_SECS", "RECONNECT_INITIAL_MS", "RECONNECT_MAX_MS"]));
    const saved = { ...process.env };
    try {
      process.env.IDLE_RENEW_SECS = "12";
      process.env.RECONNECT_INITIAL_MS = "50";
      process.env.RECONNECT_MAX_MS = "400";
      process.env.BASE_URL = "https://bridge.example.test";
      process.env.SESSION_SECRET = "must-not-leak-0123456789abcdef0123456789";
      const s = createSidecarFromConfig();
      const env = (s.supervisor as unknown as { o: { env: Record<string, string> } }).o.env;
      expect(env).toMatchObject({ IDLE_RENEW_SECS: "12", RECONNECT_INITIAL_MS: "50", RECONNECT_MAX_MS: "400" });
      expect(JSON.stringify(env)).not.toContain("must-not-leak");
    } finally {
      for (const k of Object.keys(process.env)) if (!(k in saved)) delete process.env[k];
      Object.assign(process.env, saved);
    }
  });
});
