import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

let db: Database.Database;
let withStatusColumn = true;
vi.mock("../../server/core/db/database.js", () => ({ getDb: () => db }));

let connectBehavior: () => Promise<void> = async () => {};
let constructed = 0;
vi.mock("imapflow", () => ({
  ImapFlow: class {
    usable = true;
    constructor() { constructed++; }
    on() { return this; }
    async connect() { await connectBehavior(); }
    close() { this.usable = false; }
    async logout() { this.usable = false; }
  },
}));
vi.mock("../../server/core/imap/mailboxes.js", () => ({
  getMailboxCredentials: () => ({ host: "imap.example.test", port: 993, user: "u", password: "p" }),
}));
vi.mock("../../server/core/imap/ssrf.js", () => ({ assertHostAllowed: async () => ["127.0.0.1"] }));

const client = await import("../../server/core/imap/client.js");
const { computeBackoffDelay, withImap, markMailboxAuthFailed, clearMailboxAuthFailure, isMailboxAuthFailed, ImapAuthError, ImapConnectError, resetBackoffForTests, getBackoffState } = client;
const { readOp, retryDelayMs, MAX_READ_RETRIES } = await import("../../server/core/mcp/reliability.js");
const { withBudget } = await import("../../server/core/imap/budget.js");
const { ToolError } = await import("../../server/core/mcp/errors.js");

beforeEach(async () => {
  process.env.LOG_LEVEL = "error";
  await client.closeAllImap();
  db = new Database(":memory:");
  db.exec(`CREATE TABLE mailboxes (id TEXT PRIMARY KEY${withStatusColumn ? ", status TEXT NOT NULL DEFAULT 'unknown', last_error_code TEXT, last_ok_at TEXT, next_retry_at TEXT" : ""})`);
  db.prepare("INSERT INTO mailboxes (id) VALUES ('mb')").run();
  constructed = 0;
  connectBehavior = async () => {};
  resetBackoffForTests();
  delete process.env.RECONNECT_INITIAL_MS;
  delete process.env.RECONNECT_MAX_MS;
});
afterEach(() => { withStatusColumn = true; delete process.env.RECONNECT_INITIAL_MS; delete process.env.RECONNECT_MAX_MS; });

describe("computeBackoffDelay: capped exponential, full jitter, floor 500 ms", () => {
  it("grows 1s,2s,4s... and caps at 60s (upper bound of the jitter window)", () => {
    const max = () => 0.999999;
    expect([0, 1, 2, 3, 4, 5, 6, 7, 20].map((n) => computeBackoffDelay(n, { rand: max }))).toEqual([999, 1999, 3999, 7999, 15999, 31999, 59999, 59999, 59999]);
  });
  it("full jitter: spans the whole window but never drops below 500 ms", () => {
    expect(computeBackoffDelay(5, { rand: () => 0 })).toBe(500);
    expect(computeBackoffDelay(0, { rand: () => 0.1 })).toBe(500);
    expect(computeBackoffDelay(3, { rand: () => 0.5 })).toBe(4000);
    for (let i = 0; i < 500; i++) {
      const d = computeBackoffDelay(2);
      expect(d).toBeGreaterThanOrEqual(500);
      expect(d).toBeLessThanOrEqual(4000);
    }
  });
  it("RECONNECT_INITIAL_MS / RECONNECT_MAX_MS shrink the schedule for tests", () => {
    process.env.RECONNECT_INITIAL_MS = "40";
    process.env.RECONNECT_MAX_MS = "100";
    expect(computeBackoffDelay(0, { rand: () => 0.999 })).toBeLessThanOrEqual(40);
    expect(computeBackoffDelay(10, { rand: () => 0.999 })).toBeLessThanOrEqual(100);
    expect(computeBackoffDelay(10, { rand: () => 0 })).toBe(100 < 500 ? Math.min(500, 100) : 500);
  });
});

describe("pool reconnect gate", () => {
  it("a failed connect arms the backoff; calls inside the window fail fast without a new connection attempt", async () => {
    process.env.RECONNECT_INITIAL_MS = "200";
    process.env.RECONNECT_MAX_MS = "400";
    connectBehavior = async () => { throw Object.assign(new Error("refused"), { code: "ECONNREFUSED" }); };
    await expect(withImap("mb", async () => 1)).rejects.toBeInstanceOf(ImapConnectError);
    expect(constructed).toBe(1);
    const e = await withImap("mb", async () => 1).catch((x) => x);
    expect(e).toBeInstanceOf(ImapConnectError);
    expect(e.retryAfterMs).toBeGreaterThan(0);
    expect(constructed).toBe(1); // gated: no second attempt
    expect(getBackoffState("mb").failures).toBe(1);
    await new Promise((r) => setTimeout(r, 450));
    connectBehavior = async () => {};
    expect(await withImap("mb", async () => "ok")).toBe("ok");
    expect(constructed).toBe(2);
  });

  it("inside a tool budget a short backoff is waited out instead of failing", async () => {
    process.env.RECONNECT_INITIAL_MS = "150";
    process.env.RECONNECT_MAX_MS = "150";
    connectBehavior = async () => { throw new Error("refused"); };
    await withImap("mb", async () => 1).catch(() => {});
    connectBehavior = async () => {};
    const t0 = Date.now();
    expect(await withBudget(() => withImap("mb", async () => "ok"), 10_000)).toBe("ok");
    expect(Date.now() - t0).toBeLessThan(1_000);
  });
});

describe("auth-failure latch", () => {
  it("server rejects login => latched, status persisted, later calls never construct a client", async () => {
    connectBehavior = async () => { throw Object.assign(new Error("Invalid credentials"), { authenticationFailed: true, serverResponseCode: "AUTHENTICATIONFAILED", responseStatus: "NO" }); };
    await expect(withImap("mb", async () => 1)).rejects.toBeInstanceOf(ImapAuthError);
    expect(constructed).toBe(1);
    expect(isMailboxAuthFailed("mb")).toBe(true);
    expect(db.prepare("SELECT status, last_error_code FROM mailboxes WHERE id='mb'").get()).toEqual({ status: "auth_failed", last_error_code: "AUTH_FAILED" });
    for (let i = 0; i < 3; i++) await expect(withImap("mb", async () => 1)).rejects.toMatchObject({ latched: true });
    expect(constructed).toBe(1);
  });

  it("tools answer AUTH_FAILED immediately without invoking the backend", async () => {
    markMailboxAuthFailed("mb");
    const fn = vi.fn(async () => 1);
    const e = await readOp("mb", fn).catch((x) => x);
    expect(e).toBeInstanceOf(ToolError);
    expect(e.code).toBe("AUTH_FAILED");
    expect(e.retryable).toBe(false);
    expect(fn).not.toHaveBeenCalled();
  });

  it("clearMailboxAuthFailure resumes attempts and resets the status to unknown", async () => {
    markMailboxAuthFailed("mb");
    clearMailboxAuthFailure("mb");
    expect(db.prepare("SELECT status FROM mailboxes WHERE id='mb'").get()).toEqual({ status: "unknown" });
    expect(await withImap("mb", async () => "ok")).toBe("ok");
  });

  it("the DB status column is authoritative (admin UI / sidecar poller can latch it)", () => {
    db.prepare("UPDATE mailboxes SET status='auth_failed' WHERE id='mb'").run();
    expect(isMailboxAuthFailed("mb")).toBe(true);
    db.prepare("UPDATE mailboxes SET status='unknown' WHERE id='mb'").run();
    expect(isMailboxAuthFailed("mb")).toBe(false);
  });

  it("works before migration 0002 (no status column): in-memory latch only, no throw", () => {
    db.exec("DROP TABLE mailboxes; CREATE TABLE mailboxes (id TEXT PRIMARY KEY)");
    db.prepare("INSERT INTO mailboxes (id) VALUES ('mb')").run();
    expect(() => markMailboxAuthFailed("mb")).not.toThrow();
    expect(isMailboxAuthFailed("mb")).toBe(true);
    clearMailboxAuthFailure("mb");
    expect(isMailboxAuthFailed("mb")).toBe(false);
  });
});

describe("bounded jittered read retries inside the budget", () => {
  const upstream = () => Object.assign(new Error("x"), { code: "ECONNRESET" });

  it("retries at most MAX_READ_RETRIES (=2) times then gives up", async () => {
    expect(MAX_READ_RETRIES).toBe(2);
    const fn = vi.fn(async () => { throw new ToolError("UPSTREAM_ERROR", "down"); });
    await expect(readOp("mb", fn, () => 0)).rejects.toMatchObject({ code: "UPSTREAM_ERROR" });
    expect(fn).toHaveBeenCalledTimes(3);
    void upstream;
  });
  it("succeeds when a retry recovers", async () => {
    let n = 0;
    const r = await readOp("mb", async () => { if (++n < 3) throw new ToolError("TIMEOUT", "t"); return "fine"; }, () => 0);
    expect(r).toBe("fine");
    expect(n).toBe(3);
  });
  it("does not retry non-retryable errors", async () => {
    const fn = vi.fn(async () => { throw new ToolError("NOT_FOUND", "nf"); });
    await expect(readOp("mb", fn)).rejects.toMatchObject({ code: "NOT_FOUND" });
    expect(fn).toHaveBeenCalledTimes(1);
  });
  it("jitter: delay is random per call and within [150,400]*2^n", () => {
    expect(retryDelayMs(0, () => 0)).toBe(150);
    expect(retryDelayMs(0, () => 1)).toBe(400);
    expect(retryDelayMs(1, () => 0)).toBe(300);
    const set = new Set(Array.from({ length: 20 }, () => retryDelayMs(0)));
    expect(set.size).toBeGreaterThan(1);
  });
  it("30 s budget is honoured: a hanging read ends as TIMEOUT at the budget, not after", async () => {
    const t0 = Date.now();
    const e = await withBudget(() => readOp("mb", () => new Promise(() => {})), 300).catch((x) => x);
    expect(e.code).toBe("TIMEOUT");
    expect(Date.now() - t0).toBeLessThan(1_500);
  });
  it("no retry is started when the remaining budget cannot cover the delay", async () => {
    const fn = vi.fn(async () => { throw new ToolError("UPSTREAM_ERROR", "down"); });
    await withBudget(() => readOp("mb", fn, () => 0), 800).catch(() => {});
    expect(fn.mock.calls.length).toBeLessThan(3);
  });
});
