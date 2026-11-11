/**
 * Black-box acceptance tests for the audit admin API (docs/NUXT_MIGRATION.md): GET /api/audit (filters, pagination,
 * options) and the streamed JSONL / CSV exports. The audit table is seeded directly so that every expectation is
 * computed from a reference model of the seed, not from the implementation.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { makeSelfSignedCert } from "../helpers/certs.js";
import { Browser, errorOf, json } from "../helpers/http.js";
import { createStack, type Stack } from "../helpers/stack.js";
import type { AuditEvent, AuditPage } from "../../shared/types/api.js";

const haveOpenssl = !!makeSelfSignedCert();
const PAGE_SIZE = 50;
const OUTCOMES = ["ok", "ok", "denied", "failed", "unknown_outcome"] as const;
const TOOLS = ["search_messages", "read_message", "create_draft"] as const;
const BASE = Date.parse("2026-01-10T00:00:00.000Z");

interface Seed { id: string; ts: string; client: string; mailbox: string | null; tool: string; outcome: string; folder: string | null; uid: number | null; uids: number[] | null; cached: number; reconciled: number; ms: number | null; err: string | null }

function seedRows(n: number): Seed[] {
  return Array.from({ length: n }, (_, i) => ({
    id: `seed-${String(i).padStart(5, "0")}`,
    ts: new Date(BASE + i * 20 * 60_000).toISOString(), // 20 minutes apart: spans three UTC days for n = 123
    client: i % 2 === 0 ? "client-even" : "client-odd",
    mailbox: i % 7 === 6 ? null : i % 3 === 0 ? "mailbox-a" : "mailbox-b",
    tool: TOOLS[i % 3],
    outcome: OUTCOMES[i % 5],
    folder: i % 4 === 0 ? "INBOX" : i % 4 === 1 ? "Archive/2025" : null,
    uid: i % 5 === 0 ? i + 1 : null,
    uids: i % 5 === 1 ? [i + 1, i + 2, i + 3] : null,
    cached: i % 6 === 0 ? 1 : 0,
    reconciled: i % 11 === 0 ? 1 : 0,
    ms: i % 9 === 0 ? null : 5 + i,
    err: OUTCOMES[i % 5] === "failed" ? "UPSTREAM_ERROR" : OUTCOMES[i % 5] === "denied" ? "FORBIDDEN" : null,
  }));
}

describe.skipIf(!haveOpenssl)("audit admin API", () => {
  let s: Stack;
  let seed: Seed[] = [];
  type F = Partial<{ client: string; mailbox: string; tool: string; outcome: string; from: string; to: string }>;
  const model = (f: F): Seed[] => {
    const to = f.to ? (/^\d{4}-\d\d-\d\d$/.test(f.to) ? new Date(Date.parse(f.to) + 86_400_000).toISOString() : new Date(f.to).toISOString()) : undefined;
    const from = f.from ? new Date(f.from).toISOString() : undefined;
    return seed.filter((r) => (!f.client || r.client === f.client) && (!f.mailbox || r.mailbox === f.mailbox) && (!f.tool || r.tool === f.tool) && (!f.outcome || r.outcome === f.outcome) && (!from || r.ts >= from) && (!to || r.ts < to));
  };
  const newestFirst = (rows: Seed[]) => [...rows].sort((a, b) => (a.ts < b.ts ? 1 : a.ts > b.ts ? -1 : a.id < b.id ? 1 : -1));
  const qs = (f: Record<string, string | number>) => new URLSearchParams(Object.entries(f).map(([k, v]) => [k, String(v)])).toString();
  const page = async (f: Record<string, string | number> = {}) => {
    const r = await s.admin.get(`/api/audit?${qs(f)}`);
    expect(r.status, qs(f)).toBe(200);
    return json<AuditPage>(r);
  };

  beforeAll(async () => {
    s = await createStack({ accounts: ["alice@example.test"], skipMailboxes: true });
    seed = seedRows(123);
    const db = s.srv.db();
    db.pragma("busy_timeout = 5000");
    const ins = db.prepare("INSERT INTO audit_events (id, ts, request_id, client_id, mailbox_id, folder, uid_validity, uid, uids, uids_truncated, tool, outcome, error_code, cached, reconciled, duration_ms) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
    db.transaction(() => {
      for (const r of seed) ins.run(r.id, r.ts, "req-" + r.id, r.client, r.mailbox, r.folder, r.folder ? 7 : null, r.uid, r.uids ? JSON.stringify(r.uids) : null, 0, r.tool, r.outcome, r.err, r.cached, r.reconciled, r.ms);
    })();
  });
  afterAll(async () => { await s?.teardown(); });

  describe("GET /api/audit", () => {
    it("returns AuditPage: newest first, 50 per page, totals and page count", async () => {
      const p = await page();
      expect(p.total).toBe(123);
      expect(p.pageSize).toBe(PAGE_SIZE);
      expect(p.pages).toBe(3);
      expect(p.page).toBe(1);
      expect(p.events).toHaveLength(50);
      expect(p.events.map((e) => e.id)).toEqual(newestFirst(seed).slice(0, 50).map((r) => r.id));
      const p3 = await page({ page: 3 });
      expect(p3.page).toBe(3);
      expect(p3.events.map((e) => e.id)).toEqual(newestFirst(seed).slice(100).map((r) => r.id));
      expect(p3.events).toHaveLength(23);
      // pages tile the data exactly: no overlap, no gap
      const all = [...(await page({ page: 1 })).events, ...(await page({ page: 2 })).events, ...p3.events].map((e) => e.id);
      expect(new Set(all).size).toBe(123);
    });

    it("bad or out-of-range page numbers are clamped, never an error", async () => {
      expect((await page({ page: 99 })).page).toBe(3);
      for (const bad of [0, -5, "abc", "", "1e3x"]) {
        const p = await page({ page: bad });
        expect(p.page, `page=${bad}`).toBeGreaterThanOrEqual(1);
        expect(p.page).toBeLessThanOrEqual(3);
      }
      expect((await page({ page: 0 })).page).toBe(1);
      expect((await page({ page: "abc" })).page).toBe(1);
    });

    it("the event DTO carries identifiers only, typed as documented", async () => {
      const p = await page();
      const byId = new Map(seed.map((r) => [r.id, r]));
      for (const e of p.events) {
        const r = byId.get(e.id)!;
        expect(e).toMatchObject({ id: r.id, ts: r.ts, requestId: "req-" + r.id, clientId: r.client, mailboxId: r.mailbox, folder: r.folder, tool: r.tool, outcome: r.outcome, errorCode: r.err, cached: !!r.cached, reconciled: !!r.reconciled, durationMs: r.ms, uid: r.uid, uidsTruncated: false });
        expect(e.uidValidity).toBe(r.folder ? 7 : null);
        expect(e.uids).toEqual(r.uids);
        expect(Number.isNaN(Date.parse(e.ts))).toBe(false);
      }
      expect(p.events.some((e) => e.uids && e.uids.length === 3)).toBe(true);
      expect(p.events.some((e) => e.cached === true) && p.events.some((e) => e.cached === false)).toBe(true);
    });

    it("options list the distinct clients, mailboxes and tools present plus all four outcomes", async () => {
      const p = await page();
      expect([...p.options.clients].sort()).toEqual(["client-even", "client-odd"]);
      expect([...p.options.mailboxes].sort()).toEqual(["mailbox-a", "mailbox-b"]);
      expect([...p.options.tools].sort()).toEqual([...TOOLS].sort());
      expect([...p.options.outcomes].sort()).toEqual(["denied", "failed", "ok", "unknown_outcome"]);
      // options are not narrowed by the active filter
      const f = await page({ client: "client-even" });
      expect([...f.options.clients].sort()).toEqual(["client-even", "client-odd"]);
    });

    it.each<[string, F]>([
      ["client", { client: "client-even" }],
      ["mailbox", { mailbox: "mailbox-a" }],
      ["tool", { tool: "create_draft" }],
      ["outcome", { outcome: "denied" }],
      ["outcome unknown_outcome", { outcome: "unknown_outcome" }],
      ["client + tool + outcome", { client: "client-odd", tool: "search_messages", outcome: "ok" }],
      ["from (inclusive instant)", { from: new Date(BASE + 30 * 20 * 60_000).toISOString() }],
      ["to (exclusive instant)", { to: new Date(BASE + 30 * 20 * 60_000).toISOString() }],
      ["from + to window", { from: "2026-01-10T12:00:00.000Z", to: "2026-01-11T06:00:00.000Z" }],
      ["bare-date from", { from: "2026-01-11" }],
      ["bare-date to is inclusive of that whole day", { to: "2026-01-10" }],
      ["bare-date range", { from: "2026-01-11", to: "2026-01-11" }],
      ["everything combined", { client: "client-even", mailbox: "mailbox-b", tool: "read_message", outcome: "ok", from: "2026-01-10", to: "2026-01-11" }],
      ["no match", { client: "client-even", tool: "no_such_tool" }],
    ])("filter: %s", async (_name, f) => {
      const want = newestFirst(model(f));
      const p = await page(f as Record<string, string>);
      expect(p.total).toBe(want.length);
      expect(p.pages).toBe(Math.max(1, Math.ceil(want.length / PAGE_SIZE)));
      expect(p.events.map((e) => e.id)).toEqual(want.slice(0, PAGE_SIZE).map((r) => r.id));
    });

    it("the filter survives pagination", async () => {
      const f = { client: "client-even" };
      const want = newestFirst(model(f));
      expect(want.length).toBeGreaterThan(PAGE_SIZE);
      const p2 = await page({ ...f, page: 2 });
      expect(p2.page).toBe(2);
      expect(p2.events.map((e) => e.id)).toEqual(want.slice(PAGE_SIZE, 2 * PAGE_SIZE).map((r) => r.id));
    });

    it("unknown outcomes and unparsable dates are ignored (unfiltered), values are trimmed, SQL metacharacters are inert", async () => {
      expect((await page({ outcome: "bogus" })).total).toBe(123);
      expect((await page({ outcome: "" })).total).toBe(123);
      expect((await page({ from: "not-a-date" })).total).toBe(123);
      expect((await page({ to: "tomorrow-ish" })).total).toBe(123);
      expect((await page({ client: "  client-odd  " })).total).toBe(model({ client: "client-odd" }).length);
      for (const evil of ["' OR '1'='1", "client-even' --", "%", "_"]) expect((await page({ client: evil })).total, evil).toBe(0);
      expect((await page({ from: "2026-01-12", to: "2026-01-10" })).total).toBe(0); // inverted window is empty, not an error
    });

    it("the audit table survives all of that untouched", () => {
      expect((s.srv.db().prepare("SELECT COUNT(*) n FROM audit_events").get() as any).n).toBe(123);
    });
  });

  describe("exports", () => {
    it("export.jsonl streams every matching event (not just one page), oldest first, with download headers", async () => {
      const r = await s.admin.get("/api/audit/export.jsonl");
      expect(r.status).toBe(200);
      expect(r.headers.get("content-type")).toMatch(/^application\/(x-ndjson|jsonl|json)/);
      expect(r.headers.get("content-disposition")).toMatch(/^attachment;\s*filename="?audit\.jsonl"?/);
      expect(r.headers.get("cache-control")).toMatch(/no-store/);
      const lines = (await r.text()).split("\n").filter(Boolean);
      expect(lines).toHaveLength(123);
      const ev = lines.map((l) => JSON.parse(l) as AuditEvent);
      expect(ev.map((e) => e.id)).toEqual([...seed].sort((a, b) => (a.ts < b.ts ? -1 : 1)).map((x) => x.id));
      for (const e of ev) {
        for (const k of ["id", "ts", "requestId", "clientId", "mailboxId", "folder", "uidValidity", "uid", "uids", "uidsTruncated", "tool", "outcome", "errorCode", "cached", "reconciled", "durationMs"]) expect(e, k).toHaveProperty(k);
      }
    });

    it("export.jsonl honours the same filters as the list", async () => {
      const f = { outcome: "denied", client: "client-odd", from: "2026-01-10", to: "2026-01-11" };
      const r = await s.admin.get(`/api/audit/export.jsonl?${qs(f)}`);
      expect(r.status).toBe(200);
      const got = (await r.text()).split("\n").filter(Boolean).map((l) => JSON.parse(l).id);
      expect(got).toEqual(model(f).sort((a, b) => (a.ts < b.ts ? -1 : 1)).map((x) => x.id));
      expect(got.length).toBeGreaterThan(0);
      expect(got.length).toBeLessThan(123);
      const none = await s.admin.get(`/api/audit/export.jsonl?${qs({ client: "nobody" })}`);
      expect(none.status).toBe(200);
      expect((await none.text()).trim()).toBe("");
    });

    it("export.csv has a header row, one line per event, quoted JSON arrays, and neutralises spreadsheet formulas", async () => {
      s.srv.db().prepare("INSERT INTO audit_events (id, ts, request_id, client_id, tool, outcome) VALUES (?,?,?,?,?,?)").run("seed-formula", "2026-02-01T00:00:00.000Z", "req-formula", "client-even", "=HYPERLINK(\"http://evil.example\")", "ok");
      const r = await s.admin.get("/api/audit/export.csv");
      expect(r.status).toBe(200);
      expect(r.headers.get("content-type")).toMatch(/^text\/csv/);
      expect(r.headers.get("content-disposition")).toMatch(/^attachment;\s*filename="?audit\.csv"?/);
      expect(r.headers.get("cache-control")).toMatch(/no-store/);
      const text = await r.text();
      const lines = text.trim().split("\n");
      expect(lines[0].split(",")).toEqual(["id", "ts", "requestId", "clientId", "mailboxId", "folder", "uidValidity", "uid", "uids", "uidsTruncated", "tool", "outcome", "errorCode", "cached", "reconciled", "durationMs"]);
      expect(lines.length - 1).toBe(124);
      expect(text).toContain('"[2,3,4]"'); // uids as a JSON array cell (row i=1)
      expect(text).toContain("'=HYPERLINK"); // formula prefix defused
      expect(text).not.toMatch(/,=HYPERLINK/);
      s.srv.db().prepare("DELETE FROM audit_events WHERE id = 'seed-formula'").run();
    });

    it("exports many thousands of rows completely (streamed from the database, not capped at a page)", async () => {
      const db = s.srv.db();
      const ins = db.prepare("INSERT INTO audit_events (id, ts, request_id, client_id, tool, outcome) VALUES (?,?,?,?,?,?)");
      db.transaction(() => {
        for (let i = 0; i < 6000; i++) ins.run(`bulk-${String(i).padStart(5, "0")}`, new Date(BASE + 90 * 86_400_000 + i * 1000).toISOString(), "req-bulk-" + i, "client-bulk", "search_messages", "ok");
      })();
      const r = await s.admin.get(`/api/audit/export.jsonl?${qs({ client: "client-bulk" })}`);
      expect(r.status).toBe(200);
      const lines = (await r.text()).split("\n").filter(Boolean);
      expect(lines).toHaveLength(6000);
      expect(JSON.parse(lines[0]).id).toBe("bulk-00000");
      expect(JSON.parse(lines[5999]).id).toBe("bulk-05999");
      const list = await page({ client: "client-bulk" });
      expect(list.total).toBe(6000);
      expect(list.pages).toBe(120);
    });

    it("exports need the admin session", async () => {
      const anon = new Browser(s.base);
      for (const p of ["/api/audit/export.jsonl", "/api/audit/export.csv", "/api/audit"]) {
        const r = await anon.get(p);
        expect(r.status, p).toBe(401);
        expect((await errorOf(r)).code).toBeTruthy();
      }
    });
  });
});
