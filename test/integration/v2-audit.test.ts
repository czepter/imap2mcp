/**
 * Version 2 acceptance criterion 4 (auditability), end to end: every tool attempt (allowed, denied incl. NOT_FOUND-masked
 * policy denials, cached, failed, unknown-outcome, reconciled) writes exactly ONE audit row with the right fields BEFORE the
 * result is returned; multi-message reads/searches store the exact returned UID set; bodies, headers, subjects, queries,
 * tokens and credentials never reach the DB or the exports (planted canaries); retention pruning; JSONL/CSV export (CLI and
 * admin UI); AUDIT_FAIL_MODE=closed blocks access when the audit table cannot be written, `open` keeps serving.
 */
import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import { randomBytes } from "node:crypto";
import { msg, sleep, type Stack } from "../helpers/stack.js";
import { Browser } from "../helpers/http.js";
import { allowAll, newClient, type Client, type Rule } from "../helpers/v1.js";
import {
  ALICE, auditCount, auditRows, canRunV2, createV2Stack, dbAll, dbExec, dbFileBytes, dbRun, expectNoLeak, expectStructuredError, isoMs,
  newAuditRows, rawToolCall, runAuditExport, until, uidsOf, writeCommands, type AuditRow,
} from "../helpers/v2.js";

vi.setConfig({ testTimeout: 120_000, hookTimeout: 120_000 });

const tag = randomBytes(5).toString("hex");
const CANARY = {
  subject: `CANARY-SUBJ-${tag}`,
  body: `CANARY-BODY-${tag}`,
  header: `CANARY-HDR-${tag}`,
  from: `canary-from-${tag}@leak.example`,
  query: `CANARY-QUERY-${tag}`,
  draftSubject: `CANARY-DRAFTSUBJ-${tag}`,
  draftBody: `CANARY-DRAFTBODY-${tag}`,
  draftTo: `canary-to-${tag}@leak.example`,
  folder: "Cold",
};
const uidSet = (r: AuditRow): number[] => [...new Set([...(r.uid !== null ? [r.uid] : []), ...uidsOf(r)])].sort((a, b) => a - b);

describe.skipIf(!canRunV2)("v2 audit trail (criterion 4)", () => {
  let s: Stack;
  let box: string;
  let A: Client;
  let B: Client;
  let uv: number;

  const one = async (fn: () => Promise<any>) => {
    const { result, rows } = await newAuditRows(s, fn);
    expect(rows, `exactly one audit row per attempt, got ${JSON.stringify(rows.map((r) => [r.tool, r.outcome]))}`).toHaveLength(1);
    return { r: result, row: rows[0] };
  };
  const mk = (subject: string, extra = "") =>
    `From: Canary <${CANARY.from}>\r\nTo: owner@example.test\r\nSubject: ${subject}\r\nX-Canary: ${CANARY.header}\r\nDate: Fri, 02 Jan 2026 03:04:05 +0000\r\nMessage-ID: <${randomBytes(6).toString("hex")}@example.org>\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n${CANARY.body} ${extra}\r\n`;

  beforeAll(async () => {
    s = await createV2Stack();
    box = s.mailbox[ALICE];
    for (let i = 0; i < 5; i++) s.fake.addMessage(ALICE, "INBOX", mk(`${CANARY.subject}-${i}`));
    s.fake.addFolder(ALICE, "Secret");
    s.fake.addMessage(ALICE, "Secret", mk(`${CANARY.subject}-secret`));
    s.fake.addFolder(ALICE, CANARY.folder);
    s.fake.addMessage(ALICE, CANARY.folder, mk(`${CANARY.subject}-cold`));
    uv = s.fake.folder(ALICE, "INBOX").uidValidity;
    A = await newClient(s, box, allowAll(), "audit-A");
    const readOnly: Rule[] = [...allowAll("*").filter(([, op]) => ["search", "read_headers", "read_body"].includes(op)),
      ["Secret", "search", "deny"], ["Secret", "read_headers", "deny"], ["Secret", "read_body", "deny"]];
    B = await newClient(s, box, readOnly, "audit-B");
  });
  afterAll(async () => {
    await A?.mcp.close();
    await B?.mcp.close();
    await s?.teardown();
  });

  describe("one row per attempt, with the right fields", () => {
    let inboxUids: number[];

    it("allowed multi-message search: outcome ok, mailbox/folder/UIDVALIDITY, the EXACT returned UID set (not the match total)", async () => {
      const { r, row } = await one(() => A.mcp.call("search_messages", { mailbox: box, folder: "INBOX", limit: 3 }));
      expect(r.isError, r.text).toBe(false);
      const returned: number[] = r.data.messages.map((m: any) => m.ref.uid);
      expect(returned).toHaveLength(3);
      expect(r.data.total).toBeGreaterThan(3);
      expect(row).toMatchObject({ tool: "search_messages", outcome: "ok", client_id: A.clientId, mailbox_id: box, folder: "INBOX", uid_validity: uv, error_code: null, uids_truncated: 0 });
      expect(uidSet(row)).toEqual([...returned].sort((a, b) => a - b));
      expect(row.ts).toMatch(isoMs);
      expect(Math.abs(Date.now() - Date.parse(row.ts))).toBeLessThan(60_000);
      expect(row.request_id).toMatch(/^[A-Za-z0-9_-]{8,64}$/);
      expect(Number.isInteger(row.duration_ms) && row.duration_ms! >= 0).toBe(true);
      inboxUids = returned;
    });

    it("cached: a repeat of a warm search is recorded as cached, and still lists the exact UID set", async () => {
      await A.mcp.call("search_messages", { mailbox: box, folder: "INBOX", limit: 3 });
      const { r, row } = await one(() => A.mcp.call("search_messages", { mailbox: box, folder: "INBOX", limit: 3 }));
      expect(r.isError).toBe(false);
      expect(row.outcome).toBe("ok");
      expect(row.cached, "served from the sidecar cache").toBe(1);
      expect(uidSet(row)).toEqual([...inboxUids].sort((a, b) => a - b));
    });

    it("single-message read: uid + uidValidity, and bodies are not cached so cached=0", async () => {
      const ref = { mailbox: box, folder: "INBOX", uidValidity: uv, uid: inboxUids[0] };
      const { r, row } = await one(() => A.mcp.call("read_message", { ref }));
      expect(r.isError, r.text).toBe(false);
      expect(row).toMatchObject({ tool: "read_message", outcome: "ok", client_id: A.clientId, mailbox_id: box, folder: "INBOX", uid_validity: uv, error_code: null });
      expect(uidSet(row)).toEqual([ref.uid]);
      expect(row.cached).toBe(0);
    });

    it("list tools are audited too (mailbox-level, no folder or UID)", async () => {
      const a = await one(() => A.mcp.call("list_mailboxes"));
      expect(a.row).toMatchObject({ tool: "list_mailboxes", outcome: "ok", client_id: A.clientId, uid: null, uids: null });
      const b = await one(() => A.mcp.call("list_folders", { mailbox: box }));
      expect(b.row).toMatchObject({ tool: "list_folders", outcome: "ok", mailbox_id: box });
    });

    it("set_flags on three messages: exactly those three UIDs", async () => {
      const refs = inboxUids.map((uid) => ({ mailbox: box, folder: "INBOX", uidValidity: uv, uid }));
      const { r, row } = await one(() => A.mcp.call("set_flags", { refs, add: ["\\Flagged"] }));
      expect(r.isError, r.text).toBe(false);
      expect(row).toMatchObject({ tool: "set_flags", outcome: "ok", mailbox_id: box, folder: "INBOX", uid_validity: uv });
      expect(uidSet(row)).toEqual([...inboxUids].sort((a, b) => a - b));
    });

    it("denied by missing capability: FORBIDDEN => outcome denied, nothing reached the server", async () => {
      s.fake.clearLog();
      const ref = { mailbox: box, folder: "INBOX", uidValidity: uv, uid: inboxUids[0] };
      const { r, row } = await one(() => B.mcp.call("set_flags", { refs: [ref], add: ["\\Seen"] }));
      expectStructuredError(r, "FORBIDDEN");
      expect(row).toMatchObject({ tool: "set_flags", outcome: "denied", error_code: "FORBIDDEN", client_id: B.clientId });
      expect(writeCommands(s.fake)).toEqual([]);
    });

    it("denied by folder policy answers NOT_FOUND to the client but is recorded as denied (the owner sees the truth)", async () => {
      s.fake.clearLog();
      const { r, row } = await one(() => B.mcp.call("search_messages", { mailbox: box, folder: "Secret" }));
      expectStructuredError(r, "NOT_FOUND");
      expect(row).toMatchObject({ tool: "search_messages", outcome: "denied", error_code: "NOT_FOUND", client_id: B.clientId });
      expect(row.folder === null || row.folder === "Secret").toBe(true);
      const rd = await one(() => B.mcp.call("read_message", { ref: { mailbox: box, folder: "Secret", uidValidity: s.fake.folder(ALICE, "Secret").uidValidity, uid: 1 } }));
      expect(rd.row).toMatchObject({ tool: "read_message", outcome: "denied", error_code: "NOT_FOUND" });
      expect(s.fake.commands.filter((x) => x.selected === "Secret" || /Secret/.test(x.line))).toHaveLength(0);
    });

    it("a genuinely missing message is NOT_FOUND but a failure, not a policy denial", async () => {
      const { r, row } = await one(() => A.mcp.call("read_message", { ref: { mailbox: box, folder: "INBOX", uidValidity: uv, uid: 99999 } }));
      expectStructuredError(r, ["NOT_FOUND"]);
      expect(row).toMatchObject({ outcome: "failed", error_code: "NOT_FOUND" });
    });

    it("denied: unknown mailbox id is indistinguishable from no access (FORBIDDEN, denied)", async () => {
      const { r, row } = await one(() => A.mcp.call("list_folders", { mailbox: "no-such-mailbox" }));
      expectStructuredError(r, "FORBIDDEN");
      expect(row).toMatchObject({ outcome: "denied", error_code: "FORBIDDEN", tool: "list_folders" });
    });

    it("failed: validation error and an unavailable folder are 'failed' with the tool error code", async () => {
      const ref = { mailbox: box, folder: "INBOX", uidValidity: uv, uid: inboxUids[0] };
      const v = await one(() => A.mcp.call("set_flags", { refs: [ref], add: ["\\Deleted"] }));
      expectStructuredError(v.r, "INVALID_INPUT");
      expect(v.row).toMatchObject({ outcome: "failed", error_code: "INVALID_INPUT" });
      const h = s.fake.inject(/^(SELECT|EXAMINE) "?Cold"?/i, { kind: "reply", text: "NO [UNAVAILABLE] try later" }, Infinity);
      const u = await one(() => A.mcp.call("search_messages", { mailbox: box, folder: CANARY.folder }));
      h.remove();
      expectStructuredError(u.r, "FOLDER_UNAVAILABLE");
      expect(u.row).toMatchObject({ outcome: "failed", error_code: "FOLDER_UNAVAILABLE", folder: CANARY.folder, mailbox_id: box });
    });

    it("unknown_outcome: an ambiguous APPEND is recorded as unknown_outcome; a reconciled one as ok + reconciled=1; one row each", async () => {
      s.fake.inject(/^APPEND /i, { kind: "drop" });
      const lost = await one(() => A.mcp.call("create_draft", { mailbox: box, subject: CANARY.draftSubject, body: CANARY.draftBody, to: [CANARY.draftTo] }));
      expectStructuredError(lost.r, "UNKNOWN_OUTCOME");
      expect(lost.row).toMatchObject({ tool: "create_draft", outcome: "unknown_outcome", error_code: "UNKNOWN_OUTCOME", client_id: A.clientId, mailbox_id: box });
      s.fake.inject(/^APPEND /i, { kind: "drop-after-apply" });
      const rec = await one(() => A.mcp.call("create_draft", { mailbox: box, subject: CANARY.draftSubject, body: CANARY.draftBody, to: [CANARY.draftTo] }));
      expect(rec.r.isError, rec.r.text).toBe(false);
      expect(rec.row).toMatchObject({ tool: "create_draft", outcome: "ok", reconciled: 1, error_code: null });
      expect(rec.row.folder).toBe("Drafts");
      expect(uidSet(rec.row)).toEqual([rec.r.data.ref.uid]);
      const okd = await one(() => A.mcp.call("create_draft", { mailbox: box, subject: CANARY.draftSubject, body: CANARY.draftBody, to: [CANARY.draftTo] }));
      expect(okd.row).toMatchObject({ outcome: "ok", reconciled: 0 });
    });

    it("the audited request id is the one returned to the client (header and error payload)", async () => {
      const mine = "audit-" + randomBytes(6).toString("hex");
      const before = new Set(auditRows(s).map((r) => r.id));
      const raw = await rawToolCall(s.base, A.token, "search_messages", { mailbox: box, folder: "Nope" }, { "x-request-id": mine });
      const rows = auditRows(s).filter((r) => !before.has(r.id));
      expect(rows).toHaveLength(1);
      expect(raw.requestId).toBe(mine);
      expect(raw.data.requestId).toBe(mine);
      expect(rows[0].request_id).toBe(mine);
    });

    it("pre-tool authentication failures (bad / missing token) are not tool attempts: 401 and no audit row", async () => {
      const n = auditCount(s);
      const bad = await rawToolCall(s.base, "not-a-real-token", "list_mailboxes");
      expect(bad.status).toBe(401);
      const none = await fetch(`${s.base}/mcp`, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream" }, body: "{}" });
      expect(none.status).toBe(401);
      expect(auditCount(s)).toBe(n);
    });

    it("the audit table has exactly the contract columns (no free-text column to leak into)", () => {
      const cols = dbAll<{ name: string }>(s, "PRAGMA table_info(audit_events)").map((c) => c.name).sort();
      expect(cols).toEqual(["cached", "client_id", "duration_ms", "error_code", "folder", "id", "mailbox_id", "outcome", "reconciled", "request_id", "tool", "ts", "uid", "uid_validity", "uids", "uids_truncated"].sort());
    });
  });

  describe("no content in the trail", () => {
    it("planted canaries (subject, body, header, address, search text, draft content, folder-less secrets) are absent from every row, the DB file and the exports", async () => {
      // make sure queries with canary text and full reads have happened
      await A.mcp.call("search_messages", { mailbox: box, folder: "INBOX", text: CANARY.query });
      await A.mcp.call("search_messages", { mailbox: box, folder: "INBOX", subject: CANARY.subject, from: CANARY.from });
      const first = (await A.mcp.call("search_messages", { mailbox: box, folder: "INBOX", limit: 2 })).data.messages[0];
      const rd = await A.mcp.call("read_message", { ref: first.ref });
      expect(rd.data.body).toContain(CANARY.body);

      const needles = [CANARY.subject, CANARY.body, CANARY.header, CANARY.from, CANARY.query, CANARY.draftSubject, CANARY.draftBody, CANARY.draftTo, "X-Canary", "leak.example"];
      const secrets = [...Object.values(s.imapPasswords), A.token, B.token, s.work.keyHex, s.work.sessionSecret, s.adminPassword];

      const rows = auditRows(s);
      expect(rows.length).toBeGreaterThan(10);
      expectNoLeak(JSON.stringify(rows), [...needles, ...secrets], "audit_events rows");

      const file = dbFileBytes(s);
      expectNoLeak(file, [...needles, ...secrets], "bridge.db (+WAL)");

      const jsonl = await runAuditExport(s, ["--format", "jsonl"]);
      expect(jsonl.code, jsonl.stderr).toBe(0);
      expectNoLeak(jsonl.stdout, [...needles, ...secrets], "JSONL export");
      const csv = await runAuditExport(s, ["--format", "csv"]);
      expect(csv.code, csv.stderr).toBe(0);
      expectNoLeak(csv.stdout, [...needles, ...secrets], "CSV export");

      const page = await (await s.admin.get("/api/audit")).text();
      expectNoLeak(page, [...needles, ...secrets], "/api/audit response");
      for (const f of ["jsonl", "csv"]) expectNoLeak(await (await s.admin.get(`/api/audit/export.${f}`)).text(), [...needles, ...secrets], `/api/audit/export.${f} response`);
      expectNoLeak(s.srv.output(), secrets, "server log");
    });
  });

  describe("export", () => {
    it("CLI JSONL: every event with documented fields, ISO-UTC ms timestamps; from is inclusive, to exclusive; matches the DB", async () => {
      const rows = auditRows(s);
      const all = await runAuditExport(s, ["--format", "jsonl"]);
      expect(all.code, all.stderr).toBe(0);
      const ev = all.stdout.trim().split("\n").map((l) => JSON.parse(l));
      expect(ev).toHaveLength(rows.length);
      expect(new Set(ev.map((e) => e.id))).toEqual(new Set(rows.map((r) => r.id)));
      for (const e of ev) {
        expect(e.ts).toMatch(isoMs);
        expect(["ok", "denied", "failed", "unknown_outcome"]).toContain(e.outcome);
        for (const k of ["requestId", "clientId", "mailboxId", "folder", "uidValidity", "tool", "outcome"]) expect(e, k).toHaveProperty(k);
      }
      const lo = rows[3].ts;
      const hi = rows[Math.min(8, rows.length - 1)].ts;
      const part = await runAuditExport(s, ["--format", "jsonl", "--from", lo, "--to", hi]);
      const got = part.stdout.trim().split("\n").filter(Boolean).map((l) => JSON.parse(l).id);
      expect(new Set(got)).toEqual(new Set(rows.filter((r) => r.ts >= lo && r.ts < hi).map((r) => r.id)));
      const denied = await runAuditExport(s, ["--format", "jsonl", "--outcome", "denied"]);
      const dn = denied.stdout.trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));
      expect(dn.length).toBe(rows.filter((r) => r.outcome === "denied").length);
      expect(dn.every((e) => e.outcome === "denied")).toBe(true);
    });

    it("CLI CSV: header + one line per event, uids as a JSON array cell", async () => {
      const rows = auditRows(s);
      const r = await runAuditExport(s, ["--format", "csv"]);
      expect(r.code, r.stderr).toBe(0);
      const lines = r.stdout.trim().split("\n");
      expect(lines[0].split(",")).toEqual(expect.arrayContaining(["id", "ts", "requestId", "clientId", "mailboxId", "folder", "uidValidity", "uid", "uids", "tool", "outcome", "errorCode", "cached", "reconciled"]));
      expect(lines.length - 1).toBe(rows.length);
      expect(r.stdout).toContain('"[');
    });

    it("CLI rejects bad input cleanly", async () => {
      const r = await runAuditExport(s, ["--format", "xml"]);
      expect(r.code).not.toBe(0);
      expect(r.stderr).toMatch(/format/i);
    });

    it("admin API: /api/audit lists events, filters by outcome, downloads JSONL and CSV; anonymous users get nothing", async () => {
      const page = await s.admin.get("/api/audit");
      expect(page.status).toBe(200);
      const body = (await page.json()) as any;
      expect(body.events.some((e: any) => e.tool === "search_messages")).toBe(true);
      expect(body.events.some((e: any) => e.outcome === "denied")).toBe(true);
      expect(body.total).toBe(auditCount(s));
      const filtered = (await (await s.admin.get("/api/audit?outcome=unknown_outcome")).json()) as any;
      expect(filtered.events.length).toBeGreaterThan(0);
      expect(filtered.events.every((e: any) => e.outcome === "unknown_outcome")).toBe(true);
      expect(filtered.events.some((e: any) => e.tool === "create_draft")).toBe(true);
      expect(filtered.events.some((e: any) => e.tool === "list_folders")).toBe(false);
      const j = await s.admin.get("/api/audit/export.jsonl?outcome=denied");
      expect(j.status).toBe(200);
      expect(j.headers.get("content-disposition")).toMatch(/attachment/);
      const jl = (await j.text()).trim().split("\n").map((l) => JSON.parse(l));
      expect(jl.length).toBe(auditRows(s).filter((r) => r.outcome === "denied").length);
      const c = await s.admin.get("/api/audit/export.csv");
      expect(c.status).toBe(200);
      expect((await c.text()).trim().split("\n").length).toBe(auditCount(s) + 1);
      const anon = new Browser(s.base);
      for (const p of ["/api/audit", "/api/audit/export.jsonl", "/api/audit/export.csv"]) {
        const r = await anon.get(p);
        expect(r.status, p).toBe(401);
        expect(await r.text()).not.toContain("search_messages");
      }
    });
  });

  describe("retention", () => {
    const old = (daysAgo: number, id: string) => {
      dbRun(s, "INSERT INTO audit_events (id, ts, request_id, client_id, tool, outcome) VALUES (?, ?, ?, ?, 'search_messages', 'ok')",
        id, new Date(Date.now() - daysAgo * 86_400_000).toISOString(), "retention-" + id, A.clientId);
    };
    const ids = () => new Set(auditRows(s).map((r) => r.id));

    it("AUDIT_RETENTION_DAYS=30 prunes older rows at startup and keeps newer ones", async () => {
      old(100, "ret-100"); old(40, "ret-40"); old(5, "ret-5");
      const recent = auditCount(s) - 3;
      await s.restart({ AUDIT_RETENTION_DAYS: "30" });
      const left = ids();
      expect(left.has("ret-100")).toBe(false);
      expect(left.has("ret-40")).toBe(false);
      expect(left.has("ret-5")).toBe(true);
      expect(auditCount(s)).toBe(recent + 1);
    });

    it("AUDIT_RETENTION_DAYS=0 keeps everything forever", async () => {
      old(900, "ret-900");
      await s.restart({ AUDIT_RETENTION_DAYS: "0" });
      expect(ids().has("ret-900")).toBe(true);
    });

    it("default retention is 90 days", async () => {
      old(120, "ret-120"); old(60, "ret-60");
      await s.restart({ AUDIT_RETENTION_DAYS: undefined });
      const left = ids();
      expect(left.has("ret-120")).toBe(false);
      expect(left.has("ret-900")).toBe(false);
      expect(left.has("ret-60")).toBe(true);
    });
  });

  describe("fail-closed / fail-open", () => {
    const refOf = (uid: number) => ({ mailbox: box, folder: "INBOX", uidValidity: uv, uid });
    let uid: number;
    beforeAll(async () => {
      const r = await A.mcp.call("search_messages", { mailbox: box, folder: "INBOX", limit: 1 });
      expect(r.isError, r.text).toBe(false);
      uid = r.data.messages[0].ref.uid;
    });
    const block = () => dbExec(s, "CREATE TRIGGER IF NOT EXISTS audit_block BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT, 'disk full'); END;");
    const unblock = () => dbExec(s, "DROP TRIGGER IF EXISTS audit_block;");

    it("default mode is closed: an unwritable audit table fails reads with UNAVAILABLE and returns no data", async () => {
      block();
      try {
        const n = auditCount(s);
        const r = await A.mcp.call("search_messages", { mailbox: box, folder: "INBOX" });
        expectStructuredError(r, "UNAVAILABLE");
        expectNoLeak(r.text, [CANARY.subject, CANARY.from, ALICE], "closed-mode error");
        const rd = await A.mcp.call("read_message", { ref: refOf(uid) });
        expectStructuredError(rd, "UNAVAILABLE");
        expect(rd.text).not.toContain(CANARY.body);
        expect(auditCount(s)).toBe(n);
        expect(s.srv.proc.exitCode).toBeNull();
      } finally { unblock(); }
    });

    it("closed mode never starts a write it cannot audit: no APPEND / MOVE / STORE reaches the server", async () => {
      block();
      try {
        s.fake.clearLog();
        const d = await A.mcp.call("create_draft", { mailbox: box, subject: "s", body: "b", to: ["x@example.org"] });
        expectStructuredError(d, "UNAVAILABLE");
        const m = await A.mcp.call("move_message", { ref: refOf(uid), destination: "Archive" });
        expectStructuredError(m, "UNAVAILABLE");
        const f = await A.mcp.call("set_flags", { refs: [refOf(uid)], add: ["\\Seen"] });
        expectStructuredError(f, "UNAVAILABLE");
        await sleep(300);
        expect(writeCommands(s.fake), "writes that reached the server").toEqual([]);
      } finally { unblock(); }
    });

    it("service resumes by itself once the audit table is writable again", async () => {
      const r = await one(() => A.mcp.call("search_messages", { mailbox: box, folder: "INBOX", limit: 1 }));
      expect(r.r.isError, r.r.text).toBe(false);
    });

    it("AUDIT_FAIL_MODE=open keeps serving (logging the audit failure) instead of blocking access", async () => {
      block();
      try {
        await s.restart({ AUDIT_FAIL_MODE: "open", AUDIT_RETENTION_DAYS: "0" });
        const n = auditCount(s);
        const r = await A.mcp.call("search_messages", { mailbox: box, folder: "INBOX", limit: 1 });
        expect(r.isError, r.text).toBe(false);
        expect(r.data.messages).toHaveLength(1);
        expect(auditCount(s)).toBe(n);
        await until(() => /audit/i.test(s.srv.output().split("\n").filter((l) => /write_failed|unavailable|failed/i.test(l)).join("\n")), 5_000, "audit failure logged");
        expect(s.srv.proc.exitCode).toBeNull();
      } finally { unblock(); }
      await s.restart({ AUDIT_FAIL_MODE: undefined });
    });
  });
});
