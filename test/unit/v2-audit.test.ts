import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { openDatabase } from "../../server/core/db/database.js";
import { auditNote } from "../../server/core/audit/context.js";
import { withAudit, setAuditDb, classifyResult, auditFailMode } from "../../server/core/audit/withAudit.js";
import { insertAuditEvent, queryAudit, countAudit, MAX_AUDIT_UIDS } from "../../server/core/audit/store.js";
import { pruneAudit, retentionDays } from "../../server/core/audit/retention.js";
import { csvCell, exportLines } from "../../server/core/audit/export.js";
import { resolveRequestId } from "../../server/core/security/requestId.js";
import { errorResult, ToolError, okResult } from "../../server/core/mcp/errors.js";

let h: ReturnType<typeof openDatabase>;
beforeEach(() => { h = openDatabase(":memory:"); setAuditDb(() => h.raw); delete process.env.AUDIT_FAIL_MODE; });
afterEach(() => { setAuditDb(undefined); h.raw.close(); delete process.env.AUDIT_FAIL_MODE; });

const RID = "req-12345678";
const run = (tool: string, fn: () => Promise<any>, args: unknown = {}, mutating = false) =>
  withAudit({ tool, clientId: "client-1", requestId: RID, mutating }, args, fn);
const rows = () => queryAudit({}, { limit: 1000 }, h.raw);

describe("migration 0002", () => {
  it("creates audit_events and mailbox status columns", () => {
    const cols = (h.raw.prepare("PRAGMA table_info(mailboxes)").all() as any[]).map((c) => c.name);
    expect(cols).toEqual(expect.arrayContaining(["status", "last_error_code", "last_ok_at", "next_retry_at"]));
    const a = (h.raw.prepare("PRAGMA table_info(audit_events)").all() as any[]).map((c) => c.name);
    expect(a).toEqual(["id", "ts", "request_id", "client_id", "mailbox_id", "folder", "uid_validity", "uid", "uids", "uids_truncated", "tool", "outcome", "error_code", "cached", "reconciled", "duration_ms"]);
  });
  it("rejects invalid outcomes", () => {
    expect(() => h.raw.prepare("INSERT INTO audit_events (id,ts,request_id,tool,outcome) VALUES ('a','t','r','x','bogus')").run()).toThrow();
  });
});

describe("withAudit: one row per attempt, classification", () => {
  it("ok with notes, cached and duration", async () => {
    const r = await run("read_message", async () => {
      auditNote({ mailboxId: "mb1", folder: "INBOX", uidValidity: 7, uids: [42], cached: true });
      return okResult({ x: 1 });
    });
    expect(r.isError).toBeUndefined();
    const [e] = rows();
    expect(rows()).toHaveLength(1);
    expect(e).toMatchObject({ tool: "read_message", outcome: "ok", clientId: "client-1", requestId: RID, mailboxId: "mb1", folder: "INBOX", uidValidity: 7, uid: 42, uids: null, cached: true, errorCode: null });
    expect(e.durationMs).toBeGreaterThanOrEqual(0);
    expect(e.ts).toMatch(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/);
  });

  it("FORBIDDEN is denied; a bare NOT_FOUND is a genuine miss (failed); others failed; UNKNOWN_OUTCOME separate", async () => {
    const codes: [string, string][] = [["FORBIDDEN", "denied"], ["NOT_FOUND", "failed"], ["UPSTREAM_ERROR", "failed"], ["INVALID_INPUT", "failed"], ["TIMEOUT", "failed"], ["UNKNOWN_OUTCOME", "unknown_outcome"]];
    for (const [c] of codes) await run("move_message", async () => errorResult(new ToolError(c as any, "m")), {}, true);
    expect(rows().map((r) => [r.errorCode, r.outcome]).sort()).toEqual([...codes].sort());
  });

  it("NOT_FOUND is denied only when the tool marked the policy mask (note.denied === true)", () => {
    expect(classifyResult(errorResult(new ToolError("NOT_FOUND", "x")), { denied: true }).outcome).toBe("denied");
    expect(classifyResult(errorResult(new ToolError("NOT_FOUND", "x")), {}).outcome).toBe("failed");
    expect(classifyResult(errorResult(new ToolError("NOT_FOUND", "x")), { denied: false } as any).outcome).toBe("failed");
  });

  it("stores per-folder refs for multi-folder results; uids is the flat union", async () => {
    await run("search_messages", async () => {
      auditNote({ mailboxId: "m", refs: [{ folder: "INBOX", uidValidity: 1, uids: [1, 2] }, { folder: "Sent", uidValidity: 5, uids: [9] }] });
      return okResult({});
    });
    expect(rows()[0]).toMatchObject({ folder: null, uids: [1, 2, 9], refs: [{ folder: "INBOX", uidValidity: 1, uids: [1, 2] }, { folder: "Sent", uidValidity: 5, uids: [9] }] });
  });

  it("a throwing tool still writes exactly one failed row", async () => {
    const r = await run("search_messages", async () => { throw new Error("boom with secret-host.example"); });
    expect(r.isError).toBe(true);
    expect(JSON.stringify(r)).not.toContain("secret-host");
    expect(rows()).toHaveLength(1);
    expect(rows()[0].outcome).toBe("failed");
  });

  it("injects requestId into error payloads", async () => {
    const r = await run("read_message", async () => ({ isError: true, content: [{ type: "text" as const, text: JSON.stringify({ code: "UPSTREAM_ERROR", message: "x" }) }] }));
    expect(JSON.parse(r.content[0].text).requestId).toBe(RID);
  });

  it("falls back to argument identifiers when the tool noted nothing (denied path)", async () => {
    await run("read_message", async () => errorResult(new ToolError("FORBIDDEN", "x")), { ref: { mailbox: "m9", folder: "Secret", uidValidity: 3, uid: 5 }, include: ["body"] });
    expect(rows()[0]).toMatchObject({ outcome: "denied", mailboxId: "m9", folder: "Secret", uidValidity: 3, uid: 5 });
  });

  it("records reconciled", async () => {
    await run("create_draft", async () => { auditNote({ mailboxId: "m", reconciled: true }); return okResult({}); }, {}, true);
    expect(rows()[0].reconciled).toBe(true);
  });
});

describe("uid sets and truncation", () => {
  it("stores the exact returned UID set", async () => {
    await run("search_messages", async () => { auditNote({ mailboxId: "m", folder: "INBOX", uidValidity: 1, uids: [5, 3, 9] }); auditNote({ uids: [11] }); return okResult({}); });
    expect(rows()[0]).toMatchObject({ uid: null, uids: [5, 3, 9, 11], uidsTruncated: false });
  });
  it("caps at 5000 and flags truncation", async () => {
    const all = Array.from({ length: MAX_AUDIT_UIDS + 10 }, (_, i) => i + 1);
    await run("search_messages", async () => { auditNote({ uids: all }); return okResult({}); });
    const e = rows()[0];
    expect(e.uids).toHaveLength(MAX_AUDIT_UIDS);
    expect(e.uids![MAX_AUDIT_UIDS - 1]).toBe(MAX_AUDIT_UIDS);
    expect(e.uidsTruncated).toBe(true);
  });
  it("exactly 5000 is not flagged", () => {
    insertAuditEvent({ requestId: RID, clientId: null, mailboxId: null, folder: null, uidValidity: null, tool: "t", outcome: "ok", errorCode: null, durationMs: 1, uids: Array.from({ length: MAX_AUDIT_UIDS }, (_, i) => i + 1) }, h.raw);
    expect(rows()[0].uidsTruncated).toBe(false);
  });
});

describe("AUDIT_FAIL_MODE", () => {
  const breakAudit = () => h.raw.exec("DROP TABLE audit_events");
  it("defaults to closed and invalid values are closed", () => {
    expect(auditFailMode({} as any)).toBe("closed");
    expect(auditFailMode({ AUDIT_FAIL_MODE: "weird" } as any)).toBe("closed");
    expect(auditFailMode({ AUDIT_FAIL_MODE: "open" } as any)).toBe("open");
  });
  it("closed: read returns UNAVAILABLE with no data and does not run the tool", async () => {
    breakAudit();
    let ran = false;
    const r = await run("read_message", async () => { ran = true; return okResult({ secret: "BODY" }); });
    expect(ran).toBe(false);
    const p = JSON.parse(r.content[0].text);
    expect(p.code).toBe("UNAVAILABLE");
    expect(p.requestId).toBe(RID);
    expect(JSON.stringify(r)).not.toContain("BODY");
  });
  it("closed: a write is never started when the store is down", async () => {
    breakAudit();
    let ran = false;
    const r = await run("create_draft", async () => { ran = true; return okResult({}); }, {}, true);
    expect(ran).toBe(false);
    expect(r.isError).toBe(true);
  });
  it("closed: a table that exists but rejects INSERTs blocks the write before it starts (pre-flight proves the insert)", async () => {
    h.raw.exec("CREATE TRIGGER no_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT, 'disk full'); END");
    let ran = false;
    const r = await run("move_message", async () => { ran = true; return okResult({}); }, {}, true);
    expect(ran).toBe(false);
    expect(JSON.parse(r.content[0].text).code).toBe("UNAVAILABLE");
    expect(h.raw.prepare("SELECT COUNT(*) n FROM audit_events").get()).toMatchObject({ n: 0 });
  });
  it("closed: the probe row never persists", async () => {
    await run("read_message", async () => okResult({}));
    expect(rows()).toHaveLength(1);
  });
  it("closed: insert failure after the call (preflight ok) yields UNAVAILABLE, no data", async () => {
    const r = await run("read_message", async () => {
      h.raw.exec("DROP TABLE audit_events"); // fails between preflight and insert
      return okResult({ secret: "BODY" });
    });
    expect(JSON.parse(r.content[0].text).code).toBe("UNAVAILABLE");
    expect(JSON.stringify(r)).not.toContain("BODY");
  });
  it("open: result is returned and the failure is only logged", async () => {
    process.env.AUDIT_FAIL_MODE = "open";
    breakAudit();
    const r = await run("read_message", async () => okResult({ fine: true }));
    expect(r.isError).toBeUndefined();
    expect(JSON.parse(r.content[0].text)).toEqual({ fine: true });
  });
});

describe("retention", () => {
  const ev = (ts: string) => insertAuditEvent({ ts, requestId: RID, clientId: "c", mailboxId: null, folder: null, uidValidity: null, tool: "t", outcome: "ok", errorCode: null, durationMs: 1 }, h.raw);
  it("prunes events older than N days and keeps newer", () => {
    const now = Date.parse("2026-06-01T00:00:00.000Z");
    ev("2026-01-01T00:00:00.000Z"); ev("2026-05-30T00:00:00.000Z");
    expect(pruneAudit(90, now, h.raw)).toBe(1);
    expect(countAudit({}, h.raw)).toBe(1);
  });
  it("0 keeps forever; env parsing defaults to 90", () => {
    ev("2000-01-01T00:00:00.000Z");
    expect(pruneAudit(0, Date.now(), h.raw)).toBe(0);
    expect(countAudit({}, h.raw)).toBe(1);
    expect(retentionDays({} as any)).toBe(90);
    expect(retentionDays({ AUDIT_RETENTION_DAYS: "0" } as any)).toBe(0);
    expect(retentionDays({ AUDIT_RETENTION_DAYS: "7" } as any)).toBe(7);
    expect(retentionDays({ AUDIT_RETENTION_DAYS: "-3" } as any)).toBe(90);
    expect(retentionDays({ AUDIT_RETENTION_DAYS: "abc" } as any)).toBe(90);
  });
});

describe("filters and export", () => {
  beforeEach(() => {
    const base = { requestId: RID, folder: "INBOX", uidValidity: 1, errorCode: null, durationMs: 1 };
    insertAuditEvent({ ...base, ts: "2026-01-01T00:00:00.000Z", clientId: "a", mailboxId: "m1", tool: "search_messages", outcome: "ok", uids: [1, 2] }, h.raw);
    insertAuditEvent({ ...base, ts: "2026-01-02T00:00:00.000Z", clientId: "b", mailboxId: "m2", tool: "read_message", outcome: "denied", uid: 3 }, h.raw);
    insertAuditEvent({ ...base, ts: "2026-01-03T00:00:00.000Z", clientId: "a", mailboxId: "m1", tool: "=cmd|' /C calc'!A0", outcome: "failed", folder: "=HYPERLINK(\"x\")" } as any, h.raw);
  });
  it("filters by client, mailbox, tool, outcome and time", () => {
    expect(queryAudit({ clientId: "a" }, {}, h.raw)).toHaveLength(2);
    expect(queryAudit({ mailboxId: "m2" }, {}, h.raw)).toHaveLength(1);
    expect(queryAudit({ tool: "read_message" }, {}, h.raw)).toHaveLength(1);
    expect(queryAudit({ outcome: "failed" }, {}, h.raw)).toHaveLength(1);
    expect(queryAudit({ from: "2026-01-02T00:00:00.000Z", to: "2026-01-03T00:00:00.000Z" }, {}, h.raw)).toHaveLength(1);
    expect(queryAudit({}, { limit: 2, offset: 2 }, h.raw)).toHaveLength(1);
  });
  it("JSONL: one parseable object per line, oldest first", () => {
    const lines = [...exportLines("jsonl", {}, h.raw)];
    expect(lines).toHaveLength(3);
    const o = lines.map((l) => JSON.parse(l));
    expect(o[0]).toMatchObject({ ts: "2026-01-01T00:00:00.000Z", uids: [1, 2], outcome: "ok", uidsTruncated: false });
    expect(o[1].uid).toBe(3);
  });
  it("CSV: header, quoting, formula neutralisation", () => {
    const lines = [...exportLines("csv", {}, h.raw)];
    expect(lines[0].split(",")).toContain("requestId");
    expect(lines).toHaveLength(4);
    expect(lines[1]).toContain('"[1,2]"');
    expect(lines[3]).toContain("'=HYPERLINK");
    expect(csvCell('a,"b"')).toBe('"a,""b"""');
    expect(csvCell(null)).toBe("");
  });
});

describe("no sensitive fields", () => {
  it("schema has no content/credential columns", () => {
    const cols = (h.raw.prepare("PRAGMA table_info(audit_events)").all() as any[]).map((c) => c.name.toLowerCase());
    for (const bad of ["body", "header", "subject", "from", "to", "address", "email", "token", "password", "secret", "text"]) {
      expect(cols.some((c) => c.split("_").includes(bad))).toBe(false);
    }
  });
  it("tool arguments and results never reach the row", async () => {
    await run("create_draft", async () => okResult({ body: "TOPSECRETBODY" }), {
      mailbox: "m1", to: ["victim@example.com"], subject: "SECRETSUBJECT", body: "TOPSECRETBODY", token: "tok_abc",
    }, true);
    await run("search_messages", async () => okResult({}), { mailbox: "m1", text: "needle@example.com", from: "boss@example.com", subject: "SECRETSUBJECT" });
    const dump = JSON.stringify(h.raw.prepare("SELECT * FROM audit_events").all());
    for (const s of ["TOPSECRETBODY", "victim@example.com", "SECRETSUBJECT", "needle@example.com", "boss@example.com", "tok_abc"]) expect(dump).not.toContain(s);
  });
});

describe("request id", () => {
  it("honors valid ids, replaces invalid ones", () => {
    expect(resolveRequestId("abc_DEF-1234")).toBe("abc_DEF-1234");
    expect(resolveRequestId("short")).not.toBe("short");
    expect(resolveRequestId("bad id with spaces!!")).toMatch(/^[0-9a-f-]{36}$/);
    expect(resolveRequestId("x".repeat(65))).toMatch(/^[0-9a-f-]{36}$/);
    expect(resolveRequestId(undefined)).toMatch(/^[0-9a-f-]{36}$/);
  });
});

describe("audit:export CLI", () => {
  it("exports a file database to JSONL", () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-cli-"));
    try {
      const f = openDatabase(join(dir, "bridge.db"));
      insertAuditEvent({ ts: "2026-02-01T00:00:00.000Z", requestId: RID, clientId: "c", mailboxId: "m", folder: "INBOX", uidValidity: 1, tool: "list_folders", outcome: "ok", errorCode: null, durationMs: 2 }, f.raw);
      insertAuditEvent({ ts: "2026-03-01T00:00:00.000Z", requestId: RID, clientId: "c", mailboxId: "m", folder: "INBOX", uidValidity: 1, tool: "list_folders", outcome: "ok", errorCode: null, durationMs: 2 }, f.raw);
      f.raw.pragma("wal_checkpoint(TRUNCATE)");
      f.raw.close();
      const r = spawnSync(process.execPath, ["--import", "tsx", "server/core/audit/cli.ts", "--from", "2026-02-15", "--format", "csv"], {
        env: { ...process.env, DATA_DIR: dir }, encoding: "utf8", cwd: process.cwd(),
      });
      expect(r.status).toBe(0);
      const lines = r.stdout.trim().split("\n");
      expect(lines).toHaveLength(2);
      expect(lines[1]).toContain("2026-03-01");
      const bad = spawnSync(process.execPath, ["--import", "tsx", "server/core/audit/cli.ts", "--format", "xml"], { env: { ...process.env, DATA_DIR: dir }, encoding: "utf8" });
      expect(bad.status).toBe(1);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
});
