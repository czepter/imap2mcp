import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { openDatabase } from "../../server/core/db/database.js";
import { insertAuditEvent } from "../../server/core/audit/store.js";
import { exportLines } from "../../server/core/audit/export.js";
import { auditExportLines, auditFilterFrom, toAuditEventDto } from "../../server/utils/dto-audit";
import { toRuleDto, tokenReach } from "../../server/utils/dto-client";
import { parseMailboxBody, toMailboxDto } from "../../server/utils/dto-mailbox";
import { isoTs, parseGrantList, toClientSummary } from "../../server/utils/dto-common";

describe("tokenReach", () => {
  const mbs = [{ id: "m1", label: "Work" }, { id: "m2", label: "Home" }];
  const granted = new Map<string, Set<string>>([["c1:m1", new Set(["read", "draft", "organize"])], ["c1:m2", new Set(["organize"])]]);
  it("intersects the scope ceiling with live grants, per mailbox, in capability order", () => {
    expect(tokenReach("mail:organize mail:read", "c1", mbs, granted)).toEqual([
      { mailboxId: "m1", mailboxLabel: "Work", capabilities: ["read", "organize"] },
      { mailboxId: "m2", mailboxLabel: "Home", capabilities: ["organize"] },
    ]);
  });
  it("is empty when all grants are gone or the client has none", () => {
    expect(tokenReach("mail:read", "c1", mbs, granted).map((r) => r.mailboxId)).toEqual(["m1"]);
    expect(tokenReach("mail:read mail:draft", "c2", mbs, granted)).toEqual([]);
  });
});

describe("auditFilterFrom", () => {
  it("maps query params; a bare-date `to` is inclusive; junk is ignored", () => {
    const f = auditFilterFrom({ client: " c1 ", outcome: "denied", from: "2026-01-01", to: "2026-01-02", tool: ["x"], mailbox: "" });
    expect(f).toEqual({ clientId: "c1", outcome: "denied", from: "2026-01-01T00:00:00.000Z", to: "2026-01-03T00:00:00.000Z" });
    expect(auditFilterFrom({ outcome: "bogus", from: "nope", to: "2026-01-02T10:00:00Z" })).toEqual({ to: "2026-01-02T10:00:00.000Z" });
  });
});

describe("parseMailboxBody / parseGrantList", () => {
  it("trims, caps and accepts numeric or string ports", () => {
    expect(parseMailboxBody({ label: " L ", host: " h ", port: "993", username: " u ", password: " p " }))
      .toEqual({ label: "L", host: "h", port: 993, username: "u", password: " p " });
    expect(parseMailboxBody({ port: 143 }).port).toBe(143);
    expect(Number.isNaN(parseMailboxBody({}).port)).toBe(true);
  });
  it("drops malformed grants", () => {
    expect(parseGrantList([{ mailboxId: "m", capability: "read" }, { mailboxId: "m", capability: "send" }, null, { capability: "read" }]))
      .toEqual([{ mailboxId: "m", capability: "read" }]);
    expect(parseGrantList("x")).toEqual([]);
  });
});

describe("auditExportLines (chunked export)", () => {
  let h: ReturnType<typeof openDatabase>;
  beforeEach(() => {
    h = openDatabase(":memory:");
    // 7 events; several share one timestamp so the (ts, id) resume point is exercised
    for (let i = 0; i < 7; i++) {
      insertAuditEvent({ id: `id-${i}`, ts: `2026-01-01T00:00:0${i < 4 ? 0 : i}.000Z`, requestId: "req-12345678", clientId: "c", mailboxId: null, folder: null, uidValidity: null, tool: "t", outcome: "ok", errorCode: null, durationMs: 1 }, h.raw);
    }
  });
  afterEach(() => h.raw.close());
  it.each(["jsonl", "csv"] as const)("%s output equals exportLines for any chunk size", (format) => {
    const expected = [...exportLines(format, {}, h.raw)];
    for (const size of [1, 2, 3, 7, 8, 500]) {
      expect([...auditExportLines(format, {}, h.raw, size)].flat(), `chunk ${size}`).toEqual(expected);
    }
    expect([...auditExportLines(format, { from: "2026-01-01T00:00:05.000Z" }, h.raw, 1)].flat()).toEqual([...exportLines(format, { from: "2026-01-01T00:00:05.000Z" }, h.raw)]);
  });
  it("leaves no cursor open between chunks (writes keep working mid-export)", () => {
    const it = auditExportLines("jsonl", {}, h.raw, 2);
    it.next();
    expect(() => insertAuditEvent({ id: "late", requestId: "req-12345678", clientId: null, mailboxId: null, folder: null, uidValidity: null, tool: "t", outcome: "ok", errorCode: null, durationMs: 1 }, h.raw)).not.toThrow();
  });
  it("wire DTO drops the internal refs", () => {
    expect(toAuditEventDto({ id: "a", ts: "t", requestId: "r", clientId: null, mailboxId: null, folder: null, uidValidity: null, uid: null, uids: [1], refs: [{ folder: "F", uidValidity: 1, uids: [1] }] as any, uidsTruncated: false, tool: "x", outcome: "ok", errorCode: null, cached: false, reconciled: false, durationMs: 1 })).not.toHaveProperty("refs");
  });
});

describe("timestamps are ISO-8601 UTC in every DTO family", () => {
  const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
  it("isoTs", () => {
    expect(isoTs("2026-11-10 21:13:18")).toBe("2026-11-10T21:13:18.000Z");
    expect(isoTs("2026-11-10 21:13:18.5")).toBe("2026-11-10T21:13:18.500Z");
    expect(isoTs("2026-11-10T21:13:18.123Z")).toBe("2026-11-10T21:13:18.123Z");
    expect(isoTs(null)).toBeNull();
  });
  it("mailbox, client, rule, audit", () => {
    expect(toMailboxDto({ id: "m", label: "l", imap_host: "h", imap_port: 1, imap_username: "u", drafts_folder: null, created_at: "2026-11-10 21:13:18" }).createdAt).toMatch(ISO);
    expect(toClientSummary({ client_id: "c", client_name: null, redirect_uris: "[]", disabled: 0, created_at: "2026-11-10 21:13:18" }).createdAt).toMatch(ISO);
    expect(toRuleDto({ id: "r", client_id: "c", mailbox_id: "m", folder: "*", operation: "search", effect: "allow", created_at: "2026-11-10 21:13:18" }).createdAt).toMatch(ISO);
    expect(toAuditEventDto({ id: "a", ts: "2026-11-10 21:13:18", requestId: "r", clientId: null, mailboxId: null, folder: null, uidValidity: null, uid: null, uids: null, refs: null, uidsTruncated: false, tool: "x", outcome: "ok", errorCode: null, cached: false, reconciled: false, durationMs: 1 }).ts).toMatch(ISO);
  });
});
