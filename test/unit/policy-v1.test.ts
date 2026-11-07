import { describe, it, expect, beforeEach } from "vitest";
import Database from "better-sqlite3";
import { assertOp, isOpAllowed, filterAllowedFolders, anyAllowedMailboxes, assertAllowed, allowedMailboxes } from "../../src/policy/policy.js";
import { folderMatches, isValidSelector, OPERATIONS, type Operation } from "../../src/policy/rules.js";
import { PolicyError, type Capability, type TokenContext } from "../../src/types.js";

let db: Database.Database;
let n = 0;
const ALL: Capability[] = ["read", "draft", "organize"];
const ctx = (clientId = "c1", scopes: Capability[] = ALL): TokenContext => ({ tokenId: "t", clientId, scopes });
const rule = (folder: string, op: Operation, effect: "allow" | "deny", c = "c1", m = "m1") =>
  db.prepare("INSERT INTO policy_rules (id, client_id, mailbox_id, folder, operation, effect) VALUES (?,?,?,?,?,?)").run(`r${n++}`, c, m, folder, op, effect);

beforeEach(() => {
  db = new Database(":memory:");
  db.exec(`CREATE TABLE policy_rules (id TEXT PRIMARY KEY, client_id TEXT NOT NULL, mailbox_id TEXT NOT NULL, folder TEXT NOT NULL,
    operation TEXT NOT NULL, effect TEXT NOT NULL, UNIQUE (client_id, mailbox_id, folder, operation));`);
});
const ok = (f: string, op: Operation, c = ctx(), m = "m1") => isOpAllowed(c, m, f, op, db);

describe("glob matching", () => {
  it("supports exact, '*' and 'prefix/*' only", () => {
    expect(folderMatches("*", "anything/at/all")).toBe(true);
    expect(folderMatches("INBOX", "INBOX")).toBe(true);
    expect(folderMatches("INBOX", "INBOX/Sub")).toBe(false);
    expect(folderMatches("INBOX/*", "INBOX/Sub")).toBe(true);
    expect(folderMatches("INBOX/*", "INBOX/Sub/Deep")).toBe(true);
    expect(folderMatches("INBOX/*", "INBOX")).toBe(false);
    expect(folderMatches("INBOX/*", "INBOXX/a")).toBe(false);
    expect(folderMatches("INBOX", "inbox")).toBe(false); // case-sensitive
  });
  it("invalid selectors never match", () => {
    for (const bad of ["", "IN*BOX", "*/Sub", "**", "a/*/b", "/*", "INBOX*", "a\nb", "*.*"]) {
      expect(isValidSelector(bad), bad).toBe(false);
      expect(folderMatches(bad, "INBOX"), bad).toBe(false);
      expect(folderMatches(bad, "IN*BOX"), bad).toBe(false);
    }
    rule("IN*BOX", "search", "allow");
    expect(ok("INBOX", "search")).toBe(false);
    expect(ok("IN*BOX", "search")).toBe(false);
  });
});

describe("policy v1 evaluation", () => {
  it("defaults to deny, for every op", () => {
    for (const op of OPERATIONS) expect(ok("INBOX", op)).toBe(false);
    expect(anyAllowedMailboxes(ctx(), db)).toEqual([]);
  });
  it("deny beats allow regardless of specificity or order", () => {
    rule("*", "read_body", "allow");
    rule("Private/*", "read_body", "deny");
    rule("Private/Taxes", "read_body", "allow");
    expect(ok("INBOX", "read_body")).toBe(true);
    expect(ok("Private/Taxes", "read_body")).toBe(false);
    expect(ok("Private/Other", "read_body")).toBe(false);
    rule("INBOX", "read_body", "deny");
    expect(ok("INBOX", "read_body")).toBe(false);
  });
  it("operations are independent", () => {
    rule("INBOX", "search", "allow");
    expect(ok("INBOX", "search")).toBe(true);
    for (const op of OPERATIONS.filter((o) => o !== "search")) expect(ok("INBOX", op), op).toBe(false);
    expect(ok("Other", "search")).toBe(false);
  });
  it("is scoped per client and mailbox", () => {
    rule("*", "search", "allow");
    expect(ok("INBOX", "search", ctx("c2"))).toBe(false);
    expect(ok("INBOX", "search", ctx(), "m2")).toBe(false);
  });
  it("move is authorized per folder (source and destination are separate checks)", () => {
    rule("INBOX", "move", "allow");
    expect(ok("INBOX", "move")).toBe(true);
    expect(ok("Archive", "move")).toBe(false);
    expect(() => assertOp(ctx(), "m1", "Archive", "move", db)).toThrow(PolicyError);
  });
  it("token scopes are a ceiling", () => {
    rule("*", "search", "allow"); rule("*", "move", "allow"); rule("*", "draft", "allow");
    const narrow = ctx("c1", ["read"]);
    expect(ok("INBOX", "search", narrow)).toBe(true);
    expect(ok("INBOX", "move", narrow)).toBe(false);
    expect(ok("INBOX", "draft", narrow)).toBe(false);
    expect(() => assertOp(narrow, "m1", "INBOX", "flag", db)).toThrow(PolicyError);
    expect(anyAllowedMailboxes(ctx("c1", ["organize"]), db)).toEqual(["m1"]);
    expect(anyAllowedMailboxes(ctx("c1", []), db)).toEqual([]);
  });
  it("rule removal and addition apply on the very next call (no cache)", () => {
    rule("*", "read_headers", "allow");
    expect(ok("INBOX", "read_headers")).toBe(true);
    db.prepare("DELETE FROM policy_rules").run();
    expect(ok("INBOX", "read_headers")).toBe(false);
    rule("*", "read_headers", "allow");
    rule("INBOX", "read_headers", "deny");
    expect(ok("INBOX", "read_headers")).toBe(false);
  });
  it("rejects malformed input", () => {
    rule("*", "search", "allow");
    expect(ok("", "search")).toBe(false);
    expect(ok("INBOX", "search", ctx(), "")).toBe(false);
    expect(ok("INBOX", "bogus" as Operation)).toBe(false);
    expect(isOpAllowed({ tokenId: "t", clientId: "c1" } as unknown as TokenContext, "m1", "INBOX", "search", db)).toBe(false);
    expect(isOpAllowed(undefined as unknown as TokenContext, "m1", "INBOX", "search", db)).toBe(false);
  });
});

describe("leakage helpers", () => {
  const folders = ["INBOX", "Private", "Private/Taxes", "Work", "Work/Secret"];
  it("filterAllowedFolders returns only folders where any listed op is allowed, order preserved", () => {
    rule("*", "search", "allow");
    rule("Private/*", "search", "deny");
    rule("Work/Secret", "search", "deny");
    rule("Private", "read_headers", "allow");
    expect(filterAllowedFolders(ctx(), "m1", ["search"], folders, db)).toEqual(["INBOX", "Private", "Work"]);
    expect(filterAllowedFolders(ctx(), "m1", ["search", "read_headers"], folders, db)).toEqual(["INBOX", "Private", "Work"]);
    expect(filterAllowedFolders(ctx(), "m1", ["read_body"], folders, db)).toEqual([]);
  });
  it("folder discovery for organize/draft-only clients is empty when only read ops are listed", () => {
    rule("*", "move", "allow"); rule("*", "flag", "allow"); rule("*", "draft", "allow");
    expect(filterAllowedFolders(ctx(), "m1", ["search", "read_headers", "read_body"], folders, db)).toEqual([]);
  });
  it("filterAllowedFolders respects the token ceiling and malformed input", () => {
    rule("*", "search", "allow");
    expect(filterAllowedFolders(ctx("c1", ["draft"]), "m1", ["search"], folders, db)).toEqual([]);
    expect(filterAllowedFolders(ctx(), "", ["search"], folders, db)).toEqual([]);
    expect(filterAllowedFolders(ctx(), "m1", [], folders, db)).toEqual([]);
    expect(filterAllowedFolders(ctx(), "m1", ["search"], ["", "INBOX"], db)).toEqual(["INBOX"]);
  });
  it("anyAllowedMailboxes ignores deny-only mailboxes and invalid selectors", () => {
    rule("*", "search", "deny", "c1", "m1");
    rule("IN*", "search", "allow", "c1", "m2");
    rule("INBOX", "flag", "allow", "c1", "m3");
    expect(anyAllowedMailboxes(ctx(), db)).toEqual(["m3"]);
  });
});

describe("v0 shims", () => {
  it("allowed iff allow on '*' for ALL ops of the capability and no deny", () => {
    rule("*", "search", "allow"); rule("*", "read_headers", "allow");
    const allowed = () => { try { assertAllowed(ctx(), "m1", "read", db); return true; } catch { return false; } };
    expect(allowed()).toBe(false); // read_body missing
    rule("*", "read_body", "allow");
    expect(allowed()).toBe(true);
    expect(allowedMailboxes(ctx(), "read", db)).toEqual(["m1"]);
    rule("Private", "read_body", "deny");
    expect(allowed()).toBe(false);
    expect(allowedMailboxes(ctx(), "read", db)).toEqual([]);
  });
  it("folder-restricted allows do not satisfy the shim", () => {
    rule("INBOX", "draft", "allow");
    expect(() => assertAllowed(ctx(), "m1", "draft", db)).toThrow(PolicyError);
    expect(allowedMailboxes(ctx(), "draft", db)).toEqual([]);
  });
});
