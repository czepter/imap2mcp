import { describe, it, expect, beforeEach } from "vitest";
import Database from "better-sqlite3";
import { assertAllowed, allowedMailboxes, anyAllowedMailboxes } from "../../src/policy/policy.js";
import { PolicyError, type Capability, type TokenContext } from "../../src/types.js";

const CAPS: Capability[] = ["read", "draft", "organize"];
let db: Database.Database;

function ctx(clientId: string, scopes: Capability[] = CAPS): TokenContext {
  return { tokenId: "t1", clientId, scopes };
}
function grant(c: string, m: string, cap: Capability) {
  db.prepare("INSERT INTO grants (client_id, mailbox_id, capability) VALUES (?,?,?)").run(c, m, cap);
}
function allowed(c: TokenContext, m: string, cap: Capability): boolean {
  try { assertAllowed(c, m, cap, db); return true; } catch (e) {
    expect(e).toBeInstanceOf(PolicyError);
    expect((e as PolicyError).code).toBe("FORBIDDEN");
    return false;
  }
}

beforeEach(() => {
  db = new Database(":memory:");
  db.exec(`
    CREATE TABLE grants (client_id TEXT NOT NULL, mailbox_id TEXT NOT NULL,
      capability TEXT NOT NULL CHECK (capability IN ('read','draft','organize')),
      PRIMARY KEY (client_id, mailbox_id, capability));`);
});

describe("policy", () => {
  it("denies by default", () => {
    for (const m of ["m1", "m2"]) for (const cap of CAPS) expect(allowed(ctx("c1"), m, cap)).toBe(false);
    expect(allowedMailboxes(ctx("c1"), "read", db)).toEqual([]);
    expect(anyAllowedMailboxes(ctx("c1"), db)).toEqual([]);
  });

  it("matrix client x mailbox x capability", () => {
    grant("c1", "m1", "read");
    grant("c1", "m2", "draft");
    grant("c2", "m1", "organize");
    const expected = (c: string, m: string, cap: Capability) =>
      (c === "c1" && m === "m1" && cap === "read") ||
      (c === "c1" && m === "m2" && cap === "draft") ||
      (c === "c2" && m === "m1" && cap === "organize");
    for (const c of ["c1", "c2", "c3"])
      for (const m of ["m1", "m2", "m3"])
        for (const cap of CAPS) expect(allowed(ctx(c), m, cap), `${c} ${m} ${cap}`).toBe(expected(c, m, cap));
  });

  it("token scopes are a ceiling over grants", () => {
    grant("c1", "m1", "read");
    grant("c1", "m1", "organize");
    const narrow = ctx("c1", ["read"]);
    expect(allowed(narrow, "m1", "read")).toBe(true);
    expect(allowed(narrow, "m1", "organize")).toBe(false);
    expect(allowedMailboxes(narrow, "organize", db)).toEqual([]);
  });

  it("draft and organize do not imply read; capabilities are independent", () => {
    grant("c1", "m1", "draft");
    grant("c1", "m1", "organize");
    expect(allowed(ctx("c1"), "m1", "read")).toBe(false);
    grant("c2", "m1", "read");
    expect(allowed(ctx("c2"), "m1", "draft")).toBe(false);
    expect(allowed(ctx("c2"), "m1", "organize")).toBe(false);
  });

  it("grant removal affects the next call with the same token context", () => {
    grant("c1", "m1", "read");
    const c = ctx("c1");
    expect(allowed(c, "m1", "read")).toBe(true);
    db.prepare("DELETE FROM grants WHERE client_id='c1' AND mailbox_id='m1' AND capability='read'").run();
    expect(allowed(c, "m1", "read")).toBe(false);
    expect(allowedMailboxes(c, "read", db)).toEqual([]);
  });

  it("anyAllowedMailboxes unions capabilities within scopes", () => {
    grant("c1", "m1", "read");
    grant("c1", "m2", "draft");
    grant("c1", "m3", "organize");
    expect(anyAllowedMailboxes(ctx("c1"), db)).toEqual(["m1", "m2", "m3"]);
    expect(anyAllowedMailboxes(ctx("c1", ["draft"]), db)).toEqual(["m2"]);
  });

  it("rejects empty or malformed input", () => {
    grant("c1", "", "read");
    expect(allowed(ctx("c1"), "", "read")).toBe(false);
    expect(allowed({ tokenId: "t", clientId: "c1" } as unknown as TokenContext, "m1", "read")).toBe(false);
  });
});
