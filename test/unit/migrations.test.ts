import { describe, it, expect } from "vitest";
import { mkdtempSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { openDatabase } from "../../src/db/database.js";

describe("drizzle migrations", () => {
  it("creates all tables on a fresh DB with FKs enforced", () => {
    const { raw } = openDatabase(join(mkdtempSync(join(tmpdir(), "db-")), "t.db"));
    const names = (raw.prepare("SELECT name FROM sqlite_master WHERE type='table'").all() as { name: string }[]).map((r) => r.name);
    for (const t of ["admin", "mailboxes", "oauth_clients", "grants", "oauth_codes", "oauth_tokens"]) expect(names).toContain(t);
    expect(raw.pragma("foreign_keys", { simple: true })).toBe(1);
    expect(() => raw.prepare("INSERT INTO admin (id, password_hash) VALUES (2, 'x')").run()).toThrow();
    raw.prepare("INSERT INTO oauth_clients (client_id, redirect_uris) VALUES ('c','[]')").run();
    expect(() => raw.prepare("INSERT INTO grants (client_id, mailbox_id, capability) VALUES ('c','nope','read')").run()).toThrow();
    raw.close();
  });
  it("is idempotent when reopened", () => {
    const p = join(mkdtempSync(join(tmpdir(), "db-")), "t.db");
    openDatabase(p).raw.close();
    openDatabase(p).raw.close();
  });
});
