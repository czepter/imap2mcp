import { describe, it, expect } from "vitest";
import Database from "better-sqlite3";
import { readFileSync, mkdtempSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { migrationsFolder, openDatabase } from "../../src/db/database.js";
import { assertOp, filterAllowedFolders, isOpAllowed, anyAllowedMailboxes } from "../../src/policy/policy.js";
import { OPERATIONS, OP_CAPABILITY } from "../../src/policy/rules.js";
import type { Capability, TokenContext } from "../../src/types.js";

const CAPS: Capability[] = ["read", "draft", "organize"];
const FOLDERS = ["INBOX", "INBOX/Sub", "Archive", "Archive/2020/Q1", "Drafts", "Sent"];
const DRAFTS = "Drafts";

function applySql(raw: Database.Database, file: string) {
  for (const stmt of readFileSync(join(migrationsFolder(), file), "utf8").split("--> statement-breakpoint")) {
    if (stmt.trim()) raw.exec(stmt);
  }
}

/** v0 semantics: a grant of capability C allows every op of C on any folder of the mailbox (draft: Drafts only). */
function v0Allowed(grants: Set<string>, client: string, mailbox: string, folder: string, op: (typeof OPERATIONS)[number]): boolean {
  if (!grants.has(`${client}|${mailbox}|${OP_CAPABILITY[op]}`)) return false;
  return op === "draft" ? folder === DRAFTS : true;
}

describe("migration 0001: grants -> policy_rules", () => {
  it("effective rights are identical before and after, and the grants table is gone", () => {
    const raw = new Database(":memory:");
    raw.pragma("foreign_keys = ON");
    applySql(raw, "0000_melodic_proteus.sql");
    const clients = ["c-none", "c-read", "c-draft", "c-org", "c-two", "c-all"];
    const mailboxes = ["m1", "m2", "m3"];
    for (const c of clients) raw.prepare("INSERT INTO oauth_clients (client_id, redirect_uris) VALUES (?, '[]')").run(c);
    for (const m of mailboxes) raw.prepare("INSERT INTO mailboxes (id, label, imap_host, imap_username, imap_password_enc, drafts_folder) VALUES (?, ?, 'h', 'u', 'x', ?)").run(m, m, DRAFTS);
    const seed: Array<[string, string, Capability]> = [
      ["c-read", "m1", "read"], ["c-draft", "m2", "draft"], ["c-org", "m3", "organize"],
      ["c-two", "m1", "read"], ["c-two", "m1", "organize"], ["c-two", "m2", "draft"],
      ...mailboxes.flatMap((m) => CAPS.map((cap) => ["c-all", m, cap] as [string, string, Capability])),
    ];
    const grants = new Set<string>();
    for (const [c, m, cap] of seed) {
      raw.prepare("INSERT INTO grants (client_id, mailbox_id, capability) VALUES (?,?,?)").run(c, m, cap);
      grants.add(`${c}|${m}|${cap}`);
    }

    applySql(raw, "0001_policy_rules.sql");
    expect(raw.prepare("SELECT name FROM sqlite_master WHERE name = 'grants'").get()).toBeUndefined();
    expect((raw.prepare("SELECT COUNT(*) n FROM policy_rules").get() as { n: number }).n).toBe(
      seed.reduce((n, [, , cap]) => n + (cap === "read" ? 3 : cap === "draft" ? 1 : 2), 0),
    );
    expect(raw.prepare("SELECT COUNT(*) n FROM policy_rules WHERE effect <> 'allow' OR folder <> '*'").get()).toEqual({ n: 0 });

    let checked = 0;
    for (const c of clients) {
      const ctx: TokenContext = { tokenId: "t", clientId: c, scopes: CAPS };
      for (const m of mailboxes) {
        for (const f of FOLDERS) for (const op of OPERATIONS) {
          // callers evaluate `draft` only against the mailbox's Drafts folder (design: "draft is evaluated against Drafts")
          if (op === "draft" && f !== DRAFTS) continue;
          expect(isOpAllowed(ctx, m, f, op, raw), `${c} ${m} ${f} ${op}`).toBe(v0Allowed(grants, c, m, f, op));
          checked++;
        }
        // folder discovery: v0 needed `read`; v1 needs any read op on the folder
        const listed = filterAllowedFolders(ctx, m, ["search", "read_headers", "read_body"], FOLDERS, raw);
        expect(listed, `discovery ${c} ${m}`).toEqual(grants.has(`${c}|${m}|read`) ? FOLDERS : []);
      }
      const anyV0 = mailboxes.filter((m) => CAPS.some((cap) => grants.has(`${c}|${m}|${cap}`)));
      expect(anyAllowedMailboxes(ctx, raw)).toEqual(anyV0);
    }
    expect(checked).toBe(clients.length * mailboxes.length * (FOLDERS.length * (OPERATIONS.length - 1) + 1));
    // a token ceiling still applies after migration
    expect(() => assertOp({ tokenId: "t", clientId: "c-all", scopes: ["read"] }, "m1", "INBOX", "move", raw)).toThrow();
    raw.close();
  });

  it("a fresh database has no v0 grants to migrate and starts default-deny", () => {
    const { raw } = openDatabase(join(mkdtempSync(join(tmpdir(), "mig-")), "t.db"));
    expect(raw.prepare("SELECT COUNT(*) n FROM policy_rules").get()).toEqual({ n: 0 });
    raw.close();
  });
});
