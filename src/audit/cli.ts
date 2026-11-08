#!/usr/bin/env node
/* Usage: npm run audit:export -- [--from ISO|YYYY-MM-DD] [--to ISO|YYYY-MM-DD] [--format jsonl|csv] [--client ID] [--mailbox ID] [--tool NAME] [--outcome OUT] [--out FILE] */
import { createWriteStream, existsSync } from "node:fs";
import { join, resolve } from "node:path";
import Database from "better-sqlite3";
import { exportLines, parseTime } from "./export.js";
import type { AuditFilter, AuditOutcome } from "./store.js";

function parseArgs(argv: string[]): Record<string, string> {
  const o: Record<string, string> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("--")) throw new Error(`Unexpected argument: ${a}`);
    const eq = a.indexOf("=");
    if (eq > 0) o[a.slice(2, eq)] = a.slice(eq + 1);
    else { o[a.slice(2)] = argv[i + 1] ?? ""; i++; }
  }
  return o;
}

function main(): void {
  const a = parseArgs(process.argv.slice(2));
  const known = new Set(["from", "to", "format", "client", "mailbox", "tool", "outcome", "out"]);
  for (const k of Object.keys(a)) if (!known.has(k)) throw new Error(`Unknown option --${k}`);
  const format = (a.format ?? "jsonl") as "jsonl" | "csv";
  if (format !== "jsonl" && format !== "csv") throw new Error("--format must be jsonl or csv");
  const f: AuditFilter = {};
  if (a.from) { f.from = parseTime(a.from); if (!f.from) throw new Error("--from is not a valid date"); }
  if (a.to) { f.to = parseTime(a.to); if (!f.to) throw new Error("--to is not a valid date"); }
  if (a.client) f.clientId = a.client;
  if (a.mailbox) f.mailboxId = a.mailbox;
  if (a.tool) f.tool = a.tool;
  if (a.outcome) {
    if (!["ok", "denied", "failed", "unknown_outcome"].includes(a.outcome)) throw new Error("--outcome is invalid");
    f.outcome = a.outcome as AuditOutcome;
  }
  const dbPath = join(resolve(process.env.DATA_DIR || "./data"), "bridge.db");
  if (!existsSync(dbPath)) throw new Error(`Database not found: ${dbPath} (set DATA_DIR)`);
  const db = new Database(dbPath, { readonly: true, fileMustExist: true });
  const out = a.out ? createWriteStream(a.out, { mode: 0o600 }) : process.stdout;
  try {
    for (const line of exportLines(format, f, db)) out.write(line + "\n");
  } finally {
    db.close();
    if (a.out) (out as ReturnType<typeof createWriteStream>).end();
  }
}

try { main(); } catch (e) {
  process.stderr.write(`audit:export failed: ${(e as Error).message}\n`);
  process.exit(1);
}
