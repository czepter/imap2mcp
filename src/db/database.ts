import Database from "better-sqlite3";
import { drizzle, type BetterSQLite3Database } from "drizzle-orm/better-sqlite3";
import { migrate } from "drizzle-orm/better-sqlite3/migrator";
import { dirname, join } from "path";
import { mkdirSync, existsSync, readFileSync, readdirSync, chmodSync, unlinkSync } from "fs";
import { fileURLToPath } from "url";
import { config } from "../config.js";
import * as schema from "./schema.js";
import { log } from "../log.js";

let db: Database.Database | undefined;
let orm: BetterSQLite3Database<typeof schema> | undefined;

/** Locate <package root>/drizzle from src/db or dist/db (and Docker, where drizzle/ sits next to dist/). */
export function migrationsFolder(): string {
  let dir = dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 4; i++) {
    const candidate = join(dir, "drizzle");
    if (existsSync(join(candidate, "meta", "_journal.json"))) return candidate;
    dir = dirname(dir);
  }
  throw new Error("Drizzle migrations folder not found (run npm run db:generate)");
}

interface JournalEntry { idx: number; when: number; tag: string }

function journal(): JournalEntry[] {
  const j = JSON.parse(readFileSync(join(migrationsFolder(), "meta", "_journal.json"), "utf8")) as { entries: JournalEntry[] };
  return j.entries;
}

/** Migrations known to this build vs. applied in this database (drizzle compares by created_at of the last applied one). */
export function migrationStatus(raw: Database.Database): { expected: number; applied: number; pending: number } {
  const entries = journal();
  let lastApplied = -1;
  let applied = 0;
  const has = raw.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='__drizzle_migrations'").get();
  if (has) {
    const r = raw.prepare("SELECT COUNT(*) AS n, MAX(created_at) AS last FROM __drizzle_migrations").get() as { n: number; last: number | null };
    applied = r.n;
    lastApplied = r.last ?? -1;
  }
  const pending = entries.filter((e) => e.when > lastApplied).length;
  return { expected: entries.length, applied, pending };
}

export const BACKUP_KEEP = 5;

function pruneBackups(dir: string): void {
  const files = readdirSync(dir).filter((f) => /^bridge-.+-pre-\d+\.db$/.test(f)).sort();
  for (const f of files.slice(0, Math.max(0, files.length - BACKUP_KEEP))) {
    try { unlinkSync(join(dir, f)); } catch { /* best effort */ }
  }
}

/**
 * Before applying pending migrations to an existing database, take a consistent copy with VACUUM INTO
 * (DATA_DIR/backups/bridge-<ISO>-pre-<n>.db, mode 0600, newest BACKUP_KEEP kept). n = migrations already applied.
 * Throws if the backup cannot be written: we do not migrate without a safety copy.
 */
function backupBeforeMigrate(raw: Database.Database, dbPath: string, applied: number): string {
  const dir = join(dirname(dbPath), "backups");
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  try { chmodSync(dir, 0o700); } catch { /* not owner */ }
  const stamp = new Date().toISOString().replace(/:/g, "-");
  let target = join(dir, `bridge-${stamp}-pre-${applied}.db`);
  for (let i = 1; existsSync(target); i++) target = join(dir, `bridge-${stamp}.${i}-pre-${applied}.db`);
  raw.exec(`VACUUM INTO '${target.replace(/'/g, "''")}'`);
  chmodSync(target, 0o600);
  pruneBackups(dir);
  return target;
}

export class MigrationError extends Error {}

/** Open a database (":memory:" allowed) with pragmas and all migrations applied. Used by tests too. */
export function openDatabase(path: string): { raw: Database.Database; orm: BetterSQLite3Database<typeof schema> } {
  const raw = new Database(path);
  try {
    raw.pragma("journal_mode = WAL");
    raw.pragma("foreign_keys = ON");
    const o = drizzle(raw, { schema });
    const st = migrationStatus(raw);
    let backup: string | undefined;
    if (st.pending > 0 && st.applied > 0 && path !== ":memory:" && path !== "") {
      backup = backupBeforeMigrate(raw, path, st.applied);
      log.info("pre-migration backup written", { backup, applied: st.applied, pending: st.pending });
    }
    try {
      migrate(o, { migrationsFolder: migrationsFolder() });
    } catch (e) {
      throw new MigrationError(
        `Database migration failed; the database was not changed (migrations run in one transaction).${backup ? ` Pre-migration backup: ${backup}.` : ""} Cause: ${(e as Error).message}`
      );
    }
    return { raw, orm: o };
  } catch (e) {
    try { raw.close(); } catch { /* ignore */ }
    throw e;
  }
}

function init() {
  if (!db) {
    mkdirSync(config.dataDir, { recursive: true });
    const r = openDatabase(config.dbPath);
    db = r.raw;
    orm = r.orm;
  }
}

/** Raw better-sqlite3 handle. */
export function getDb(): Database.Database {
  init();
  return db!;
}

export function getOrm(): BetterSQLite3Database<typeof schema> {
  init();
  return orm!;
}

/** Test helper: close and forget the singleton. */
export function closeDb(): void {
  db?.close();
  db = undefined;
  orm = undefined;
}
