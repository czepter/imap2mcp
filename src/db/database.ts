import Database from "better-sqlite3";
import { join, dirname } from "path";
import { mkdirSync, readdirSync, readFileSync, existsSync } from "fs";
import { fileURLToPath } from "url";
import { config } from "../config.js";

let db: Database.Database | undefined;

function migrationsDir(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  const local = join(here, "migrations");
  if (existsSync(local)) return local;
  // compiled to dist/db: fall back to the source tree copy
  const src = join(here, "..", "..", "src", "db", "migrations");
  if (existsSync(src)) return src;
  throw new Error("Migrations directory not found (expected next to database.js or at src/db/migrations)");
}

/** Apply pending NNN_name.sql files in order, each in a transaction, recorded in schema_migrations. */
export function runMigrations(database: Database.Database, dir: string = migrationsDir()): string[] {
  database.exec(
    "CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT (datetime('now')))"
  );
  const applied = new Set(
    (database.prepare("SELECT version FROM schema_migrations").all() as { version: string }[]).map((r) => r.version)
  );
  const files = readdirSync(dir).filter((f) => /^\d+.*\.sql$/.test(f)).sort();
  const ran: string[] = [];
  for (const file of files) {
    if (applied.has(file)) continue;
    const sql = readFileSync(join(dir, file), "utf8");
    database.transaction(() => {
      database.exec(sql);
      database.prepare("INSERT INTO schema_migrations (version) VALUES (?)").run(file);
    })();
    ran.push(file);
  }
  return ran;
}

/** Open a database at a path (":memory:" allowed) with pragmas and migrations applied. Used by tests too. */
export function openDatabase(path: string): Database.Database {
  const d = new Database(path);
  d.pragma("journal_mode = WAL");
  d.pragma("foreign_keys = ON");
  runMigrations(d);
  return d;
}

export function getDb(): Database.Database {
  if (!db) {
    mkdirSync(config.dataDir, { recursive: true });
    db = openDatabase(config.dbPath);
  }
  return db;
}

/** Test helper: close and forget the singleton. */
export function closeDb(): void {
  db?.close();
  db = undefined;
}
