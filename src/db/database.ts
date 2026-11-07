import Database from "better-sqlite3";
import { drizzle, type BetterSQLite3Database } from "drizzle-orm/better-sqlite3";
import { migrate } from "drizzle-orm/better-sqlite3/migrator";
import { dirname, join } from "path";
import { mkdirSync, existsSync } from "fs";
import { fileURLToPath } from "url";
import { config } from "../config.js";
import * as schema from "./schema.js";

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

/** Open a database (":memory:" allowed) with pragmas and all migrations applied. Used by tests too. */
export function openDatabase(path: string): { raw: Database.Database; orm: BetterSQLite3Database<typeof schema> } {
  const raw = new Database(path);
  raw.pragma("journal_mode = WAL");
  raw.pragma("foreign_keys = ON");
  const o = drizzle(raw, { schema });
  migrate(o, { migrationsFolder: migrationsFolder() });
  return { raw, orm: o };
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
