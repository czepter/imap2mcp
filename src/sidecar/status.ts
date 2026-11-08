import type Database from "better-sqlite3";
import { log } from "../log.js";

const slog = log.child({ component: "sidecar-status" });

/** Result of the sidecar `status` RPC (docs/DESIGN_V2.md "Sidecar additions"). */
export interface SidecarStatus {
  state: "connected" | "reconnecting" | "auth_failed" | "closed";
  since: string;
  lastErrorCode?: string;
  nextRetryAt?: string;
  idle: boolean;
  reconnects: number;
}

export type MailboxStatus = "unknown" | "ok" | "degraded" | "auth_failed";

/** Sidecar connection state -> persisted `mailboxes.status`. `closed` carries no information (null). */
export function toMailboxStatus(state: SidecarStatus["state"]): MailboxStatus | null {
  switch (state) {
    case "connected": return "ok";
    case "reconnecting": return "degraded";
    case "auth_failed": return "auth_failed";
    default: return null;
  }
}

/** What the poller needs from the sidecar facade (SidecarService implements it; tests fake it). */
export interface StatusSource {
  /** Mailboxes this process opened in the sidecar (plus ones whose open was rejected for bad credentials). */
  trackedMailboxIds(): string[];
  status(mailboxId: string): Promise<SidecarStatus>;
}

export interface StatusPollerOptions {
  source: StatusSource;
  /** Database holding the `mailboxes` table. */
  db: () => Database.Database;
  intervalMs?: number;
  /** last_ok_at is refreshed at most this often while healthy (avoids a write every poll). */
  okRefreshMs?: number;
  now?: () => Date;
}

interface Row { status: string; last_error_code: string | null; last_ok_at: string | null; next_retry_at: string | null }

/**
 * Polls the sidecar `status` of every opened mailbox (default every 5 s) and persists
 * mailboxes.status / last_error_code / last_ok_at / next_retry_at with raw SQL, so it also works
 * before the drizzle schema exposes the columns (guarded: a database without them is left alone).
 *
 * A mailbox whose stored status is `auth_failed` stays that way until the operator edits the
 * credentials or presses Retry (which resets it to `unknown`); the poller never "heals" it on its own.
 */
export class StatusPoller {
  private timer: NodeJS.Timeout | null = null;
  private running = false;
  private columns: boolean | null = null;
  private readonly intervalMs: number;
  private readonly okRefreshMs: number;
  private readonly now: () => Date;

  constructor(private readonly o: StatusPollerOptions) {
    this.intervalMs = o.intervalMs ?? 5_000;
    this.okRefreshMs = o.okRefreshMs ?? 60_000;
    this.now = o.now ?? (() => new Date());
  }

  start(): void {
    if (this.timer) return;
    this.timer = setInterval(() => { void this.pollOnce(); }, this.intervalMs);
    this.timer.unref?.();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  private hasColumns(db: Database.Database): boolean {
    if (this.columns === true) return true;
    const cols = (db.prepare("PRAGMA table_info(mailboxes)").all() as Array<{ name: string }>).map((c) => c.name);
    const ok = ["status", "last_error_code", "last_ok_at", "next_retry_at"].every((c) => cols.includes(c));
    if (ok) this.columns = true; // keep re-checking while absent: migration 0002 may land later
    return ok;
  }

  /** One polling round. Never throws. */
  async pollOnce(): Promise<void> {
    if (this.running) return;
    this.running = true;
    try {
      const ids = this.o.source.trackedMailboxIds();
      if (ids.length === 0) return;
      let db: Database.Database;
      try { db = this.o.db(); } catch { return; }
      if (!this.hasColumns(db)) return;
      for (const id of ids) {
        let st: SidecarStatus;
        try { st = await this.o.source.status(id); } catch { continue; } // sidecar down: keep the last persisted state
        try { this.persist(db, id, st); } catch (e) { slog.warn("persisting mailbox status failed", { mailboxId: id, err: e }); }
      }
    } catch (e) {
      slog.warn("status poll failed", { err: e });
    } finally {
      this.running = false;
    }
  }

  private persist(db: Database.Database, id: string, st: SidecarStatus): void {
    const mapped = toMailboxStatus(st.state);
    if (!mapped) return;
    const row = db.prepare("SELECT status, last_error_code, last_ok_at, next_retry_at FROM mailboxes WHERE id = ?").get(id) as Row | undefined;
    if (!row) return;
    if (row.status === "auth_failed" && mapped !== "auth_failed") return; // operator action required first
    const nowIso = this.now().toISOString();
    const errCode = mapped === "ok" ? null : (st.lastErrorCode ?? null);
    const nextRetry = mapped === "degraded" ? (st.nextRetryAt ?? null) : null;
    let lastOk = row.last_ok_at;
    if (mapped === "ok") {
      const age = lastOk ? this.now().getTime() - Date.parse(lastOk) : Infinity;
      if (row.status !== "ok" || !(age < this.okRefreshMs)) lastOk = nowIso;
    }
    if (row.status === mapped && row.last_error_code === errCode && row.next_retry_at === nextRetry && row.last_ok_at === lastOk) return;
    db.prepare("UPDATE mailboxes SET status = ?, last_error_code = ?, last_ok_at = ?, next_retry_at = ? WHERE id = ?")
      .run(mapped, errCode, lastOk, nextRetry, id);
  }
}
