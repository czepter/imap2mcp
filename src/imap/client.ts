import { ImapFlow } from "imapflow";
import { assertHostAllowed } from "./ssrf.js";
import { getMailboxCredentials } from "./mailboxes.js";
import { getDb } from "../db/database.js";
import { log } from "../log.js";
import { remainingMs } from "./budget.js";

export const OPERATION_TIMEOUT_MS = 30_000;
const IDLE_TIMEOUT_MS = 5 * 60 * 1000;

export class ImapTimeoutError extends Error {
  constructor() {
    super("IMAP operation timed out");
    this.name = "ImapTimeoutError";
  }
}

/** Thrown when failure happened before any command could be issued (safe to treat as "nothing happened"). */
export class ImapConnectError extends Error {
  constructor(message: string, readonly cause?: unknown, readonly retryAfterMs?: number) {
    super(message);
    this.name = "ImapConnectError";
  }
}

/** The server rejected the mailbox credentials, or the mailbox is latched as auth_failed. No server contact happened if latched. */
export class ImapAuthError extends Error {
  constructor(message = "Mailbox authentication failed", readonly latched = false) {
    super(message);
    this.name = "ImapAuthError";
  }
}

// ---------- reconnect backoff (docs/DESIGN_V2.md "Backoff") ----------
export const BACKOFF_FLOOR_MS = 500;
export const HEALTHY_AFTER_MS = 30_000;

function envMs(name: string, dflt: number): number {
  const n = Number(process.env[name]);
  return Number.isFinite(n) && n > 0 ? n : dflt;
}

/**
 * Delay before reconnect attempt number `attempt` (0-based): full jitter over min(max, initial * 2^attempt),
 * never below 500 ms (or the cap itself when the test-only env knobs make the cap smaller).
 * Defaults: initial 1 s, max 60 s. Env RECONNECT_INITIAL_MS / RECONNECT_MAX_MS exist for tests.
 */
export function computeBackoffDelay(
  attempt: number,
  o: { initialMs?: number; maxMs?: number; rand?: () => number } = {},
): number {
  const initial = o.initialMs ?? envMs("RECONNECT_INITIAL_MS", 1_000);
  const max = o.maxMs ?? envMs("RECONNECT_MAX_MS", 60_000);
  const cap = Math.min(max, initial * 2 ** Math.min(Math.max(attempt, 0), 30));
  const rand = o.rand ?? Math.random;
  const floor = Math.min(BACKOFF_FLOOR_MS, cap);
  return Math.max(floor, Math.floor(rand() * cap));
}

interface BackoffState { failures: number; nextAttemptAt: number }
const backoff = new Map<string, BackoffState>();

function bstate(id: string): BackoffState {
  let s = backoff.get(id);
  if (!s) { s = { failures: 0, nextAttemptAt: 0 }; backoff.set(id, s); }
  return s;
}

function noteFailure(id: string): number {
  const s = bstate(id);
  const delay = computeBackoffDelay(s.failures);
  s.failures += 1;
  s.nextAttemptAt = Date.now() + delay;
  return delay;
}

/** Introspection for tests/diagnostics. */
export function getBackoffState(id: string): { failures: number; nextAttemptAt: number } {
  return { ...bstate(id) };
}
export function resetBackoffForTests(): void { backoff.clear(); authFailedMem.clear(); }

// ---------- auth-failure latch ----------
const authFailedMem = new Set<string>();

function trySql(sql: string, ...params: unknown[]): void {
  try { getDb().prepare(sql).run(...params); } catch { /* column missing (pre-0002 DB) or DB unavailable: memory latch still holds */ }
}

/** True when the server rejected LOGIN/AUTHENTICATE. */
export function isAuthFailure(e: unknown): boolean {
  const x = e as { authenticationFailed?: boolean; serverResponseCode?: string; responseText?: string; message?: string } | undefined;
  if (!x) return false;
  if (x.authenticationFailed === true) return true;
  if (/^(AUTHENTICATIONFAILED|AUTHORIZATIONFAILED|AUTH)/i.test(x.serverResponseCode ?? "")) return true;
  if (/\[(AUTH|AUTHENTICATIONFAILED|AUTHORIZATIONFAILED)/i.test(x.responseText ?? "")) return true;
  return /invalid credentials|authentication failed|login failed/i.test(x.message ?? "") && !!(x as { responseStatus?: string }).responseStatus;
}

/**
 * Latch a mailbox as auth_failed: all automatic credential attempts (Node pool; sidecar via status poll) stop and tools
 * answer AUTH_FAILED immediately. Persisted in mailboxes.status when the column exists (migration 0002).
 */
export function markMailboxAuthFailed(mailboxId: string): void {
  const was = isMailboxAuthFailed(mailboxId);
  authFailedMem.add(mailboxId);
  trySql("UPDATE mailboxes SET status = 'auth_failed', last_error_code = 'AUTH_FAILED', next_retry_at = NULL WHERE id = ?", mailboxId);
  const e = pool.get(mailboxId);
  if (e) drop(mailboxId, e);
  if (!was) log.warn("mailbox auth failed; credential attempts stopped", { mailboxId });
}

/** Admin edited credentials or pressed Retry: resume credential attempts. */
export function clearMailboxAuthFailure(mailboxId: string): void {
  authFailedMem.delete(mailboxId);
  backoff.delete(mailboxId);
  trySql("UPDATE mailboxes SET status = 'unknown', last_error_code = NULL, next_retry_at = NULL WHERE id = ? AND status = 'auth_failed'", mailboxId);
}

/** The DB (status column) is authoritative when present, so the admin UI / sidecar poller can latch and clear it too. */
export function isMailboxAuthFailed(mailboxId: string): boolean {
  try {
    const r = getDb().prepare("SELECT status FROM mailboxes WHERE id = ?").get(mailboxId) as { status?: string } | undefined;
    if (r && typeof r.status === "string") return r.status === "auth_failed";
  } catch { /* no status column yet */ }
  return authFailedMem.has(mailboxId);
}

interface Entry {
  connectedAt: number;
  client: ImapFlow;
  idle: ReturnType<typeof setTimeout>;
  queue: Promise<unknown>; // serialises operations on the single connection
}

const pool = new Map<string, Entry>();
const connecting = new Map<string, Promise<Entry>>();

function drop(mailboxId: string, entry: Entry): void {
  clearTimeout(entry.idle);
  if (pool.get(mailboxId) === entry) pool.delete(mailboxId);
  try { entry.client.close(); } catch { /* ignore */ }
}

function touch(mailboxId: string, entry: Entry): void {
  clearTimeout(entry.idle);
  entry.idle = setTimeout(() => {
    if (pool.get(mailboxId) === entry) pool.delete(mailboxId);
    entry.client.logout().catch(() => { try { entry.client.close(); } catch { /* ignore */ } });
  }, IDLE_TIMEOUT_MS);
  entry.idle.unref?.();
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

async function connect(mailboxId: string): Promise<Entry> {
  if (isMailboxAuthFailed(mailboxId)) throw new ImapAuthError("Mailbox is latched as auth_failed", true);
  const bs = bstate(mailboxId);
  const wait = bs.nextAttemptAt - Date.now();
  if (wait > 0) {
    const rem = remainingMs();
    // Wait out a short backoff inside the tool budget; otherwise fail fast so the caller never blocks past 30 s.
    if (rem !== undefined && wait < rem - 1_000) await sleep(wait);
    else throw new ImapConnectError("Reconnect backoff in effect", undefined, wait);
  }
  const creds = getMailboxCredentials(mailboxId);
  const addrs = await assertHostAllowed(creds.host); // SSRF policy on every connect
  const client = new ImapFlow({
    host: addrs[0], // pin to the vetted address (DNS-rebinding guard)
    port: creds.port,
    secure: true, // implicit TLS, certificate validation on; no downgrade
    servername: creds.host,
    tls: { servername: creds.host, rejectUnauthorized: true },
    auth: { user: creds.user, pass: creds.password },
    logger: false,
    socketTimeout: OPERATION_TIMEOUT_MS,
    greetingTimeout: OPERATION_TIMEOUT_MS,
    connectionTimeout: OPERATION_TIMEOUT_MS,
  });
  client.on("error", () => { /* handled via close/op failure; never log credentials */ });
  const entry: Entry = { connectedAt: 0, client, idle: setTimeout(() => {}, 0), queue: Promise.resolve() };
  clearTimeout(entry.idle);
  try {
    await client.connect();
  } catch (e) {
    try { client.close(); } catch { /* ignore */ }
    if (isAuthFailure(e)) {
      markMailboxAuthFailed(mailboxId);
      throw new ImapAuthError();
    }
    const delay = noteFailure(mailboxId);
    log.warn("mailbox connect failed", { mailboxId, errorCode: (e as { code?: string })?.code, nextAttemptInMs: delay });
    throw new ImapConnectError("Could not connect to mailbox", e, delay);
  }
  entry.connectedAt = Date.now();
  client.on("close", () => {
    if (Date.now() - entry.connectedAt >= HEALTHY_AFTER_MS) bstate(mailboxId).failures = 0; // was healthy: reset
    else noteFailure(mailboxId); // flapped quickly: keep growing the delay
    drop(mailboxId, entry);
  });
  pool.set(mailboxId, entry);
  touch(mailboxId, entry);
  return entry;
}

async function getEntry(mailboxId: string): Promise<Entry> {
  if (isMailboxAuthFailed(mailboxId)) {
    const stale = pool.get(mailboxId);
    if (stale) drop(mailboxId, stale);
    throw new ImapAuthError("Mailbox is latched as auth_failed", true);
  }
  const existing = pool.get(mailboxId);
  if (existing && existing.client.usable) {
    const bs = backoff.get(mailboxId);
    if (bs && bs.failures > 0 && Date.now() - existing.connectedAt >= HEALTHY_AFTER_MS) bs.failures = 0;
    return existing;
  }
  if (existing) drop(mailboxId, existing);
  let p = connecting.get(mailboxId);
  if (!p) {
    p = connect(mailboxId).finally(() => connecting.delete(mailboxId));
    connecting.set(mailboxId, p);
  }
  return p;
}

/**
 * Run `fn` on a pooled, TLS-validated, SSRF-checked connection with a 30 s deadline.
 * On timeout the connection is destroyed (outcome of in-flight command is then unknown) and
 * ImapTimeoutError is thrown. Operations on one mailbox are serialised.
 */
export async function withImap<T>(
  mailboxId: string, fn: (c: ImapFlow) => Promise<T>, opts: { timeoutMs?: number } = {},
): Promise<T> {
  if (remainingMs() !== undefined && remainingMs()! <= 0) throw new ImapTimeoutError();
  const entry = await getEntry(mailboxId);
  const run = async (): Promise<T> => {
    if (!entry.client.usable) throw new ImapConnectError("Connection lost");
    const rem = remainingMs();
    if (rem !== undefined && rem <= 0) throw new ImapTimeoutError();
    const limit = Math.max(1, Math.min(opts.timeoutMs ?? OPERATION_TIMEOUT_MS, OPERATION_TIMEOUT_MS, rem ?? Infinity));
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        drop(mailboxId, entry);
        reject(new ImapTimeoutError());
      }, limit);
    });
    try {
      return await Promise.race([fn(entry.client), timeout]);
    } finally {
      clearTimeout(timer);
      if (pool.get(mailboxId) === entry) touch(mailboxId, entry);
    }
  };
  const result = entry.queue.then(run, run);
  entry.queue = result.catch(() => undefined);
  return result;
}

export async function closeAllImap(): Promise<void> {
  for (const [id, e] of [...pool]) {
    clearTimeout(e.idle);
    pool.delete(id);
    try { await e.client.logout(); } catch { try { e.client.close(); } catch { /* ignore */ } }
  }
}
