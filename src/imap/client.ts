import { ImapFlow } from "imapflow";
import { assertHostAllowed } from "./ssrf.js";
import { getMailboxCredentials } from "./mailboxes.js";

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
  constructor(message: string, readonly cause?: unknown) {
    super(message);
    this.name = "ImapConnectError";
  }
}

interface Entry {
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

async function connect(mailboxId: string): Promise<Entry> {
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
  const entry: Entry = { client, idle: setTimeout(() => {}, 0), queue: Promise.resolve() };
  clearTimeout(entry.idle);
  try {
    await client.connect();
  } catch (e) {
    try { client.close(); } catch { /* ignore */ }
    throw new ImapConnectError("Could not connect to mailbox", e);
  }
  client.on("close", () => drop(mailboxId, entry));
  pool.set(mailboxId, entry);
  touch(mailboxId, entry);
  return entry;
}

async function getEntry(mailboxId: string): Promise<Entry> {
  const existing = pool.get(mailboxId);
  if (existing && existing.client.usable) return existing;
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
export async function withImap<T>(mailboxId: string, fn: (c: ImapFlow) => Promise<T>): Promise<T> {
  const entry = await getEntry(mailboxId);
  const run = async (): Promise<T> => {
    if (!entry.client.usable) throw new ImapConnectError("Connection lost");
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        drop(mailboxId, entry);
        reject(new ImapTimeoutError());
      }, OPERATION_TIMEOUT_MS);
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
