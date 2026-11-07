import { ImapFlow } from "imapflow";
import { getAccount, getAccountPassword } from "./accounts.js";

interface PoolEntry {
  client: ImapFlow;
  timer: ReturnType<typeof setTimeout>;
}

const pool = new Map<string, PoolEntry>();
const IDLE_TIMEOUT = 5 * 60 * 1000;

export async function getImapClient(accountId: string): Promise<ImapFlow> {
  const existing = pool.get(accountId);
  if (existing) {
    clearTimeout(existing.timer);
    existing.timer = setTimeout(() => closeConnection(accountId), IDLE_TIMEOUT);
    return existing.client;
  }

  const account = getAccount(accountId);
  if (!account) throw new Error("IMAP account not found");

  const password = getAccountPassword(account);
  const client = new ImapFlow({
    host: account.imap_host,
    port: account.imap_port,
    secure: account.imap_tls === 1,
    auth: { user: account.username, pass: password },
    logger: false,
  });

  await client.connect();

  const timer = setTimeout(() => closeConnection(accountId), IDLE_TIMEOUT);
  pool.set(accountId, { client, timer });

  client.on("close", () => {
    pool.delete(accountId);
  });

  return client;
}

async function closeConnection(accountId: string) {
  const entry = pool.get(accountId);
  if (entry) {
    clearTimeout(entry.timer);
    pool.delete(accountId);
    try { await entry.client.logout(); } catch {}
  }
}
