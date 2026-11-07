import { randomUUID } from "crypto";
import { ImapFlow } from "imapflow";
import { getDb } from "../db/database.js";
import { encrypt, decrypt } from "./crypto.js";
import { assertHostAllowed } from "./ssrf.js";

export interface Mailbox {
  id: string;
  label: string;
  imap_host: string;
  imap_port: number;
  imap_username: string;
  drafts_folder: string | null;
  created_at: string;
}

const PUBLIC_COLS = "id, label, imap_host, imap_port, imap_username, drafts_folder, created_at";
const aad = (id: string) => `mailboxes:${id}:imap_password_enc`;

export function getMailbox(id: string): Mailbox | null {
  return (getDb().prepare(`SELECT ${PUBLIC_COLS} FROM mailboxes WHERE id = ?`).get(id) as Mailbox | undefined) ?? null;
}

export function listMailboxes(): Mailbox[] {
  return getDb().prepare(`SELECT ${PUBLIC_COLS} FROM mailboxes ORDER BY label COLLATE NOCASE`).all() as Mailbox[];
}

/** Server-internal only; never render or log. */
export function getMailboxCredentials(id: string): { host: string; port: number; user: string; password: string } {
  const r = getDb().prepare("SELECT imap_host, imap_port, imap_username, imap_password_enc FROM mailboxes WHERE id = ?").get(id) as
    | { imap_host: string; imap_port: number; imap_username: string; imap_password_enc: string }
    | undefined;
  if (!r) throw new Error("Mailbox not found");
  return { host: r.imap_host, port: r.imap_port, user: r.imap_username, password: decrypt(r.imap_password_enc, aad(id)) };
}

export interface MailboxInput {
  label: string;
  host: string;
  port: number;
  username: string;
  password: string;
}

export function validateMailboxInput(i: Partial<MailboxInput>, requirePassword: boolean): string | null {
  if (!i.label || i.label.length > 100) return "Label is required (max 100 characters)";
  if (!i.host || i.host.length > 253 || /[\s/@:]/.test(i.host.replace(/^\[.*\]$/, "x"))) return "A valid host name is required";
  if (!Number.isInteger(i.port) || i.port! < 1 || i.port! > 65535) return "Port must be 1-65535";
  if (!i.username || i.username.length > 320) return "Username is required";
  if (requirePassword && !i.password) return "Password is required";
  return null;
}

export function createMailbox(i: MailboxInput): Mailbox {
  const id = randomUUID();
  getDb()
    .prepare("INSERT INTO mailboxes (id, label, imap_host, imap_port, imap_username, imap_password_enc) VALUES (?, ?, ?, ?, ?, ?)")
    .run(id, i.label, i.host.trim(), i.port, i.username, encrypt(i.password, aad(id)));
  return getMailbox(id)!;
}

/** Empty password keeps the stored one. Changing host/username/port resets the Drafts folder. */
export function updateMailbox(id: string, i: Omit<MailboxInput, "password"> & { password?: string }): boolean {
  const db = getDb();
  const cur = getMailbox(id);
  if (!cur) return false;
  const changedTarget = cur.imap_host !== i.host.trim() || cur.imap_port !== i.port || cur.imap_username !== i.username;
  db.transaction(() => {
    db.prepare("UPDATE mailboxes SET label = ?, imap_host = ?, imap_port = ?, imap_username = ?, drafts_folder = CASE WHEN ? THEN NULL ELSE drafts_folder END WHERE id = ?")
      .run(i.label, i.host.trim(), i.port, i.username, changedTarget ? 1 : 0, id);
    if (i.password) db.prepare("UPDATE mailboxes SET imap_password_enc = ? WHERE id = ?").run(encrypt(i.password, aad(id)), id);
  })();
  return true;
}

/** Removes configuration only; never touches remote mail. Grants cascade. */
export function deleteMailbox(id: string): boolean {
  return getDb().prepare("DELETE FROM mailboxes WHERE id = ?").run(id).changes > 0;
}

export function setDraftsFolder(id: string, folder: string | null): boolean {
  return getDb().prepare("UPDATE mailboxes SET drafts_folder = ? WHERE id = ?").run(folder, id).changes > 0;
}

export interface TestResult {
  ok: boolean;
  message: string;
  folders: string[];
}

/** Sanitised, actionable error text; never includes credentials. */
function describe(e: any): string {
  const code = e?.code as string | undefined;
  if (e?.authenticationFailed || /auth/i.test(String(e?.responseText ?? ""))) return "Authentication failed: check username and password (some providers need an app password).";
  if (code === "ENOTFOUND") return "Host name could not be resolved.";
  if (code === "ECONNREFUSED") return "Connection refused: check host and port (IMAPS is usually 993).";
  if (code === "ETIMEDOUT" || /timeout/i.test(String(e?.message))) return "Connection timed out.";
  if (code === "HOST_NOT_ALLOWED") return e.message;
  if (/certificate|self.signed|CERT_|ERR_TLS|SSL/i.test(String(code) + String(e?.message))) return "TLS certificate validation failed; the server certificate is not trusted for this host name.";
  return "Connection failed.";
}

/** Connect (TLS, validated certs, SSRF-checked), list folders, disconnect. Uses saved credentials. */
export async function testMailbox(id: string): Promise<TestResult> {
  let creds;
  try {
    creds = getMailboxCredentials(id);
  } catch {
    return { ok: false, message: "Mailbox not found or credentials unreadable.", folders: [] };
  }
  let client: ImapFlow | null = null;
  try {
    const addrs = await assertHostAllowed(creds.host);
    // connect to the vetted address, validate the cert against the real host name (anti DNS-rebinding)
    client = new ImapFlow({
      host: addrs[0],
      port: creds.port,
      secure: true,
      servername: creds.host,
      tls: { servername: creds.host, rejectUnauthorized: true },
      auth: { user: creds.user, pass: creds.password },
      logger: false,
      disableAutoIdle: true,
      socketTimeout: 20000,
      greetingTimeout: 15000,
      connectionTimeout: 15000,
    } as any);
    client.on("error", () => {});
    await client.connect();
    const list = await client.list();
    const folders = list.filter((f) => !f.flags?.has("\\Noselect")).map((f) => f.path).sort((a, b) => a.localeCompare(b));
    return { ok: true, message: `Connected. ${folders.length} folder(s) found.`, folders };
  } catch (e) {
    return { ok: false, message: describe(e), folders: [] };
  } finally {
    try { await client?.logout(); } catch { try { client?.close(); } catch { /* ignore */ } }
  }
}
