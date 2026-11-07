import { v4 as uuid } from "uuid";
import { getDb } from "../db/database.js";
import { encrypt, decrypt } from "./crypto.js";
import type { ImapAccount } from "../types.js";

interface CreateAccountInput {
  userId: string;
  label: string;
  imapHost: string;
  imapPort: number;
  imapTls: boolean;
  username: string;
  password: string;
  smtpHost?: string;
  smtpPort?: number;
  smtpTls?: boolean;
}

export function createAccount(input: CreateAccountInput): ImapAccount {
  const db = getDb();
  const id = uuid();
  const { ciphertext, iv } = encrypt(input.password);
  db.prepare(`
    INSERT INTO imap_accounts (id, user_id, label, imap_host, imap_port, imap_tls, username, password_encrypted, password_iv, smtp_host, smtp_port, smtp_tls)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id, input.userId, input.label, input.imapHost, input.imapPort,
    input.imapTls ? 1 : 0, input.username, ciphertext, iv,
    input.smtpHost || null, input.smtpPort || 587, input.smtpTls !== false ? 1 : 0
  );
  return db.prepare("SELECT * FROM imap_accounts WHERE id = ?").get(id) as ImapAccount;
}

export function getAccountsByUser(userId: string): ImapAccount[] {
  const db = getDb();
  return db.prepare("SELECT * FROM imap_accounts WHERE user_id = ?").all(userId) as ImapAccount[];
}

export function getAccount(id: string): ImapAccount | null {
  const db = getDb();
  return (db.prepare("SELECT * FROM imap_accounts WHERE id = ?").get(id) as ImapAccount) || null;
}

export function getAccountPassword(account: ImapAccount): string {
  return decrypt(account.password_encrypted, account.password_iv);
}

export function deleteAccount(id: string, userId: string): boolean {
  const db = getDb();
  const result = db.prepare("DELETE FROM imap_accounts WHERE id = ? AND user_id = ?").run(id, userId);
  return result.changes > 0;
}
