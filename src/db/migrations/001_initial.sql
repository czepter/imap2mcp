CREATE TABLE admin (id INTEGER PRIMARY KEY CHECK (id=1), password_hash TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now')));
CREATE TABLE mailboxes (
  id TEXT PRIMARY KEY, label TEXT NOT NULL,
  imap_host TEXT NOT NULL, imap_port INTEGER NOT NULL DEFAULT 993,
  imap_username TEXT NOT NULL, imap_password_enc TEXT NOT NULL,   -- v1:... format
  drafts_folder TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now')));
CREATE TABLE oauth_clients (
  client_id TEXT PRIMARY KEY, client_name TEXT, redirect_uris TEXT NOT NULL, -- JSON array
  created_at TEXT NOT NULL DEFAULT (datetime('now')), disabled INTEGER NOT NULL DEFAULT 0);
CREATE TABLE grants (
  client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
  mailbox_id TEXT NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
  capability TEXT NOT NULL CHECK (capability IN ('read','draft','organize')),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (client_id, mailbox_id, capability));
CREATE TABLE oauth_codes (
  code_hash TEXT PRIMARY KEY, client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
  redirect_uri TEXT NOT NULL, scopes TEXT NOT NULL, resource TEXT NOT NULL,
  code_challenge TEXT NOT NULL, expires_at TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0);
CREATE TABLE oauth_tokens (
  id TEXT PRIMARY KEY, token_hash TEXT UNIQUE NOT NULL, refresh_hash TEXT UNIQUE,
  client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
  scopes TEXT NOT NULL, resource TEXT NOT NULL,
  expires_at TEXT NOT NULL, refresh_expires_at TEXT, revoked INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now')));
