import { sql } from "drizzle-orm";
import { sqliteTable, text, integer, check, unique, index } from "drizzle-orm/sqlite-core";

const now = sql`(datetime('now'))`;

export const admin = sqliteTable(
  "admin",
  {
    id: integer("id").primaryKey(),
    passwordHash: text("password_hash").notNull(),
    createdAt: text("created_at").notNull().default(now),
  },
  (t) => [check("admin_single_row", sql`${t.id} = 1`)]
);

export const mailboxes = sqliteTable("mailboxes", {
  id: text("id").primaryKey(),
  label: text("label").notNull(),
  imapHost: text("imap_host").notNull(),
  imapPort: integer("imap_port").notNull().default(993),
  imapUsername: text("imap_username").notNull(),
  imapPasswordEnc: text("imap_password_enc").notNull(), // v1:... format
  draftsFolder: text("drafts_folder"),
  createdAt: text("created_at").notNull().default(now),
});

export const oauthClients = sqliteTable("oauth_clients", {
  clientId: text("client_id").primaryKey(),
  clientName: text("client_name"),
  redirectUris: text("redirect_uris").notNull(), // JSON array
  createdAt: text("created_at").notNull().default(now),
  disabled: integer("disabled").notNull().default(0),
});

export const POLICY_OPERATIONS = ["search", "read_headers", "read_body", "draft", "move", "flag"] as const;

export const policyRules = sqliteTable(
  "policy_rules",
  {
    id: text("id").primaryKey(),
    clientId: text("client_id").notNull().references(() => oauthClients.clientId, { onDelete: "cascade" }),
    mailboxId: text("mailbox_id").notNull().references(() => mailboxes.id, { onDelete: "cascade" }),
    // exact IMAP path, or '*' / 'prefix/*' (case-sensitive; no other wildcards)
    folder: text("folder").notNull(),
    operation: text("operation").notNull(),
    effect: text("effect").notNull(),
    createdAt: text("created_at").notNull().default(now),
  },
  (t) => [
    unique("policy_rules_unique").on(t.clientId, t.mailboxId, t.folder, t.operation),
    index("policy_rules_client_mailbox").on(t.clientId, t.mailboxId),
    check("policy_rules_operation", sql`${t.operation} IN ('search','read_headers','read_body','draft','move','flag')`),
    check("policy_rules_effect", sql`${t.effect} IN ('allow','deny')`),
  ]
);

export const oauthCodes = sqliteTable("oauth_codes", {
  codeHash: text("code_hash").primaryKey(),
  clientId: text("client_id").notNull().references(() => oauthClients.clientId, { onDelete: "cascade" }),
  redirectUri: text("redirect_uri").notNull(),
  scopes: text("scopes").notNull(),
  resource: text("resource").notNull(),
  codeChallenge: text("code_challenge").notNull(),
  expiresAt: text("expires_at").notNull(),
  used: integer("used").notNull().default(0),
});

export const oauthTokens = sqliteTable("oauth_tokens", {
  id: text("id").primaryKey(),
  tokenHash: text("token_hash").notNull().unique(),
  refreshHash: text("refresh_hash").unique(),
  clientId: text("client_id").notNull().references(() => oauthClients.clientId, { onDelete: "cascade" }),
  scopes: text("scopes").notNull(),
  resource: text("resource").notNull(),
  expiresAt: text("expires_at").notNull(),
  refreshExpiresAt: text("refresh_expires_at"),
  revoked: integer("revoked").notNull().default(0),
  createdAt: text("created_at").notNull().default(now),
});
