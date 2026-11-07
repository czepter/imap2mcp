import type { Session } from "express-session";

export interface ImapAccount {
  id: string;
  user_id: string;
  label: string;
  imap_host: string;
  imap_port: number;
  imap_tls: number;
  username: string;
  password_encrypted: string;
  password_iv: string;
  smtp_host: string | null;
  smtp_port: number;
  smtp_tls: number;
  created_at: string;
}

export interface User {
  id: string;
  username: string;
  password_hash: string;
  created_at: string;
}

export interface OAuthClient {
  client_id: string;
  client_name: string | null;
  redirect_uris: string;
  grant_types: string;
  response_types: string;
  created_at: string;
}

export interface OAuthCode {
  code: string;
  client_id: string;
  user_id: string;
  account_id: string;
  redirect_uri: string;
  scopes: string;
  code_challenge: string;
  expires_at: string;
  used: number;
}

export interface OAuthToken {
  id: string;
  access_token: string;
  refresh_token: string | null;
  client_id: string;
  user_id: string;
  account_id: string;
  scopes: string;
  access_token_expires_at: string;
  refresh_token_expires_at: string | null;
  revoked: number;
}

export const SCOPES = {
  "mail:folders": "List mailbox folders",
  "mail:read": "Read email messages",
  "mail:search": "Search email messages",
  "mail:modify": "Move, flag, and delete messages",
  "mail:send": "Send email messages",
} as const;

export type Scope = keyof typeof SCOPES;

export interface TokenContext {
  userId: string;
  accountId: string;
  scopes: string[];
  clientId: string;
}

declare module "express-session" {
  interface SessionData {
    userId?: string;
    returnTo?: string;
  }
}

declare module "express" {
  interface Request {
    tokenContext?: TokenContext;
  }
}
