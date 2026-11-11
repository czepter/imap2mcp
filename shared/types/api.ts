/**
 * DTOs of the admin JSON API (see docs/NUXT_MIGRATION.md). Used by server/api/** and app/**.
 * Wire format is camelCase. Timestamps are ISO-8601 strings (UTC). No secret ever appears here.
 */

export type Capability = "read" | "draft" | "organize";
export type Operation = "search" | "read_headers" | "read_body" | "draft" | "move" | "flag";
export type Effect = "allow" | "deny";
export type RegistrationMode = "dynamic" | "admin";
export type MailboxStatusValue = "ok" | "degraded" | "auth_failed" | "unknown";
export type AuditOutcome = "ok" | "denied" | "failed" | "unknown_outcome";

export interface ApiErrorBody {
  error: { code: string; message: string };
}

export interface SessionInfo {
  setupRequired: boolean;
  authenticated: boolean;
  csrfToken: string;
  registrationMode: RegistrationMode;
  baseUrl: string;
}

export interface SetupRequest { token: string; password: string; password2: string }
export interface LoginRequest { password: string }

export interface Mailbox {
  id: string;
  label: string;
  host: string;
  port: number;
  username: string;
  draftsFolder: string | null;
  createdAt: string;
}

export interface MailboxStatus {
  status: MailboxStatusValue;
  lastErrorCode: string | null;
  lastOkAt: string | null;
  nextRetryAt: string | null;
}

export interface MailboxSummary extends Mailbox {
  status: MailboxStatusValue;
  /** Number of distinct clients holding at least one grant on this mailbox. */
  clientCount: number;
}

export interface MailboxInput {
  label: string;
  host: string;
  port: number;
  username: string;
  /** Required on create; empty or omitted on update keeps the saved password. */
  password?: string;
}

export interface MailboxDetail {
  mailbox: Mailbox;
  status: MailboxStatus;
  /** Clients that hold grants on this mailbox. */
  reach: { clientId: string; clientName: string; capabilities: Capability[] }[];
}

export interface MailboxTestResult { ok: boolean; message: string; folders: string[] }

export interface ClientSummary {
  clientId: string;
  clientName: string;
  createdAt: string;
  disabled: boolean;
}

export interface Grant { clientId: string; mailboxId: string; capability: Capability }

export interface TokenSummary {
  id: string;
  clientId: string;
  clientName: string;
  /** Capabilities the token could use right now: scope ceiling intersected with live grants, per mailbox. */
  reach: { mailboxId: string; mailboxLabel: string; capabilities: Capability[] }[];
  createdAt: string;
  expiresAt: string;
}

export interface Overview {
  registrationMode: RegistrationMode;
  mailboxes: MailboxSummary[];
  clients: ClientSummary[];
  grants: Grant[];
  tokens: TokenSummary[];
}

export interface Rule {
  id: string;
  mailboxId: string;
  folder: string;
  operation: Operation;
  effect: Effect;
  /** false when the selector is malformed (it never matches). */
  selectorValid: boolean;
  createdAt: string;
}

export interface RuleInput { mailboxId: string; folder: string; operation: Operation; effect: Effect }

export interface ClientDetail {
  client: ClientSummary & { redirectUris: string[] };
  mailboxes: {
    id: string;
    label: string;
    draftsFolder: string | null;
    /** Per capability: is the preset fully active for this client on this mailbox. */
    granted: Record<Capability, boolean>;
  }[];
  rules: Rule[];
  activeTokenCount: number;
  help: {
    capabilities: Record<Capability, string>;
    presetOperations: Record<Capability, Operation[]>;
    operations: { operation: Operation; capability: Capability }[];
  };
}

export interface GrantsUpdate { grants: { mailboxId: string; capability: Capability }[] }

export interface ClientCreateRequest { name: string; redirectUris: string[] }

export interface AuditEvent {
  id: string;
  ts: string;
  requestId: string;
  clientId: string | null;
  mailboxId: string | null;
  folder: string | null;
  uidValidity: number | null;
  uid: number | null;
  uids: number[] | null;
  uidsTruncated: boolean;
  tool: string;
  outcome: AuditOutcome;
  errorCode: string | null;
  cached: boolean;
  reconciled: boolean;
  durationMs: number | null;
}

export interface AuditQuery {
  client?: string; mailbox?: string; tool?: string; outcome?: AuditOutcome | ""; from?: string; to?: string; page?: number;
}

export interface AuditPage {
  events: AuditEvent[];
  total: number;
  page: number;
  pages: number;
  pageSize: number;
  options: { clients: string[]; mailboxes: string[]; tools: string[]; outcomes: AuditOutcome[] };
}

/** GET /api/oauth/authorize (the OAuth authorization request as query parameters). */
export interface AuthorizeRequest {
  client: { id: string; name: string; createdAt: string };
  redirectUri: string;
  /** Capabilities the client asked for (the only columns the consent table may show). */
  capabilities: Capability[];
  mailboxes: { id: string; label: string; draftsFolder: string | null }[];
  /** The validated, normalised OAuth params to echo back on POST. */
  params: AuthorizeParams;
}

export interface AuthorizeParams {
  client_id: string;
  redirect_uri: string;
  state?: string;
  response_type: "code";
  code_challenge: string;
  code_challenge_method: "S256";
  resource: string;
  scope: string;
}

export interface AuthorizeDecision {
  params: AuthorizeParams;
  decision: "approve" | "deny";
  grants: { mailboxId: string; capability: Capability }[];
}

/** Protocol errors the old code answered with a redirect to the client are returned this way instead. */
export interface AuthorizeRedirect { redirectTo: string }
