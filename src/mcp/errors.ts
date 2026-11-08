import { currentRequestId } from "../audit/context.js";
import { ImapAuthError, ImapConnectError, ImapTimeoutError } from "../imap/client.js";
import { CredentialDecryptError } from "../imap/credentialError.js";
import { PolicyError } from "../types.js";
import {
  RPC_AUTH, RPC_STALE_REFERENCE, RPC_TIMEOUT, RPC_UNKNOWN_MAILBOX, RPC_UPSTREAM,
  SidecarRpcError, SidecarTimeoutError, SidecarUnavailableError,
} from "../sidecar/errors.js";

export type ToolErrorCode =
  | "FORBIDDEN" | "NOT_FOUND" | "STALE_REFERENCE" | "INVALID_INPUT"
  | "UNSUPPORTED" | "UPSTREAM_ERROR" | "UNKNOWN_OUTCOME"
  | "AUTH_FAILED" | "TIMEOUT" | "QUOTA_EXCEEDED" | "FOLDER_UNAVAILABLE" | "PROTOCOL_ERROR" | "UNAVAILABLE";

/** Codes that may be retryable (only ever on reads; writes are never marked retryable). */
const MAYBE_RETRYABLE = new Set<ToolErrorCode>(["TIMEOUT", "UPSTREAM_ERROR", "UNAVAILABLE"]);

const DECRYPT_ACTION = "The server cannot decrypt stored mailbox credentials; check ENCRYPTION_KEY / key file (see docs/RECOVERY.md).";

export const OPERATOR_ACTIONS: Partial<Record<ToolErrorCode, string>> = {
  AUTH_FAILED: "The mail server rejected this mailbox's credentials. In the admin UI update the mailbox password (or press Retry once it is fixed at the provider).",
  QUOTA_EXCEEDED: "The mailbox is over quota or full. Free space or raise the quota at the mail provider.",
  FOLDER_UNAVAILABLE: "The folder exists but the server refused or could not open it. Check the folder's permissions and availability at the mail provider.",
  PROTOCOL_ERROR: "The mail server sent a reply the bridge could not parse. Check the server/provider status and the bridge logs for this requestId.",
  UNAVAILABLE: "A bridge subsystem (audit store or mail sidecar) is down. Check /readyz and the bridge logs for this requestId.",
};

export class ToolError extends Error {
  retryable: boolean;
  operatorAction?: string;
  constructor(
    readonly code: ToolErrorCode, message: string, public extra?: Record<string, unknown>,
    opts: { retryable?: boolean; operatorAction?: string } = {},
  ) {
    super(message);
    this.name = "ToolError";
    this.retryable = opts.retryable ?? MAYBE_RETRYABLE.has(code);
    this.operatorAction = opts.operatorAction ?? OPERATOR_ACTIONS[code];
  }
}

type Upstream = {
  code?: string; serverResponseCode?: string; responseText?: string; responseStatus?: string;
  command?: string; mailboxMissing?: boolean; authenticationFailed?: boolean; message?: string; name?: string;
};

export type Classified = "AUTH_FAILED" | "QUOTA_EXCEEDED" | "FOLDER_UNAVAILABLE" | "NOT_FOUND" | "PROTOCOL_ERROR" | "TIMEOUT";

const TIMEOUT_CODES = new Set(["ETIMEDOUT", "ESOCKETTIMEDOUT", "ETIMEOUT", "TimeoutError"]);

/** Classify an imapflow-style error or sidecar RPC text. Returns null when nothing specific is recognised. */
export function classifyUpstream(e: unknown, text?: string): { kind: Classified; definite: boolean } | null {
  const x = (e ?? {}) as Upstream;
  const src = `${text ?? ""} ${x.responseText ?? ""} ${x.serverResponseCode ?? ""}`;
  const rc = (x.serverResponseCode ?? "").toUpperCase();
  const rejected = x.responseStatus === "NO" || x.responseStatus === "BAD";

  if (x.authenticationFailed === true || /^(AUTHENTICATIONFAILED|AUTHORIZATIONFAILED|AUTH)/.test(rc)
    || /\[(AUTH[A-Z]*)\]|authentication failed|invalid credentials|login failed/i.test(src)) {
    return { kind: "AUTH_FAILED", definite: true };
  }
  if (rc === "OVERQUOTA" || rc === "LIMIT" || /over\s?quota|quota exceeded|mailbox (is )?full|\[LIMIT\]/i.test(src)) {
    return { kind: "QUOTA_EXCEEDED", definite: true };
  }
  if (x.mailboxMissing || rc === "NONEXISTENT" || /\[NONEXISTENT\]|nonexist|no such (mail)?box|unknown mailbox|folder not found/i.test(src)) {
    return { kind: "NOT_FOUND", definite: true };
  }
  if (rc === "UNAVAILABLE" || rc === "NOPERM" || rc === "ACCESSDENIED" || /\[(UNAVAILABLE|NOPERM)\]/i.test(src)) {
    return { kind: "FOLDER_UNAVAILABLE", definite: true };
  }
  if (x.code && TIMEOUT_CODES.has(x.code)) return { kind: "TIMEOUT", definite: false };
  if (x.name === "SyntaxError" || /^(Parse|Protocol)/i.test(x.code ?? "")
    || /malformed|unexpected (token|response|character|end)|invalid (server )?(response|reply)|protocol error|parse error|cannot parse/i.test(`${text ?? ""} ${x.message ?? ""}`)) {
    return { kind: "PROTOCOL_ERROR", definite: false };
  }
  void rejected;
  return null;
}

/** True when the server explicitly refused a command (NO/BAD or a specific response code): the write was NOT applied. */
export function isDefiniteRejection(e: unknown): boolean {
  if (e instanceof ToolError || e instanceof ImapTimeoutError || e instanceof ImapConnectError || e instanceof ImapAuthError) return false;
  const x = (e ?? {}) as Upstream;
  const c = classifyUpstream(e);
  if (c?.definite) return true;
  return x.responseStatus === "NO" || x.responseStatus === "BAD";
}

function fromKind(kind: Classified, mutating: boolean): ToolError {
  const ro = { retryable: false };
  switch (kind) {
    case "AUTH_FAILED": return new ToolError("AUTH_FAILED", "Mailbox credentials were rejected by the mail server", undefined, ro);
    case "QUOTA_EXCEEDED": return new ToolError("QUOTA_EXCEEDED", "Mailbox is over quota or full", undefined, ro);
    case "FOLDER_UNAVAILABLE": return new ToolError("FOLDER_UNAVAILABLE", "Folder is currently unavailable on the mail server", undefined, ro);
    case "NOT_FOUND": return new ToolError("NOT_FOUND", "Folder not found");
    case "PROTOCOL_ERROR":
      return mutating
        ? new ToolError("UNKNOWN_OUTCOME", "The server sent an unreadable reply; the operation may or may not have been applied. Verify before retrying.")
        : new ToolError("PROTOCOL_ERROR", "The mail server sent a reply that could not be understood", undefined, ro);
    case "TIMEOUT":
      return mutating
        ? new ToolError("UNKNOWN_OUTCOME", "Operation timed out; it may or may not have been applied. Verify before retrying.")
        : new ToolError("TIMEOUT", "Mailbox operation timed out");
  }
}

/**
 * Convert any thrown value to a ToolError without leaking upstream details (hosts, credentials, server text).
 * `mutating`: the operation may already have reached the server, so ambiguity becomes UNKNOWN_OUTCOME and
 * `retryable` is never true. Policy-denied folders are handled by the callers and stay NOT_FOUND.
 */
export function normalizeError(e: unknown, mutating = false): ToolError {
  const out = normalizeInner(e, mutating);
  if (mutating) out.retryable = false;
  return out;
}

function normalizeInner(e: unknown, mutating: boolean): ToolError {
  if (e instanceof ToolError) return e;
  if (e instanceof PolicyError) return new ToolError("FORBIDDEN", "Access denied");
  if (e instanceof CredentialDecryptError) {
    return new ToolError("UNAVAILABLE", "Stored mailbox credentials cannot be decrypted", undefined, {
      retryable: false, operatorAction: DECRYPT_ACTION,
    });
  }
  if (e instanceof ImapAuthError) return fromKind("AUTH_FAILED", false);
  if (e instanceof ImapConnectError) {
    // Nothing was sent. A refused connect is a transient upstream problem.
    const c = classifyUpstream(e.cause);
    if (c?.kind === "TIMEOUT") return new ToolError("TIMEOUT", "Mailbox connection timed out");
    if (c && c.kind !== "PROTOCOL_ERROR" && c.kind !== "NOT_FOUND") return fromKind(c.kind, false);
    return new ToolError("UPSTREAM_ERROR", "Mailbox is unreachable");
  }
  if (e instanceof ImapTimeoutError) return fromKind("TIMEOUT", mutating);
  if (e instanceof SidecarRpcError) {
    if (e.code === RPC_STALE_REFERENCE) return new ToolError("STALE_REFERENCE", "Message reference is stale (UIDVALIDITY changed); search again.");
    if (e.code === RPC_TIMEOUT) return new ToolError("TIMEOUT", "Mailbox operation timed out");
    if (e.code === RPC_AUTH) return new ToolError("UNAVAILABLE", "Mailbox service rejected the bridge");
    if (e.code === RPC_UNKNOWN_MAILBOX) return new ToolError("UNAVAILABLE", "Mailbox service does not know this mailbox yet");
    const c = classifyUpstream(undefined, e.message);
    if (c) return fromKind(c.kind, false);
    if (e.code === RPC_UPSTREAM) return new ToolError("UPSTREAM_ERROR", "Mailbox operation failed"); // never forward sidecar text
    return new ToolError("UPSTREAM_ERROR", "Mailbox operation failed");
  }
  if (e instanceof SidecarTimeoutError) return new ToolError("TIMEOUT", "Mailbox operation timed out");
  if (e instanceof SidecarUnavailableError) return new ToolError("UNAVAILABLE", "Mailbox service is unavailable");
  const c = classifyUpstream(e);
  if (c) {
    if (c.definite || !mutating) return fromKind(c.kind, mutating);
    return fromKind(c.kind, true);
  }
  return mutating
    ? new ToolError("UNKNOWN_OUTCOME", "Operation failed in an unclear state; verify before retrying.")
    : new ToolError("UPSTREAM_ERROR", "Mailbox operation failed");
}

export interface ErrorPayload {
  code: ToolErrorCode; message: string; requestId?: string; retryable: boolean; operatorAction?: string;
  [k: string]: unknown;
}

export function errorPayload(e: ToolError, requestId?: string): ErrorPayload {
  const p: ErrorPayload = {
    ...(e.extra ?? {}),
    code: e.code,
    message: e.message,
    requestId: requestId ?? currentRequestId(),
    retryable: e.retryable,
  };
  if (e.operatorAction) p.operatorAction = e.operatorAction;
  return p;
}

export function errorResult(e: ToolError, requestId?: string) {
  return {
    isError: true as const,
    content: [{ type: "text" as const, text: JSON.stringify(errorPayload(e, requestId)) }],
  };
}

export function okResult(data: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(data) }] };
}
