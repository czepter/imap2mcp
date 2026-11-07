import { ImapConnectError, ImapTimeoutError } from "../imap/client.js";
import { PolicyError } from "../types.js";
import {
  RPC_STALE_REFERENCE, RPC_TIMEOUT, RPC_UPSTREAM, SidecarRpcError, SidecarTimeoutError, SidecarUnavailableError,
} from "../sidecar/errors.js";

export type ToolErrorCode =
  | "FORBIDDEN" | "NOT_FOUND" | "STALE_REFERENCE" | "INVALID_INPUT"
  | "UNSUPPORTED" | "UPSTREAM_ERROR" | "UNKNOWN_OUTCOME";

export class ToolError extends Error {
  constructor(readonly code: ToolErrorCode, message: string, public extra?: Record<string, unknown>) {
    super(message);
    this.name = "ToolError";
  }
}

/**
 * Convert any thrown value to a ToolError without leaking upstream details (hosts, credentials, server text).
 * `mutating`: the operation may already have reached the server, so ambiguity becomes UNKNOWN_OUTCOME.
 */
export function normalizeError(e: unknown, mutating = false): ToolError {
  if (e instanceof ToolError) return e;
  if (e instanceof PolicyError) return new ToolError("FORBIDDEN", "Access denied");
  if (e instanceof ImapConnectError) return new ToolError("UPSTREAM_ERROR", "Mailbox is unreachable");
  if (e instanceof ImapTimeoutError) {
    return mutating
      ? new ToolError("UNKNOWN_OUTCOME", "Operation timed out; it may or may not have been applied. Verify before retrying.")
      : new ToolError("UPSTREAM_ERROR", "Mailbox operation timed out");
  }
  if (e instanceof SidecarRpcError) {
    if (e.code === RPC_STALE_REFERENCE) return new ToolError("STALE_REFERENCE", "Message reference is stale (UIDVALIDITY changed); search again.");
    if (e.code === RPC_UPSTREAM && /nonexist|not found|no such/i.test(e.message)) return new ToolError("NOT_FOUND", "Folder not found");
    if (e.code === RPC_TIMEOUT) return new ToolError("UPSTREAM_ERROR", "Mailbox operation timed out");
    return new ToolError("UPSTREAM_ERROR", "Mailbox operation failed"); // never forward sidecar text
  }
  if (e instanceof SidecarUnavailableError || e instanceof SidecarTimeoutError) {
    return new ToolError("UPSTREAM_ERROR", "Mailbox service is unavailable");
  }
  const err = e as { mailboxMissing?: boolean; serverResponseCode?: string } | undefined;
  if (err?.mailboxMissing || err?.serverResponseCode === "NONEXISTENT") {
    return new ToolError("NOT_FOUND", "Folder not found");
  }
  return mutating
    ? new ToolError("UNKNOWN_OUTCOME", "Operation failed in an unclear state; verify before retrying.")
    : new ToolError("UPSTREAM_ERROR", "Mailbox operation failed");
}

export function errorResult(e: ToolError) {
  return {
    isError: true as const,
    content: [{ type: "text" as const, text: JSON.stringify({ code: e.code, message: e.message, ...(e.extra ?? {}) }) }],
  };
}

export function okResult(data: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(data) }] };
}
