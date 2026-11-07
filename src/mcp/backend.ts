import { sidecarEnabled } from "../sidecar/index.js";
import { directBackend } from "./backend-direct.js";
import { sidecarBackend } from "./backend-sidecar.js";

export interface Addr { name?: string; address?: string }

/** Sidecar `Header` (docs/DESIGN_V1.md). */
export interface Header {
  uid: number; uidValidity: number; flags: string[]; subject: string | null;
  from: Addr[]; to: Addr[]; cc: Addr[]; date: string | null; messageId: string | null; size: number | null;
}

export interface FolderInfo { path: string; delimiter: string | null; flags: string[] }

/** Header-level criteria. Dates are YYYY-MM-DD. */
export interface Criteria {
  from?: string; to?: string; subject?: string; since?: string; before?: string;
  seen?: boolean; flagged?: boolean; answered?: boolean; minSize?: number; maxSize?: number;
}

export interface PageResult { uidValidity: number; items: Header[]; nextBeforeUid?: number }
export interface BodyResult { text?: string; html?: string; truncated: boolean }

/**
 * Read-only IMAP operations. Implementations perform NO authorization: callers (src/mcp/tools.ts)
 * authorize before calling and filter after. Stale uidValidity => ToolError STALE_REFERENCE.
 */
export interface ReadBackend {
  listFolders(mailbox: string): Promise<FolderInfo[]>;
  search(mailbox: string, folder: string, criteria: Criteria, limit: number, beforeUid?: number): Promise<PageResult>;
  searchText(mailbox: string, folder: string, text: string, limit: number): Promise<{ uidValidity: number; uids: number[] }>;
  fetchHeaders(mailbox: string, folder: string, uidValidity: number, uids: number[]): Promise<Header[]>;
  fetchBody(mailbox: string, folder: string, uidValidity: number, uid: number, maxBytes: number): Promise<BodyResult>;
}

export function getBackend(): ReadBackend {
  return sidecarEnabled() ? sidecarBackend : directBackend;
}
