import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { TokenContext } from "../types.js";
import { ToolError, errorResult, normalizeError, okResult } from "./errors.js";
import type { ToolResult } from "../audit/withAudit.js";
import { withAudit } from "../audit/withAudit.js";
import { resolveRequestId } from "../security/requestId.js";
import {
  MAX_ATTACHMENT_BYTES, MAX_BATCH, MAX_PAGE, createDraftTool, getAttachmentTool, listFoldersTool, listMailboxesTool,
  moveMessageTool, readMessageTool, searchMessagesTool, setFlagsTool, type AttachmentOut,
} from "./tools.js";

const mailboxId = z.string().min(1).max(128);
const folder = z.string().min(1).max(512);
const ref = z.object({
  mailbox: mailboxId, folder,
  uidValidity: z.number().int().nonnegative(),
  uid: z.number().int().positive(),
}).describe("Message reference as returned by search_messages / create_draft / move_message");
const email = z.string().min(3).max(320);

const INLINE_IMAGE = new Set(["image/png", "image/jpeg", "image/gif", "image/webp"]);
const isTextual = (t: string) => t.startsWith("text/") || /^application\/(json|xml|[\w.+-]+\+(json|xml))$/.test(t);

/**
 * First item: JSON metadata (the audit layer reads it). Second item: the file itself, as an image for common image
 * types, as text for textual types, otherwise as a base64 resource blob.
 */
export function attachmentResult(r: AttachmentOut): ToolResult {
  const { data, ...meta } = r;
  const { mailbox, folder, uidValidity, uid } = r.ref;
  const uri = `imap2mcp://attachment/${[mailbox, folder, uidValidity, uid, r.part].map((x) => encodeURIComponent(String(x))).join("/")}`
    + (r.filename ? `/${encodeURIComponent(r.filename)}` : "");
  const file = INLINE_IMAGE.has(r.contentType)
    ? { type: "image" as const, data: data.toString("base64"), mimeType: r.contentType }
    : isTextual(r.contentType)
      ? { type: "resource" as const, resource: { uri, mimeType: r.contentType, text: data.toString("utf8") } }
      : { type: "resource" as const, resource: { uri, mimeType: r.contentType, blob: data.toString("base64") } };
  return { content: [{ type: "text" as const, text: JSON.stringify(meta) }, file] } as unknown as ToolResult;
}

/**
 * Build a server whose tool handlers close over the token context of THIS request only.
 * Each handler re-checks policy against live DB grants (inside the tool functions).
 */
export function createMcpServer(ctx: TokenContext, opts: { requestId?: string } = {}): McpServer {
  const server = new McpServer({ name: "imap-bridge", version: "0.1.0" });

  const requestId = opts.requestId ?? resolveRequestId(undefined);

  // Every tool attempt runs inside withAudit: exactly one audit row is written before the result is returned.
  const wrap = <A, R = unknown>(
    tool: string, mutating: boolean, fn: (ctx: TokenContext, a: A) => R | Promise<R>,
    toResult: (r: R) => ToolResult = okResult,
  ) =>
    async (a: A) =>
      withAudit({ tool, clientId: ctx.clientId, requestId, mutating }, a, async () => {
        try { return toResult(await fn(ctx, a)); }
        catch (e) { return errorResult(e instanceof ToolError ? e : normalizeError(e, mutating), requestId); }
      });

  server.registerTool("list_mailboxes", {
    title: "List mailboxes",
    annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
    description: "List the mailboxes this client may access (ids, labels, granted capabilities).",
    inputSchema: {},
  }, wrap("list_mailboxes", false, (c) => listMailboxesTool(c)));

  server.registerTool("list_folders", {
    title: "List folders",
    annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },
    description: "List the folders of a mailbox that you may read (search/read headers/read body allowed).",
    inputSchema: { mailbox: mailboxId },
  }, wrap("list_folders", false, listFoldersTool));

  server.registerTool("search_messages", {
    title: "Search messages",
    annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },
    description: `Search one folder, or all folders you may search when folder is omitted; returns headers only, newest first, max ${MAX_PAGE} per page. Pass nextCursor as cursor for the next page. Does not change read state.`,
    inputSchema: {
      mailbox: mailboxId, folder: folder.optional().describe("Omit to search every folder you are allowed to search"),
      text: z.string().max(200).optional(), from: z.string().max(200).optional(),
      to: z.string().max(200).optional(), subject: z.string().max(200).optional(),
      since: z.string().optional().describe("YYYY-MM-DD"), before: z.string().optional().describe("YYYY-MM-DD"),
      unseen: z.boolean().optional(), flagged: z.boolean().optional(),
      limit: z.number().int().min(1).max(MAX_PAGE).optional(),
      cursor: z.union([z.number().int().positive(), z.string().min(1).max(4096)]).optional(),
    },
  }, wrap("search_messages", false, searchMessagesTool));

  server.registerTool("read_message", {
    title: "Read message",
    annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },
    description: "Read headers and/or text body (capped at 200 KB, flag truncated) of one message; each part is subject to your permissions. A message with only an HTML body comes back as plain text (convertedFrom: \"text/html\"; links as <url>); pass html: \"raw\" for the markup. With the body you also get `attachments` (part, filename, contentType, approximate size); fetch one with get_attachment. Does not set \\Seen.",
    inputSchema: {
      ref, include: z.array(z.enum(["headers", "body"])).min(1).max(2).optional().describe('Default: both'),
      html: z.enum(["text", "raw"]).optional().describe('HTML-only messages: "text" (default) converts to plain text, "raw" returns the HTML'),
    },
  }, wrap("read_message", false, readMessageTool));

  server.registerTool("get_attachment", {
    title: "Get attachment",
    annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },
    description: `Download one attachment of a message (max ${MAX_ATTACHMENT_BYTES / (1024 * 1024)} MB). part is the value from read_message attachments. Returns metadata, then the file: images inline, text types as text, everything else (e.g. PDF) as a base64 resource. Needs the same permission as reading the body. Does not set \\Seen.`,
    inputSchema: { ref, part: z.string().regex(/^[1-9]\d{0,4}(\.[1-9]\d{0,4}){0,10}$/).describe('IMAP part number from read_message attachments, e.g. "2" or "1.2"') },
  }, wrap("get_attachment", false, getAttachmentTool, attachmentResult));

  server.registerTool("create_draft", {
    title: "Create draft",
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    description: "Save a draft into the mailbox's configured Drafts folder via IMAP APPEND. Never sends. May return UNKNOWN_OUTCOME: do not blindly retry.",
    inputSchema: {
      mailbox: mailboxId, to: z.array(email).max(50).optional(), cc: z.array(email).max(50).optional(),
      subject: z.string().max(998), body: z.string().max(1_000_000), inReplyTo: z.string().max(998).optional(),
    },
  }, wrap("create_draft", true, createDraftTool));

  server.registerTool("move_message", {
    title: "Move message",
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    description: "Move a message to another folder of the same mailbox. Returns identifiers only.",
    inputSchema: { ref, destination: folder },
  }, wrap("move_message", true, moveMessageTool));

  server.registerTool("set_flags", {
    title: "Set flags",
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    description: `Add/remove flags on up to ${MAX_BATCH} messages. \\Deleted and \\Recent are rejected. Reports per-message outcomes; not atomic.`,
    inputSchema: {
      refs: z.array(ref).min(1).max(MAX_BATCH),
      add: z.array(z.string().max(64)).max(16).optional(),
      remove: z.array(z.string().max(64)).max(16).optional(),
    },
  }, wrap("set_flags", true, setFlagsTool));

  return server;
}
