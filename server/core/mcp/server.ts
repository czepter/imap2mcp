import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { TokenContext } from "../types.js";
import { ToolError, errorResult, normalizeError, okResult } from "./errors.js";
import { withAudit } from "../audit/withAudit.js";
import { resolveRequestId } from "../security/requestId.js";
import {
  MAX_BATCH, MAX_PAGE, createDraftTool, listFoldersTool, listMailboxesTool, moveMessageTool,
  readMessageTool, searchMessagesTool, setFlagsTool,
} from "./tools.js";

const mailboxId = z.string().min(1).max(128);
const folder = z.string().min(1).max(512);
const ref = z.object({
  mailbox: mailboxId, folder,
  uidValidity: z.number().int().nonnegative(),
  uid: z.number().int().positive(),
}).describe("Message reference as returned by search_messages / create_draft / move_message");
const email = z.string().min(3).max(320);

/**
 * Build a server whose tool handlers close over the token context of THIS request only.
 * Each handler re-checks policy against live DB grants (inside the tool functions).
 */
export function createMcpServer(ctx: TokenContext, opts: { requestId?: string } = {}): McpServer {
  const server = new McpServer({ name: "imap-bridge", version: "0.1.0" });

  const requestId = opts.requestId ?? resolveRequestId(undefined);

  // Every tool attempt runs inside withAudit: exactly one audit row is written before the result is returned.
  const wrap = <A>(tool: string, mutating: boolean, fn: (ctx: TokenContext, a: A) => unknown | Promise<unknown>) =>
    async (a: A) =>
      withAudit({ tool, clientId: ctx.clientId, requestId, mutating }, a, async () => {
        try { return okResult(await fn(ctx, a)); }
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
    description: "Read headers and/or text body (capped at 200 KB, flag truncated) of one message; each part is subject to your permissions. Does not set \\Seen.",
    inputSchema: { ref, include: z.array(z.enum(["headers", "body"])).min(1).max(2).optional().describe('Default: both') },
  }, wrap("read_message", false, readMessageTool));

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
