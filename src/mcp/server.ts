import type { Request, Response } from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";
import type { TokenContext } from "../types.js";
import { ToolError, errorResult, normalizeError, okResult } from "./errors.js";
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
export function createMcpServer(ctx: TokenContext): McpServer {
  const server = new McpServer({ name: "imap-bridge", version: "0.1.0" });

  const wrap = <A>(mutating: boolean, fn: (ctx: TokenContext, a: A) => unknown | Promise<unknown>) =>
    async (a: A) => {
      try { return okResult(await fn(ctx, a)); }
      catch (e) { return errorResult(e instanceof ToolError ? e : normalizeError(e, mutating)); }
    };

  server.registerTool("list_mailboxes", {
    description: "List the mailboxes this client may access (ids, labels, granted capabilities).",
    inputSchema: {},
  }, wrap(false, (c) => listMailboxesTool(c)));

  server.registerTool("list_folders", {
    description: "List folders of a mailbox (requires read).",
    inputSchema: { mailbox: mailboxId },
  }, wrap(false, listFoldersTool));

  server.registerTool("search_messages", {
    description: `Search a folder; returns headers only, newest first, max ${MAX_PAGE} per page. Pass nextCursor as cursor for the next page. Does not change read state.`,
    inputSchema: {
      mailbox: mailboxId, folder: folder.default("INBOX"),
      text: z.string().max(200).optional(), from: z.string().max(200).optional(),
      to: z.string().max(200).optional(), subject: z.string().max(200).optional(),
      since: z.string().optional().describe("YYYY-MM-DD"), before: z.string().optional().describe("YYYY-MM-DD"),
      unseen: z.boolean().optional(), flagged: z.boolean().optional(),
      limit: z.number().int().min(1).max(MAX_PAGE).optional(),
      cursor: z.number().int().positive().optional(),
    },
  }, wrap(false, searchMessagesTool));

  server.registerTool("read_message", {
    description: "Read headers and text body (capped at 200 KB, flag truncated) of one message. Does not set \\Seen.",
    inputSchema: { ref },
  }, wrap(false, readMessageTool));

  server.registerTool("create_draft", {
    description: "Save a draft into the mailbox's configured Drafts folder via IMAP APPEND. Never sends. May return UNKNOWN_OUTCOME: do not blindly retry.",
    inputSchema: {
      mailbox: mailboxId, to: z.array(email).max(50).optional(), cc: z.array(email).max(50).optional(),
      subject: z.string().max(998), body: z.string().max(1_000_000), inReplyTo: z.string().max(998).optional(),
    },
  }, wrap(true, createDraftTool));

  server.registerTool("move_message", {
    description: "Move a message to another folder of the same mailbox. Returns identifiers only.",
    inputSchema: { ref, destination: folder },
  }, wrap(true, moveMessageTool));

  server.registerTool("set_flags", {
    description: `Add/remove flags on up to ${MAX_BATCH} messages. \\Deleted and \\Recent are rejected. Reports per-message outcomes; not atomic.`,
    inputSchema: {
      refs: z.array(ref).min(1).max(MAX_BATCH),
      add: z.array(z.string().max(64)).max(16).optional(),
      remove: z.array(z.string().max(64)).max(16).optional(),
    },
  }, wrap(true, setFlagsTool));

  return server;
}

/**
 * Stateless Streamable HTTP handler. Mount at /mcp AFTER bearerAuth (which sets req.tokenContext
 * from the live, validated token). A fresh server+transport is created per request.
 */
export async function handleMcpRequest(req: Request, res: Response): Promise<void> {
  const ctx = req.tokenContext;
  if (!ctx) {
    res.status(401).json({ error: "invalid_token" });
    return;
  }
  if (req.method !== "POST") {
    res.status(405).set("Allow", "POST").json({
      jsonrpc: "2.0", error: { code: -32000, message: "Method not allowed (stateless server)" }, id: null,
    });
    return;
  }
  const server = createMcpServer(ctx);
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  res.on("close", () => { void transport.close(); void server.close(); });
  try {
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch {
    if (!res.headersSent) {
      res.status(500).json({ jsonrpc: "2.0", error: { code: -32603, message: "Internal server error" }, id: null });
    }
  }
}
