import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { TokenContext } from "../types.js";
import { getSessionContext } from "./context.js";

import { listFolders } from "./tools/listFolders.js";
import { listMessages } from "./tools/listMessages.js";
import { readMessage } from "./tools/readMessage.js";
import { searchMessages } from "./tools/searchMessages.js";
import { moveMessage } from "./tools/moveMessage.js";
import { flagMessage } from "./tools/flagMessage.js";
import { sendMail } from "./tools/sendMail.js";

function getCtx(extra: any): TokenContext {
  // The session ID is available from the transport
  const sessionId = extra?.sessionId;
  if (sessionId) {
    const ctx = getSessionContext(sessionId);
    if (ctx) return ctx;
  }
  throw new Error("No authentication context available");
}

export function createMcpServer(sessionId: string): McpServer {
  const server = new McpServer({
    name: "imap-bridge",
    version: "1.0.0",
  });

  server.tool(
    "list_folders",
    "List all mailbox folders in the email account",
    {},
    async (_args, extra) => {
      const ctx = getSessionContext(sessionId)!;
      const result = await listFolders(ctx);
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    "list_messages",
    "List email messages in a folder with pagination. Use includeBody=true to get message content inline and avoid separate read_message calls.",
    {
      folder: z.string().optional().default("INBOX").describe("Mailbox folder path"),
      page: z.number().optional().default(1).describe("Page number (1-based)"),
      pageSize: z.number().optional().default(20).describe("Messages per page (max 50)"),
      includeBody: z.boolean().optional().default(false).describe("Include message body preview (up to 2000 chars each) — saves separate read_message calls"),
    },
    async (args) => {
      const ctx = getSessionContext(sessionId)!;
      const result = await listMessages(ctx, args);
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    "read_message",
    "Read full email message(s) by UID including headers and body. Use 'uids' to read multiple messages in one call (up to 10).",
    {
      folder: z.string().optional().default("INBOX").describe("Mailbox folder path"),
      uid: z.number().describe("Message UID (for single message)"),
      uids: z.array(z.number()).optional().describe("Multiple message UIDs to read at once (max 10) — more efficient than separate calls"),
    },
    async (args) => {
      const ctx = getSessionContext(sessionId)!;
      const result = await readMessage(ctx, args);
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    "search_messages",
    "Search email messages by various criteria. Use includeBody=true to get message content inline and avoid separate read_message calls.",
    {
      folder: z.string().optional().default("INBOX").describe("Mailbox folder path"),
      query: z.string().optional().describe("Search text (subject and body)"),
      from: z.string().optional().describe("Filter by sender"),
      to: z.string().optional().describe("Filter by recipient"),
      since: z.string().optional().describe("Messages since date (YYYY-MM-DD)"),
      before: z.string().optional().describe("Messages before date (YYYY-MM-DD)"),
      unseen: z.boolean().optional().describe("Only unread messages"),
      limit: z.number().optional().default(20).describe("Max results"),
      includeBody: z.boolean().optional().default(false).describe("Include message body preview (up to 2000 chars each) — saves separate read_message calls"),
    },
    async (args) => {
      const ctx = getSessionContext(sessionId)!;
      const result = await searchMessages(ctx, args);
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    "move_message",
    "Move an email message to a different folder",
    {
      folder: z.string().describe("Source folder path"),
      uid: z.number().describe("Message UID"),
      destination: z.string().describe("Destination folder path"),
    },
    async (args) => {
      const ctx = getSessionContext(sessionId)!;
      const result = await moveMessage(ctx, args);
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    "flag_message",
    "Set or remove flags on an email (read/unread, star, delete)",
    {
      folder: z.string().optional().default("INBOX").describe("Mailbox folder path"),
      uid: z.number().describe("Message UID"),
      seen: z.boolean().optional().describe("Mark as read/unread"),
      flagged: z.boolean().optional().describe("Star/flag the message"),
      deleted: z.boolean().optional().describe("Mark as deleted"),
    },
    async (args) => {
      const ctx = getSessionContext(sessionId)!;
      const result = await flagMessage(ctx, args);
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    "send_mail",
    "Send an email via SMTP",
    {
      to: z.string().describe("Recipient email(s), comma-separated"),
      subject: z.string().describe("Email subject"),
      body: z.string().describe("Email body (plain text)"),
      cc: z.string().optional().describe("CC address(es)"),
      inReplyTo: z.string().optional().describe("Message-ID to reply to"),
      html: z.string().optional().describe("HTML body (optional)"),
    },
    async (args) => {
      const ctx = getSessionContext(sessionId)!;
      const result = await sendMail(ctx, args);
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    }
  );

  return server;
}
