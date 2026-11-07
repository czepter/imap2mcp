import { getImapClient } from "../../imap/client.js";
import { checkPermission } from "../permissions.js";
import type { TokenContext } from "../../types.js";

export const flagMessageDef = {
  name: "flag_message" as const,
  description: "Set or remove flags on an email message (seen, flagged, deleted)",
  inputSchema: {
    type: "object" as const,
    properties: {
      folder: { type: "string" as const, description: "Mailbox folder path", default: "INBOX" },
      uid: { type: "number" as const, description: "Message UID" },
      seen: { type: "boolean" as const, description: "Mark as read (true) or unread (false)" },
      flagged: { type: "boolean" as const, description: "Star/flag the message" },
      deleted: { type: "boolean" as const, description: "Mark as deleted" },
    },
    required: ["uid" as const],
  },
};

export async function flagMessage(ctx: TokenContext, args: {
  folder?: string; uid: number; seen?: boolean; flagged?: boolean; deleted?: boolean;
}) {
  checkPermission(ctx.scopes, "mail:modify");
  const client = await getImapClient(ctx.accountId);
  const folder = args.folder || "INBOX";

  const lock = await client.getMailboxLock(folder);
  try {
    const addFlags: string[] = [];
    const removeFlags: string[] = [];

    if (args.seen === true) addFlags.push("\\Seen");
    if (args.seen === false) removeFlags.push("\\Seen");
    if (args.flagged === true) addFlags.push("\\Flagged");
    if (args.flagged === false) removeFlags.push("\\Flagged");
    if (args.deleted === true) addFlags.push("\\Deleted");
    if (args.deleted === false) removeFlags.push("\\Deleted");

    if (addFlags.length > 0) {
      await client.messageFlagsAdd(String(args.uid), addFlags, { uid: true });
    }
    if (removeFlags.length > 0) {
      await client.messageFlagsRemove(String(args.uid), removeFlags, { uid: true });
    }

    return { success: true, added: addFlags, removed: removeFlags };
  } finally {
    lock.release();
  }
}
