import { getImapClient } from "../../imap/client.js";
import { checkPermission } from "../permissions.js";
import type { TokenContext } from "../../types.js";

export const moveMessageDef = {
  name: "move_message" as const,
  description: "Move an email message to a different folder",
  inputSchema: {
    type: "object" as const,
    properties: {
      folder: { type: "string" as const, description: "Source folder path" },
      uid: { type: "number" as const, description: "Message UID" },
      destination: { type: "string" as const, description: "Destination folder path" },
    },
    required: ["folder" as const, "uid" as const, "destination" as const],
  },
};

export async function moveMessage(ctx: TokenContext, args: { folder: string; uid: number; destination: string }) {
  checkPermission(ctx.scopes, "mail:modify");
  const client = await getImapClient(ctx.accountId);

  const lock = await client.getMailboxLock(args.folder);
  try {
    await client.messageMove(String(args.uid), args.destination, { uid: true });
    return { success: true, message: `Moved message ${args.uid} to ${args.destination}` };
  } finally {
    lock.release();
  }
}
