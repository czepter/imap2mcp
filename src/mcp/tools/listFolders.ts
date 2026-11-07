import { getImapClient } from "../../imap/client.js";
import { checkPermission } from "../permissions.js";
import type { TokenContext } from "../../types.js";

export const listFoldersDef = {
  name: "list_folders" as const,
  description: "List all mailbox folders in the email account",
  inputSchema: {
    type: "object" as const,
    properties: {},
  },
};

export async function listFolders(ctx: TokenContext) {
  checkPermission(ctx.scopes, "mail:folders");
  const client = await getImapClient(ctx.accountId);
  const folders = await client.list();
  return folders.map((f) => ({
    name: f.name,
    path: f.path,
    delimiter: f.delimiter,
    specialUse: f.specialUse || null,
    listed: f.listed,
  }));
}
