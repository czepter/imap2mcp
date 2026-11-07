import { getImapClient } from "../../imap/client.js";
import { checkPermission } from "../permissions.js";
import type { TokenContext } from "../../types.js";

export async function searchMessages(ctx: TokenContext, args: {
  folder?: string; query?: string; from?: string; to?: string;
  since?: string; before?: string; unseen?: boolean; limit?: number; includeBody?: boolean;
}) {
  checkPermission(ctx.scopes, "mail:search");
  const client = await getImapClient(ctx.accountId);
  const folder = args.folder || "INBOX";
  const includeBody = args.includeBody || false;

  const lock = await client.getMailboxLock(folder);
  try {
    const searchCriteria: any = {};

    if (args.query) searchCriteria.or = [{ subject: args.query }, { body: args.query }];
    if (args.from) searchCriteria.from = args.from;
    if (args.to) searchCriteria.to = args.to;
    if (args.since) searchCriteria.since = args.since;
    if (args.before) searchCriteria.before = args.before;
    if (args.unseen) searchCriteria.seen = false;

    const result = await client.search(
      Object.keys(searchCriteria).length > 0 ? searchCriteria : { all: true },
      { uid: true }
    );

    const uids = Array.isArray(result) ? result : [];
    const limit = Math.min(args.limit || 20, 50);
    const selectedUids = uids.slice(-limit);

    if (selectedUids.length === 0) {
      return { messages: [], total: 0 };
    }

    const messages: any[] = [];
    const uidList = selectedUids.join(",");
    for await (const msg of client.fetch(uidList, { envelope: true, flags: true, uid: true }, { uid: true })) {
      const entry: any = {
        uid: (msg as any).uid,
        subject: (msg as any).envelope?.subject || "(no subject)",
        from: (msg as any).envelope?.from?.map((a: any) => ({ name: a.name, address: a.address })) || [],
        to: (msg as any).envelope?.to?.map((a: any) => ({ name: a.name, address: a.address })) || [],
        date: (msg as any).envelope?.date?.toISOString() || null,
        flags: Array.from((msg as any).flags || []),
        messageId: (msg as any).envelope?.messageId || null,
      };

      if (includeBody) {
        try {
          const downloaded = await client.download(String((msg as any).uid), undefined, { uid: true });
          if (downloaded?.content) {
            const chunks: Buffer[] = [];
            for await (const chunk of downloaded.content) {
              chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
            }
            const text = Buffer.concat(chunks).toString("utf-8");
            entry.body = text.slice(0, 2000);
          }
        } catch {
          entry.body = "(could not extract body)";
        }
      }

      messages.push(entry);
    }

    messages.reverse();
    return { messages, total: uids.length };
  } finally {
    lock.release();
  }
}
