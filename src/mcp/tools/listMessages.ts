import { getImapClient } from "../../imap/client.js";
import { checkPermission } from "../permissions.js";
import type { TokenContext } from "../../types.js";

export async function listMessages(ctx: TokenContext, args: {
  folder?: string; page?: number; pageSize?: number; includeBody?: boolean;
}) {
  checkPermission(ctx.scopes, "mail:read");
  const client = await getImapClient(ctx.accountId);
  const folder = args.folder || "INBOX";
  const page = args.page || 1;
  const pageSize = Math.min(args.pageSize || 20, 50);
  const includeBody = args.includeBody || false;

  const lock = await client.getMailboxLock(folder);
  try {
    const mailbox = client.mailbox;
    const total = mailbox ? (mailbox as any).exists || 0 : 0;

    if (total === 0) {
      return { messages: [], total, page, pageSize };
    }

    const start = Math.max(1, total - page * pageSize + 1);
    const end = Math.max(1, total - (page - 1) * pageSize);

    const fetchOptions: any = { envelope: true, flags: true, uid: true };
    if (includeBody) fetchOptions.bodyStructure = true;

    const messages: any[] = [];
    for await (const msg of client.fetch(`${start}:${end}`, fetchOptions)) {
      const entry: any = {
        uid: (msg as any).uid,
        seq: (msg as any).seq,
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
    return { messages, total, page, pageSize };
  } finally {
    lock.release();
  }
}
