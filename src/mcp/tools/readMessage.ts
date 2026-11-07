import { getImapClient } from "../../imap/client.js";
import { checkPermission } from "../permissions.js";
import type { TokenContext } from "../../types.js";

async function readSingleMessage(client: any, uid: number) {
  const msg = await client.fetchOne(String(uid), {
    envelope: true,
    source: true,
    flags: true,
    uid: true,
  }, { uid: true });

  if (!msg) throw new Error(`Message UID ${uid} not found`);

  const source = (msg as any).source?.toString("utf-8") || "";

  let textBody = "";
  const parts = source.split(/\r?\n\r?\n/);
  if (parts.length > 1) {
    textBody = parts.slice(1).join("\n\n");
  }

  // Try download for cleaner body
  let cleanText = "";
  try {
    const downloaded = await client.download(String(uid), undefined, { uid: true });
    if (downloaded?.content) {
      const chunks: Buffer[] = [];
      for await (const chunk of downloaded.content) {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      }
      cleanText = Buffer.concat(chunks).toString("utf-8");
    }
  } catch {}

  const envelope = (msg as any).envelope;
  const flags = (msg as any).flags;

  return {
    uid: (msg as any).uid,
    subject: envelope?.subject || "(no subject)",
    from: envelope?.from?.map((a: any) => ({ name: a.name, address: a.address })) || [],
    to: envelope?.to?.map((a: any) => ({ name: a.name, address: a.address })) || [],
    cc: envelope?.cc?.map((a: any) => ({ name: a.name, address: a.address })) || [],
    date: envelope?.date?.toISOString() || null,
    flags: Array.from(flags || []),
    body: cleanText || textBody || "(could not extract body)",
    inReplyTo: envelope?.inReplyTo || null,
    messageId: envelope?.messageId || null,
  };
}

export async function readMessage(ctx: TokenContext, args: { folder?: string; uid: number; uids?: number[] }) {
  checkPermission(ctx.scopes, "mail:read");
  const client = await getImapClient(ctx.accountId);
  const folder = args.folder || "INBOX";

  const uidList = args.uids && args.uids.length > 0 ? args.uids.slice(0, 10) : [args.uid];

  const lock = await client.getMailboxLock(folder);
  try {
    if (uidList.length === 1) {
      return await readSingleMessage(client, uidList[0]);
    }

    const messages = [];
    for (const uid of uidList) {
      try {
        messages.push(await readSingleMessage(client, uid));
      } catch (e: any) {
        messages.push({ uid, error: e.message });
      }
    }
    return { messages };
  } finally {
    lock.release();
  }
}
