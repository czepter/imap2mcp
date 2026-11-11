import type { ImapFlow } from "imapflow";
import { withImap } from "../imap/client.js";
import { ToolError } from "./errors.js";
import type { Addr, BodyResult, Criteria, Header, PageResult, ReadBackend } from "./backend.js";

/** v0 direct IMAP read path. Debug only (SIDECAR_DISABLED=1); same interface and semantics as the sidecar backend. */

const addrs = (l?: { name?: string; address?: string }[]): Addr[] => (l ?? []).map((a) => ({ name: a.name || undefined, address: a.address || undefined }));

function uidValidityOf(c: ImapFlow): number {
  return Number((c.mailbox as { uidValidity?: bigint | number } | false | undefined || { uidValidity: 0 }).uidValidity ?? 0);
}

async function withFolder<T>(c: ImapFlow, folder: string, fn: () => Promise<T>): Promise<T> {
  const lock = await c.getMailboxLock(folder, { readOnly: true });
  try { return await fn(); } finally { lock.release(); }
}

function parseDate(s: string): Date {
  const d = new Date(`${s}T00:00:00Z`);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(s) || Number.isNaN(d.getTime())) throw new ToolError("INVALID_INPUT", "Invalid date");
  return d;
}

function toQuery(c: Criteria): Record<string, unknown> {
  const q: Record<string, unknown> = {};
  if (c.from) q.from = c.from;
  if (c.to) q.to = c.to;
  if (c.subject) q.subject = c.subject;
  if (c.since) q.since = parseDate(c.since);
  if (c.before) q.before = parseDate(c.before);
  if (c.seen !== undefined) q.seen = c.seen;
  if (c.flagged !== undefined) q.flagged = c.flagged;
  if (c.answered !== undefined) q.answered = c.answered;
  if (c.minSize !== undefined) q.larger = c.minSize - 1;
  if (c.maxSize !== undefined) q.smaller = c.maxSize + 1;
  if (Object.keys(q).length === 0) q.all = true;
  return q;
}

async function fetchHeaderRows(c: ImapFlow, uids: number[], uidValidity: number): Promise<Header[]> {
  const out: Header[] = [];
  if (uids.length === 0) return out;
  for await (const m of c.fetch(uids.join(","), { uid: true, envelope: true, flags: true, size: true }, { uid: true })) {
    out.push({
      uid: m.uid, uidValidity,
      flags: [...(m.flags ?? [])],
      subject: m.envelope?.subject ?? null,
      from: addrs(m.envelope?.from), to: addrs(m.envelope?.to), cc: addrs(m.envelope?.cc),
      date: m.envelope?.date ? new Date(m.envelope.date).toISOString() : null,
      messageId: m.envelope?.messageId ?? null,
      size: m.size ?? null,
    });
  }
  return out.sort((x, y) => y.uid - x.uid);
}

interface Node {
  part?: string; type?: string; parameters?: Record<string, string>; disposition?: string; childNodes?: Node[];
}
function leavesOf(n: Node, out: Node[] = []): Node[] {
  if (n.childNodes?.length) n.childNodes.forEach((x) => leavesOf(x, out)); else out.push(n);
  return out;
}

export const directBackend: ReadBackend = {
  async listFolders(mailbox) {
    const list = await withImap(mailbox, (c) => c.list());
    return list.map((f) => ({ path: f.path, delimiter: f.delimiter ?? null, flags: [...(f.flags ?? []), ...(f.specialUse ? [f.specialUse] : [])] }));
  },

  async search(mailbox, folder, criteria, limit, beforeUid): Promise<PageResult> {
    const q = toQuery(criteria);
    return withImap(mailbox, (c) => withFolder(c, folder, async () => {
      const uidValidity = uidValidityOf(c);
      const found = (await c.search(q, { uid: true })) || [];
      let uids = [...found].sort((x, y) => y - x);
      if (beforeUid !== undefined) uids = uids.filter((u) => u < beforeUid);
      const page = uids.slice(0, limit);
      const items = await fetchHeaderRows(c, page, uidValidity);
      return { uidValidity, items, nextBeforeUid: uids.length > page.length ? page[page.length - 1] : undefined };
    }));
  },

  async searchText(mailbox, folder, text, limit) {
    return withImap(mailbox, (c) => withFolder(c, folder, async () => {
      const found = (await c.search({ or: [{ subject: text }, { body: text }] }, { uid: true })) || [];
      return { uidValidity: uidValidityOf(c), uids: [...found].sort((x, y) => y - x).slice(0, limit) };
    }));
  },

  async fetchHeaders(mailbox, folder, uidValidity, uids) {
    return withImap(mailbox, (c) => withFolder(c, folder, async () => {
      if (uidValidityOf(c) !== uidValidity) throw new ToolError("STALE_REFERENCE", "Message reference is stale (UIDVALIDITY changed); search again.");
      return fetchHeaderRows(c, uids, uidValidity);
    }));
  },

  async fetchBody(mailbox, folder, uidValidity, uid, maxBytes): Promise<BodyResult> {
    return withImap(mailbox, (c) => withFolder(c, folder, async () => {
      if (uidValidityOf(c) !== uidValidity) throw new ToolError("STALE_REFERENCE", "Message reference is stale (UIDVALIDITY changed); search again.");
      const m = await c.fetchOne(String(uid), { uid: true, bodyStructure: true }, { uid: true });
      if (!m) throw new ToolError("NOT_FOUND", "Message not found");
      const leaves = leavesOf((m.bodyStructure ?? {}) as Node);
      const isAtt = (n: Node) => n.disposition?.toLowerCase() === "attachment";
      const plain = leaves.find((n) => n.type === "text/plain" && !isAtt(n));
      const html = leaves.find((n) => n.type === "text/html" && !isAtt(n));
      const chosen = plain ?? html ?? (leaves.length === 1 && (leaves[0].type ?? "text/plain").startsWith("text/") ? leaves[0] : undefined);
      if (!chosen) return { truncated: false };
      // download() uses BODY.PEEK, so \Seen is not set.
      const dl = await c.download(String(uid), chosen.part || "1", { uid: true, maxBytes: maxBytes + 1 });
      if (!dl.content) return { truncated: false }; // imapflow 2: no content stream for this part (nothing readable)
      const chunks: Buffer[] = [];
      let len = 0;
      for await (const chunk of dl.content) {
        const b = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        chunks.push(b); len += b.length;
        if (len > maxBytes) break;
      }
      let buf = Buffer.concat(chunks);
      let truncated = false;
      if (buf.length > maxBytes) { buf = buf.subarray(0, maxBytes); truncated = true; }
      let s: string;
      try { s = new TextDecoder(chosen.parameters?.charset || "utf-8").decode(buf); } catch { s = new TextDecoder("utf-8").decode(buf); }
      return chosen === html && !plain ? { html: s, truncated } : { text: s, truncated };
    }));
  },
};
