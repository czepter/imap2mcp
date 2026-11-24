import type { ImapFlow } from "imapflow";
import { withImap } from "../imap/client.js";
import { ToolError } from "./errors.js";
import type { Addr, AttachmentInfo, AttachmentResult, BodyResult, Criteria, Header, PageResult, RawHeaderResult, ReadBackend } from "./backend.js";

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
  part?: string; type?: string; parameters?: Record<string, string>; disposition?: string;
  dispositionParameters?: Record<string, string>; id?: string; encoding?: string; size?: number; childNodes?: Node[];
}
/** Leaf parts; a forwarded message (message/rfc822) is one leaf, its own parts are not descended into. */
function leavesOf(n: Node, out: Node[] = []): Node[] {
  if (n.childNodes?.length && n.type?.toLowerCase() !== "message/rfc822") n.childNodes.forEach((x) => leavesOf(x, out)); else out.push(n);
  return out;
}

const partOf = (n: Node) => n.part || "1";
const filenameOf = (n: Node) => n.dispositionParameters?.filename || n.parameters?.name || "";

/** Same rule as the sidecar: marked as attachment, has a file name, or is neither text/plain nor text/html. */
function isAttachment(n: Node): boolean {
  if (n.disposition?.toLowerCase() === "attachment" || filenameOf(n)) return true;
  const t = (n.type ?? "text/plain").toLowerCase();
  return t !== "text/plain" && t !== "text/html";
}

function attachmentInfo(n: Node): AttachmentInfo {
  const size = Number(n.size ?? 0);
  return {
    part: partOf(n), filename: filenameOf(n) || null, contentType: (n.type ?? "application/octet-stream").toLowerCase(),
    disposition: n.disposition?.toLowerCase() || null, contentId: n.id ? n.id.replace(/^<|>$/g, "") : null,
    size: n.encoding?.toLowerCase() === "base64" ? Math.floor(((size * 76) / 78) * 3 / 4) : size,
  };
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
      const attachments = leaves.filter(isAttachment).map(attachmentInfo);
      const plain = leaves.find((n) => n.type === "text/plain" && !isAttachment(n));
      const html = leaves.find((n) => n.type === "text/html" && !isAttachment(n));
      const chosen = plain ?? html ?? (leaves.length === 1 && (leaves[0].type ?? "text/plain").startsWith("text/") ? leaves[0] : undefined);
      if (!chosen) return { truncated: false, attachments };
      // download() uses BODY.PEEK, so \Seen is not set.
      const dl = await c.download(String(uid), chosen.part || "1", { uid: true, maxBytes: maxBytes + 1 });
      if (!dl.content) return { truncated: false, attachments }; // imapflow 2: no content stream for this part (nothing readable)
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
      return chosen === html && !plain ? { html: s, truncated, attachments } : { text: s, truncated, attachments };
    }));
  },

  async fetchRawHeader(mailbox, folder, uidValidity, uid, maxBytes): Promise<RawHeaderResult> {
    return withImap(mailbox, (c) => withFolder(c, folder, async () => {
      if (uidValidityOf(c) !== uidValidity) throw new ToolError("STALE_REFERENCE", "Message reference is stale (UIDVALIDITY changed); search again.");
      // BODY.PEEK[HEADER]<0.n>: one partial fetch of the header block, \Seen untouched.
      const m = await c.fetchOne(String(uid), { uid: true, bodyParts: [{ key: "HEADER", start: 0, maxLength: maxBytes + 1 }] }, { uid: true });
      if (!m) throw new ToolError("NOT_FOUND", "Message not found");
      let buf = m.headers ?? Buffer.alloc(0); // imapflow files the HEADER section under `headers`
      let truncated = false;
      if (buf.length > maxBytes) { buf = buf.subarray(0, maxBytes); truncated = true; }
      return { raw: new TextDecoder("utf-8").decode(buf), truncated };
    }));
  },

  async fetchAttachment(mailbox, folder, uidValidity, uid, part, maxBytes): Promise<AttachmentResult> {
    return withImap(mailbox, (c) => withFolder(c, folder, async () => {
      if (uidValidityOf(c) !== uidValidity) throw new ToolError("STALE_REFERENCE", "Message reference is stale (UIDVALIDITY changed); search again.");
      const m = await c.fetchOne(String(uid), { uid: true, bodyStructure: true }, { uid: true });
      if (!m) throw new ToolError("NOT_FOUND", "Message not found");
      const node = leavesOf((m.bodyStructure ?? {}) as Node).find((n) => isAttachment(n) && partOf(n) === part);
      if (!node) return { found: false };
      const attachment = attachmentInfo(node);
      // download() uses BODY.PEEK and undoes the transfer encoding.
      const dl = await c.download(String(uid), part, { uid: true, maxBytes: maxBytes + 1 });
      const chunks: Buffer[] = [];
      let len = 0;
      for await (const chunk of dl.content ?? []) {
        const b = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        chunks.push(b); len += b.length;
        if (len > maxBytes) return { found: true, attachment, tooLarge: true };
      }
      const data = Buffer.concat(chunks);
      return { found: true, attachment: { ...attachment, size: data.length }, tooLarge: false, data };
    }));
  },
};
