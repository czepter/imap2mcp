import { getSidecar } from "../sidecar/index.js";
import type { Addr, BodyResult, FolderInfo, Header, PageResult, ReadBackend } from "./backend.js";

const SIDECAR_CAP = 500;

function addr(a: unknown): Addr {
  if (typeof a === "string") return { address: a };
  const o = (a ?? {}) as Addr;
  return { name: o.name || undefined, address: o.address || undefined };
}

function header(h: Partial<Header> & { uid: number }, fallbackUidValidity: number): Header {
  return {
    uid: h.uid,
    uidValidity: Number(h.uidValidity ?? fallbackUidValidity),
    flags: [...(h.flags ?? [])],
    subject: h.subject ?? null,
    from: (h.from ?? []).map(addr),
    to: (h.to ?? []).map(addr),
    cc: (h.cc ?? []).map(addr),
    date: h.date ?? null,
    messageId: h.messageId ?? null,
    size: h.size ?? null,
  };
}

const clampLimit = (n: number) => Math.min(Math.max(1, n), SIDECAR_CAP);

export const sidecarBackend: ReadBackend = {
  async listFolders(mailbox): Promise<FolderInfo[]> {
    const r = await getSidecar().callMailbox<{ folders: { path: string; delimiter?: string; flags?: string[] }[] }>(mailbox, "listFolders");
    return (r.folders ?? []).map((f) => ({ path: f.path, delimiter: f.delimiter ?? null, flags: f.flags ?? [] }));
  },

  async search(mailbox, folder, criteria, limit, beforeUid): Promise<PageResult> {
    const params: Record<string, unknown> = { folder, criteria, limit: clampLimit(limit) };
    if (beforeUid !== undefined) params.beforeUid = beforeUid;
    const r = await getSidecar().callMailbox<{ uidValidity: number; items: Header[]; nextBeforeUid?: number }>(mailbox, "search", params);
    return {
      uidValidity: Number(r.uidValidity),
      items: (r.items ?? []).map((h) => header(h, Number(r.uidValidity))),
      nextBeforeUid: r.nextBeforeUid ?? undefined,
    };
  },

  async searchText(mailbox, folder, text, limit) {
    const r = await getSidecar().callMailbox<{ uidValidity: number; uids: number[] }>(mailbox, "searchText", { folder, text, limit: clampLimit(limit) });
    return { uidValidity: Number(r.uidValidity), uids: r.uids ?? [] };
  },

  async fetchHeaders(mailbox, folder, uidValidity, uids) {
    if (uids.length === 0) return [];
    const r = await getSidecar().callMailbox<{ items: Header[] }>(mailbox, "fetchHeaders", { folder, uidValidity, uids });
    return (r.items ?? []).map((h) => header(h, uidValidity));
  },

  async fetchBody(mailbox, folder, uidValidity, uid, maxBytes): Promise<BodyResult> {
    const r = await getSidecar().callMailbox<{ text?: string; html?: string; truncated?: boolean }>(
      mailbox, "fetchBody", { folder, uidValidity, uid, maxBytes });
    return { text: r.text, html: r.html, truncated: !!r.truncated };
  },
};
