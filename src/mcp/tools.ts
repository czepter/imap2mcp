import { randomUUID } from "node:crypto";
import type { ImapFlow } from "imapflow";
import MailComposer from "nodemailer/lib/mail-composer/index.js";
import { getDb } from "../db/database.js";
import { getMailboxCredentials } from "../imap/mailboxes.js";
import { withImap } from "../imap/client.js";
import { allowedMailboxes, anyAllowedMailboxes, assertAllowed } from "../policy/policy.js";
import type { TokenContext } from "../types.js";
import { ToolError, normalizeError } from "./errors.js";

export const MAX_PAGE = 50;
export const MAX_BATCH = 25;
export const MAX_BODY_BYTES = 200 * 1024;

export interface MessageRef { mailbox: string; folder: string; uidValidity: number; uid: number }

type Addr = { name?: string; address?: string };
const addrs = (l?: Addr[]) => (l ?? []).map((a) => ({ name: a.name || undefined, address: a.address || undefined }));

function uidValidityOf(c: ImapFlow): number {
  return Number((c.mailbox as { uidValidity?: bigint | number } | false | undefined || { uidValidity: 0 }).uidValidity ?? 0);
}

async function withFolder<T>(c: ImapFlow, folder: string, readOnly: boolean, fn: () => Promise<T>): Promise<T> {
  const lock = await c.getMailboxLock(folder, { readOnly });
  try { return await fn(); } finally { lock.release(); }
}

function checkFresh(c: ImapFlow, ref: MessageRef): void {
  if (uidValidityOf(c) !== ref.uidValidity) {
    throw new ToolError("STALE_REFERENCE", "Message reference is stale (UIDVALIDITY changed); search again.");
  }
}

// ---------- list_mailboxes ----------
export function listMailboxesTool(ctx: TokenContext) {
  const db = getDb();
  const ids = anyAllowedMailboxes(ctx, db);
  if (ids.length === 0) return { mailboxes: [] };
  const rows = db
    .prepare(`SELECT id, label FROM mailboxes WHERE id IN (${ids.map(() => "?").join(",")}) ORDER BY label`)
    .all(...ids) as { id: string; label: string }[];
  const caps = (["read", "draft", "organize"] as const).map((cap) => [cap, new Set(allowedMailboxes(ctx, cap, db))] as const);
  return {
    mailboxes: rows.map((r) => ({
      id: r.id,
      label: r.label,
      capabilities: caps.filter(([, s]) => s.has(r.id)).map(([cap]) => cap),
    })),
  };
}

// ---------- list_folders ----------
export async function listFoldersTool(ctx: TokenContext, a: { mailbox: string }) {
  assertAllowed(ctx, a.mailbox, "read");
  const list = await withImap(a.mailbox, (c) => c.list());
  return {
    mailbox: a.mailbox,
    folders: list.map((f) => ({ path: f.path, name: f.name, specialUse: f.specialUse ?? null, selectable: !f.flags?.has("\\Noselect") })),
  };
}

// ---------- search_messages ----------
export interface SearchArgs {
  mailbox: string; folder: string; text?: string; from?: string; to?: string; subject?: string;
  since?: string; before?: string; unseen?: boolean; flagged?: boolean; limit?: number; cursor?: number;
}

function parseDate(s: string, field: string): Date {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) throw new ToolError("INVALID_INPUT", `${field} must be YYYY-MM-DD`);
  const d = new Date(`${s}T00:00:00Z`);
  if (Number.isNaN(d.getTime())) throw new ToolError("INVALID_INPUT", `${field} is not a valid date`);
  return d;
}

export async function searchMessagesTool(ctx: TokenContext, a: SearchArgs) {
  assertAllowed(ctx, a.mailbox, "read");
  const limit = Math.min(Math.max(a.limit ?? 20, 1), MAX_PAGE);
  const q: Record<string, unknown> = {};
  if (a.text) q.or = [{ subject: a.text }, { body: a.text }];
  if (a.from) q.from = a.from;
  if (a.to) q.to = a.to;
  if (a.subject) q.subject = a.subject;
  if (a.since) q.since = parseDate(a.since, "since");
  if (a.before) q.before = parseDate(a.before, "before");
  if (a.unseen) q.seen = false;
  if (a.flagged) q.flagged = true;
  if (Object.keys(q).length === 0) q.all = true;

  return withImap(a.mailbox, (c) => withFolder(c, a.folder, true, async () => {
    const uidValidity = uidValidityOf(c);
    const found = (await c.search(q, { uid: true })) || [];
    let uids = [...found].sort((x, y) => y - x);
    if (a.cursor !== undefined) uids = uids.filter((u) => u < a.cursor!);
    const total = found.length;
    const page = uids.slice(0, limit);
    const hasMore = uids.length > page.length;
    const messages: unknown[] = [];
    if (page.length) {
      for await (const m of c.fetch(page.join(","), { uid: true, envelope: true, flags: true, size: true }, { uid: true })) {
        messages.push({
          ref: { mailbox: a.mailbox, folder: a.folder, uidValidity, uid: m.uid },
          subject: m.envelope?.subject ?? null,
          from: addrs(m.envelope?.from),
          to: addrs(m.envelope?.to),
          date: m.envelope?.date ? new Date(m.envelope.date).toISOString() : null,
          flags: [...(m.flags ?? [])],
          size: m.size ?? null,
        });
      }
      (messages as { ref: { uid: number } }[]).sort((x, y) => y.ref.uid - x.ref.uid);
    }
    return { total, limit, messages, nextCursor: hasMore ? page[page.length - 1] : null };
  }));
}

// ---------- read_message ----------
interface Node {
  part?: string; type?: string; parameters?: Record<string, string>; disposition?: string;
  dispositionParameters?: Record<string, string>; size?: number; childNodes?: Node[];
}
function walk(n: Node, out: Node[]): void {
  if (n.childNodes?.length) n.childNodes.forEach((x) => walk(x, out)); else out.push(n);
}

export async function readMessageTool(ctx: TokenContext, a: { ref: MessageRef }) {
  const { ref } = a;
  assertAllowed(ctx, ref.mailbox, "read");
  return withImap(ref.mailbox, (c) => withFolder(c, ref.folder, true, async () => {
    checkFresh(c, ref);
    const m = await c.fetchOne(String(ref.uid), { uid: true, envelope: true, flags: true, bodyStructure: true }, { uid: true });
    if (!m) throw new ToolError("NOT_FOUND", "Message not found");
    const leaves: Node[] = [];
    walk((m.bodyStructure ?? {}) as Node, leaves);
    const isAtt = (n: Node) => n.disposition?.toLowerCase() === "attachment";
    const plain = leaves.find((n) => n.type === "text/plain" && !isAtt(n));
    const html = leaves.find((n) => n.type === "text/html" && !isAtt(n));
    const chosen = plain ?? html ?? (leaves.length === 1 && (leaves[0].type ?? "text/plain").startsWith("text/") ? leaves[0] : undefined);
    let body = "";
    let truncated = false;
    if (chosen) {
      // download() uses BODY.PEEK, so \Seen is not set.
      const dl = await c.download(String(ref.uid), chosen.part || "1", { uid: true, maxBytes: MAX_BODY_BYTES + 1 });
      const chunks: Buffer[] = [];
      let len = 0;
      for await (const chunk of dl.content) {
        const b = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        chunks.push(b); len += b.length;
        if (len > MAX_BODY_BYTES) break;
      }
      let buf = Buffer.concat(chunks);
      if (buf.length > MAX_BODY_BYTES) { buf = buf.subarray(0, MAX_BODY_BYTES); truncated = true; }
      try { body = new TextDecoder(chosen.parameters?.charset || "utf-8").decode(buf); }
      catch { body = new TextDecoder("utf-8").decode(buf); }
    }
    const e = m.envelope;
    return {
      ref,
      subject: e?.subject ?? null,
      from: addrs(e?.from), to: addrs(e?.to), cc: addrs(e?.cc),
      date: e?.date ? new Date(e.date).toISOString() : null,
      messageId: e?.messageId ?? null,
      inReplyTo: e?.inReplyTo ?? null,
      flags: [...(m.flags ?? [])],
      bodyType: chosen === plain && plain ? "text/plain" : chosen ? chosen.type ?? "text/plain" : null,
      body,
      truncated,
      attachments: leaves.filter(isAtt).map((n) => ({
        filename: n.dispositionParameters?.filename ?? n.parameters?.name ?? null, type: n.type ?? null, size: n.size ?? null,
      })),
    };
  }));
}

// ---------- create_draft ----------
export interface DraftArgs { mailbox: string; to?: string[]; cc?: string[]; subject: string; body: string; inReplyTo?: string }

function build(opts: ConstructorParameters<typeof MailComposer>[0]): Promise<Buffer> {
  return new Promise((resolve, reject) =>
    new MailComposer(opts).compile().build((err, buf) => (err ? reject(err) : resolve(buf))));
}

export async function createDraftTool(ctx: TokenContext, a: DraftArgs) {
  assertAllowed(ctx, a.mailbox, "draft");
  const row = getDb().prepare("SELECT drafts_folder FROM mailboxes WHERE id = ?").get(a.mailbox) as { drafts_folder: string | null } | undefined;
  const folder = row?.drafts_folder;
  if (!folder) throw new ToolError("INVALID_INPUT", "No Drafts folder is configured for this mailbox");

  const creds = getMailboxCredentials(a.mailbox);
  const messageId = `<${randomUUID()}@imap2mcp.invalid>`;
  const raw = await build({
    from: creds.user.includes("@") ? creds.user : undefined,
    to: a.to, cc: a.cc, subject: a.subject, text: a.body, messageId,
    inReplyTo: a.inReplyTo, references: a.inReplyTo,
  });

  // From here on the outcome may be ambiguous: never retry automatically.
  let res: Awaited<ReturnType<ImapFlow["append"]>>;
  try {
    res = await withImap(a.mailbox, (c) => c.append(folder, raw, ["\\Draft"]));
  } catch (e) {
    const err = normalizeError(e, true);
    if (err.code === "UNKNOWN_OUTCOME") err.extra = { messageId };
    throw err;
  }
  if (res && res.uid && res.uidValidity) {
    return { ref: { mailbox: a.mailbox, folder: res.destination || folder, uidValidity: Number(res.uidValidity), uid: Number(res.uid) }, messageId };
  }
  throw new ToolError("UNKNOWN_OUTCOME",
    "Draft append was not confirmed with a stable reference; it may exist in the Drafts folder. Do not retry blindly.", { messageId });
}

// ---------- move_message ----------
export async function moveMessageTool(ctx: TokenContext, a: { ref: MessageRef; destination: string }) {
  const { ref, destination } = a;
  assertAllowed(ctx, ref.mailbox, "organize"); // source and destination are in this same, authorized mailbox
  if (destination === ref.folder) throw new ToolError("INVALID_INPUT", "Destination equals source folder");
  let sent = false;
  try {
    return await withImap(ref.mailbox, async (c) => {
      const folders = await c.list();
      if (!folders.some((f) => f.path === destination && !f.flags?.has("\\Noselect"))) {
        throw new ToolError("NOT_FOUND", "Destination folder not found");
      }
      return withFolder(c, ref.folder, false, async () => {
        checkFresh(c, ref);
        const exists = await c.fetchOne(String(ref.uid), { uid: true }, { uid: true });
        if (!exists) throw new ToolError("NOT_FOUND", "Message not found");
        assertAllowed(ctx, ref.mailbox, "organize"); // recheck right before the write
        const opts = { uid: true } as const;
        let map: { destination?: string; uidValidity?: bigint; uidMap?: Map<number, number> } | false;
        sent = true;
        if (c.capabilities.has("MOVE")) {
          map = await c.messageMove(String(ref.uid), destination, opts);
          if (!map) throw new ToolError("UPSTREAM_ERROR", "Server refused the move");
        } else if (c.capabilities.has("UIDPLUS")) {
          // COPY, then flag only this UID and UID EXPUNGE it (imapflow uses UID EXPUNGE when UIDPLUS is present).
          map = await c.messageCopy(String(ref.uid), destination, opts);
          if (!map) throw new ToolError("UPSTREAM_ERROR", "Server refused the copy");
          const flagged = await c.messageFlagsAdd(String(ref.uid), ["\\Deleted"], opts);
          const ok = flagged && (await c.messageDelete(String(ref.uid), opts));
          if (!ok) throw new ToolError("UNKNOWN_OUTCOME", "Message was copied but the original could not be removed", {});
        } else {
          sent = false;
          throw new ToolError("UNSUPPORTED", "Server supports neither MOVE nor UIDPLUS; a safe move is not possible");
        }
        const newUid = map.uidMap?.get(ref.uid);
        return {
          moved: true,
          from: ref,
          newRef: newUid && map.uidValidity
            ? { mailbox: ref.mailbox, folder: map.destination ?? destination, uidValidity: Number(map.uidValidity), uid: newUid }
            : null,
        };
      });
    });
  } catch (e) {
    throw normalizeError(e, sent);
  }
}

// ---------- set_flags ----------
const FORBIDDEN_FLAGS = new Set(["\\deleted", "\\recent"]);
const SYSTEM_FLAGS = new Set(["\\seen", "\\answered", "\\flagged", "\\draft"]);
const KEYWORD = /^[A-Za-z0-9_$.-]{1,64}$/;

export function validateFlags(flags: string[] | undefined): string[] {
  const out: string[] = [];
  for (const f of flags ?? []) {
    const l = f.toLowerCase();
    if (FORBIDDEN_FLAGS.has(l)) throw new ToolError("INVALID_INPUT", `Flag ${f} is not allowed`);
    if (f.startsWith("\\")) {
      if (!SYSTEM_FLAGS.has(l)) throw new ToolError("INVALID_INPUT", `Unsupported system flag ${f}`);
    } else if (!KEYWORD.test(f)) {
      throw new ToolError("INVALID_INPUT", "Invalid keyword flag");
    }
    out.push(f);
  }
  return out;
}

type Outcome = { ref: MessageRef; status: "ok" | "error"; code?: string; message?: string };

export async function setFlagsTool(ctx: TokenContext, a: { refs: MessageRef[]; add?: string[]; remove?: string[] }) {
  const add = validateFlags(a.add);
  const remove = validateFlags(a.remove);
  if (add.length + remove.length === 0) throw new ToolError("INVALID_INPUT", "Provide at least one flag to add or remove");
  const lower = new Set(add.map((f) => f.toLowerCase()));
  if (remove.some((f) => lower.has(f.toLowerCase()))) throw new ToolError("INVALID_INPUT", "A flag cannot be both added and removed");
  if (a.refs.length === 0 || a.refs.length > MAX_BATCH) throw new ToolError("INVALID_INPUT", `refs must contain 1..${MAX_BATCH} items`);

  // Authorize every mailbox up front: nothing is executed if any is denied.
  for (const m of new Set(a.refs.map((r) => r.mailbox))) assertAllowed(ctx, m, "organize");

  const groups = new Map<string, MessageRef[]>();
  for (const r of a.refs) {
    const k = JSON.stringify([r.mailbox, r.folder, r.uidValidity]);
    groups.set(k, [...(groups.get(k) ?? []), r]);
  }
  const outcomes: Outcome[] = [];
  const fail = (r: MessageRef, e: unknown) => {
    const te = normalizeError(e, true);
    outcomes.push({ ref: r, status: "error", code: te.code, message: te.message });
  };

  for (const refs of groups.values()) {
    const { mailbox, folder } = refs[0];
    try {
      assertAllowed(ctx, mailbox, "organize"); // recheck immediately before execution
      await withImap(mailbox, (c) => withFolder(c, folder, false, async () => {
        try { checkFresh(c, refs[0]); } catch (e) { refs.forEach((r) => fail(r, e)); return; }
        const uids = [...new Set(refs.map((r) => r.uid))];
        const present = new Set<number>();
        for await (const m of c.fetch(uids.join(","), { uid: true }, { uid: true })) present.add(m.uid);
        const live = uids.filter((u) => present.has(u));
        for (const r of refs) if (!present.has(r.uid)) outcomes.push({ ref: r, status: "error", code: "NOT_FOUND", message: "Message not found" });
        if (live.length === 0) return;
        const range = live.join(",");
        if (add.length) await c.messageFlagsAdd(range, add, { uid: true });
        if (remove.length) await c.messageFlagsRemove(range, remove, { uid: true });
        for (const r of refs) if (present.has(r.uid)) outcomes.push({ ref: r, status: "ok" });
      }));
    } catch (e) {
      const done = new Set(outcomes.map((o) => o.ref));
      refs.filter((r) => !done.has(r)).forEach((r) => fail(r, e));
    }
  }
  return {
    results: a.refs.map((r) => outcomes.find((o) => o.ref === r)!),
    succeeded: outcomes.filter((o) => o.status === "ok").length,
    failed: outcomes.filter((o) => o.status === "error").length,
  };
}
