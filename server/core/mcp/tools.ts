import { randomUUID } from "node:crypto";
import type { ImapFlow } from "imapflow";
import MailComposer from "nodemailer/lib/mail-composer/index.js";
import { getDb } from "../db/database.js";
import { getMailboxCredentials } from "../imap/mailboxes.js";
import { ImapAuthError, ImapConnectError, ImapTimeoutError, OPERATION_TIMEOUT_MS, withImap } from "../imap/client.js";
import { remainingMs, withBudget } from "../imap/budget.js";
import { auditNote } from "../audit/context.js";
import { log } from "../log.js";
import {
  allowedMailboxes, anyAllowedMailboxes, assertOp, filterAllowedFolders, isOpAllowed, mailboxHasAllow, type Operation,
} from "../policy/policy.js";
import { getSidecar, sidecarEnabled } from "../sidecar/index.js";
import { PolicyError, type TokenContext } from "../types.js";
import { getBackend, type BodyResult, type Criteria, type FolderInfo, type Header, type ReadBackend } from "./backend.js";
import { ToolError, isDefiniteRejection, normalizeError } from "./errors.js";
import { assertMailboxUsable } from "./reliability.js";

export const MAX_PAGE = 50;
export const MAX_BATCH = 25;
export const MAX_BODY_BYTES = 200 * 1024;

export interface MessageRef { mailbox: string; folder: string; uidValidity: number; uid: number }

/** After a Node-side write, tell the sidecar its cached view of these folders is stale. Best effort; never fails the write. */
async function invalidateAfterWrite(mailbox: string, folders: string[]): Promise<void> {
  if (!sidecarEnabled()) return;
  const sc = getSidecar();
  await Promise.all([...new Set(folders)].map((f) => sc.invalidate(mailbox, f)));
}

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

/** Time kept back from a write attempt so a reconcile read still fits in the 30 s tool budget. */
const RECONCILE_RESERVE_MS = 8_000;

function writeTimeoutMs(): number {
  const rem = remainingMs();
  if (rem === undefined) return OPERATION_TIMEOUT_MS;
  return Math.max(1_000, Math.min(OPERATION_TIMEOUT_MS, rem - RECONCILE_RESERVE_MS));
}

/**
 * Could the server have applied the write although we got an error? Only failures that happened before the command
 * was issued (policy, connect, auth) or explicit server rejections (NO/BAD, specific response codes) are certain.
 */
export function isAmbiguousWriteFailure(e: unknown): boolean {
  if (e instanceof ToolError || e instanceof PolicyError) return false;
  if (e instanceof ImapAuthError || e instanceof ImapConnectError) return false;
  if (e instanceof ImapTimeoutError) return true;
  return !isDefiniteRejection(e);
}


/**
 * imapflow's messageMove/messageCopy/messageFlags(Add|Remove)/messageDelete swallow command errors (including lost
 * connections) and return false. Run one and make the failure explicit:
 *  - server answered NO/BAD (tagged response arrived): definite refusal, never applied -> ToolError;
 *  - connection lost / no tagged response: ambiguous -> the underlying error is rethrown so callers reconcile.
 * Writes are never replayed.
 */
async function strictWrite<T>(c: ImapFlow, what: string, fn: () => Promise<T | false | undefined>): Promise<T> {
  const lg = (c as unknown as { log?: { warn?: (...a: unknown[]) => unknown } }).log;
  let captured: unknown;
  const orig = lg?.warn;
  if (lg) lg.warn = (...a: unknown[]) => { const o = a[0] as { err?: unknown } | undefined; if (o && typeof o === "object" && o.err) captured = o.err; return orig?.apply(lg, a); };
  let r: T | false | undefined;
  try { r = await fn(); } finally { if (lg) lg.warn = orig; }
  if (r !== false && r !== undefined) return r;
  const sock = (c as unknown as { socket?: { destroyed?: boolean } }).socket;
  const lost = !c.usable || !sock || sock.destroyed === true;
  const x = captured as { responseStatus?: string } | undefined;
  const refused = !lost && (x ? (x.responseStatus === "NO" || x.responseStatus === "BAD" || isDefiniteRejection(x)) : false);
  if (refused) {
    const te = normalizeError(captured, true);
    // An unclassified NO/BAD is a plain refusal, not an unclear state.
    throw te.code === "UNKNOWN_OUTCOME" ? new ToolError("UPSTREAM_ERROR", `Server refused the ${what}`, undefined, { retryable: false }) : te;
  }
  if (captured && !lost && !x?.responseStatus) throw captured;
  const e = (captured as Error | undefined) ?? Object.assign(new Error("Connection lost"), { code: "NoConnection" });
  throw e;
}

/** Writes are never marked retryable. */
function writeError(e: unknown): ToolError {
  const te = normalizeError(e, true);
  te.retryable = false;
  return te;
}

/** Find the UIDs of a message by Message-ID in a folder (read-only). Caller must have re-checked policy. */
async function findByMessageId(
  mailbox: string, folder: string, messageId: string, recheck?: () => void,
): Promise<{ uidValidity: number; uids: number[] }> {
  return withImap(mailbox, (c) => withFolder(c, folder, true, async () => {
    recheck?.(); // policy re-checked after the (possibly slow) verification connection is open, immediately before SEARCH
    const found = (await c.search({ header: { "message-id": messageId } }, { uid: true })) || [];
    return { uidValidity: uidValidityOf(c), uids: [...found].sort((a, b) => a - b) };
  }));
}

/**
 * Read-path gate for an explicit folder. No read-type access to the mailbox at all => FORBIDDEN (same as an unknown mailbox).
 * Otherwise a folder where any required op is denied answers EXACTLY like a nonexistent folder (existence oracle),
 * without touching the sidecar.
 */
function assertFolderReadable(ctx: TokenContext, mailbox: string, folder: string, ops: Operation[]): void {
  if (!mailboxHasAllow(ctx, mailbox, ops)) throw new PolicyError();
  if (!ops.every((o) => isOpAllowed(ctx, mailbox, folder, o))) {
    auditNote({ denied: true }); // policy-masked NOT_FOUND: the audit log records the truth
    throw new ToolError("NOT_FOUND", "Folder not found");
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
const SPECIAL_USE = new Set(["\\Drafts", "\\Sent", "\\Trash", "\\Junk", "\\Archive", "\\All", "\\Flagged", "\\Important"]);
const NOT_SELECTABLE = new Set(["\\noselect", "\\nonexistent"]);
const READ_OPS: Operation[] = ["search", "read_headers", "read_body"];

function selectable(f: FolderInfo): boolean {
  return !f.flags.some((x) => NOT_SELECTABLE.has(x.toLowerCase()));
}

async function listFoldersImpl(ctx: TokenContext, a: { mailbox: string }) {
  // Mailbox-level gate before touching the sidecar: no rule reaching a scope => same answer as an unknown mailbox.
  if (!mailboxHasAllow(ctx, a.mailbox, READ_OPS)) throw new PolicyError();
  auditNote({ mailboxId: a.mailbox });
  const all = (await getBackend().listFolders(a.mailbox)).filter(selectable);
  const allowed = new Set(filterAllowedFolders(ctx, a.mailbox, READ_OPS, all.map((f) => f.path)));
  const visible = all.filter((f) => allowed.has(f.path));
  if (visible.length === 0) throw new PolicyError(); // no readable folders: indistinguishable from no access
  return {
    mailbox: a.mailbox,
    folders: visible.map((f) => {
      const d = f.delimiter;
      return {
        path: f.path,
        name: d ? f.path.split(d).pop() || f.path : f.path,
        specialUse: f.flags.find((x) => SPECIAL_USE.has(x)) ?? null,
        selectable: true,
      };
    }),
  };
}

// ---------- search_messages ----------
export interface SearchArgs {
  mailbox: string; folder?: string; text?: string; from?: string; to?: string; subject?: string;
  since?: string; before?: string; unseen?: boolean; flagged?: boolean; limit?: number; cursor?: number | string;
}

function parseDate(s: string, field: string): string {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(s) || Number.isNaN(new Date(`${s}T00:00:00Z`).getTime())) {
    throw new ToolError("INVALID_INPUT", `${field} must be YYYY-MM-DD`);
  }
  return s;
}

const TEXT_CAP = 500; // sidecar result cap

interface FolderPage { folder: string; uidValidity: number; items: Header[]; hasMore: boolean }

async function searchFolder(
  b: ReadBackend, mailbox: string, folder: string, criteria: Criteria, text: string | undefined, limit: number, beforeUid?: number,
): Promise<FolderPage> {
  if (!text) {
    const r = await b.search(mailbox, folder, criteria, limit, beforeUid);
    return { folder, uidValidity: r.uidValidity, items: r.items, hasMore: r.nextBeforeUid !== undefined };
  }
  // Body text goes to remote IMAP SEARCH; header-level criteria come from the cache. Intersect.
  const t = await b.searchText(mailbox, folder, text, TEXT_CAP);
  const textUids = new Set(t.uids);
  const hasOther = Object.keys(criteria).length > 0;
  if (hasOther) {
    const r = await b.search(mailbox, folder, criteria, TEXT_CAP, beforeUid);
    const m = r.items.filter((h) => textUids.has(h.uid));
    return { folder, uidValidity: r.uidValidity, items: m.slice(0, limit), hasMore: m.length > limit || r.nextBeforeUid !== undefined };
  }
  const uids = [...textUids].filter((u) => beforeUid === undefined || u < beforeUid).sort((x, y) => y - x);
  const page = uids.slice(0, limit);
  const items = (await b.fetchHeaders(mailbox, folder, t.uidValidity, page)).sort((x, y) => y.uid - x.uid);
  return { folder, uidValidity: t.uidValidity, items, hasMore: uids.length > page.length };
}

/** Number of matches in one folder (capped: TEXT_CAP per request, at most 20 requests). Bodies are never fetched. */
async function countMatches(
  b: ReadBackend, mailbox: string, folder: string, criteria: Criteria, text: string | undefined,
): Promise<number> {
  let textUids: Set<number> | undefined;
  if (text) {
    textUids = new Set((await b.searchText(mailbox, folder, text, TEXT_CAP)).uids);
    if (Object.keys(criteria).length === 0) return textUids.size;
  }
  let n = 0;
  let before: number | undefined;
  for (let i = 0; i < 20; i++) {
    const r = await b.search(mailbox, folder, criteria, TEXT_CAP, before);
    n += textUids ? r.items.filter((h) => textUids!.has(h.uid)).length : r.items.length;
    if (r.nextBeforeUid === undefined) break;
    before = r.nextBeforeUid;
  }
  return n;
}

function encodeCursor(state: Record<string, number>): string {
  return Buffer.from(JSON.stringify({ v: 1, f: state })).toString("base64url");
}
function decodeCursor(c: string): Record<string, number> {
  try {
    const o = JSON.parse(Buffer.from(c, "base64url").toString("utf8")) as { v?: number; f?: Record<string, unknown> };
    if (o.v !== 1 || !o.f || typeof o.f !== "object") throw new Error();
    const out: Record<string, number> = {};
    for (const [k, v] of Object.entries(o.f)) if (Number.isInteger(v) && (v as number) >= 0) out[k] = v as number;
    return out;
  } catch { throw new ToolError("INVALID_INPUT", "Invalid cursor"); }
}

const dateKey = (h: Header) => (h.date ? Date.parse(h.date) || 0 : 0);

async function mapLimit<T, R>(items: T[], n: number, fn: (x: T) => Promise<R>): Promise<PromiseSettledResult<R>[]> {
  const out: PromiseSettledResult<R>[] = new Array(items.length);
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => {
    while (i < items.length) {
      const k = i++;
      try { out[k] = { status: "fulfilled", value: await fn(items[k]) }; } catch (e) { out[k] = { status: "rejected", reason: e }; }
    }
  }));
  return out;
}

async function searchMessagesImpl(ctx: TokenContext, a: SearchArgs) {
  const limit = Math.min(Math.max(a.limit ?? 20, 1), MAX_PAGE);
  const criteria: Criteria = {};
  if (a.from) criteria.from = a.from;
  if (a.to) criteria.to = a.to;
  if (a.subject) criteria.subject = a.subject;
  if (a.since) criteria.since = parseDate(a.since, "since");
  if (a.before) criteria.before = parseDate(a.before, "before");
  if (a.unseen) criteria.seen = false;
  if (a.flagged) criteria.flagged = true;
  const b = getBackend();
  const msg = (h: Header, folder: string) => ({
    ref: { mailbox: a.mailbox, folder, uidValidity: h.uidValidity, uid: h.uid },
    subject: h.subject, from: h.from, to: h.to, date: h.date, flags: h.flags, size: h.size,
  });
  // Authorization is evaluated again AFTER the data came back (revocation between check and result).
  const stillReadable = (folder: string) =>
    isOpAllowed(ctx, a.mailbox, folder, "search") && isOpAllowed(ctx, a.mailbox, folder, "read_headers");

  if (a.folder !== undefined) {
    // Single folder: denied => FORBIDDEN before the sidecar is touched (no existence/count leak).
    assertFolderReadable(ctx, a.mailbox, a.folder, ["search", "read_headers"]);
    let before: number | undefined;
    if (a.cursor !== undefined) {
      if (typeof a.cursor !== "number") throw new ToolError("INVALID_INPUT", "Invalid cursor for a single-folder search");
      before = a.cursor;
    }
    const r = await searchFolder(b, a.mailbox, a.folder, criteria, a.text, limit, before);
    assertFolderReadable(ctx, a.mailbox, a.folder, ["search", "read_headers"]);
    const items = r.items.slice(0, limit);
    const total = await countMatches(b, a.mailbox, a.folder, criteria, a.text);
    assertFolderReadable(ctx, a.mailbox, a.folder, ["search", "read_headers"]);
    auditNote({ mailboxId: a.mailbox, folder: a.folder, uidValidity: r.uidValidity, uids: items.map((h) => h.uid) });
    return {
      limit,
      total,
      messages: items.map((h) => msg(h, a.folder!)),
      nextCursor: r.hasMore && items.length ? items[items.length - 1].uid : null,
    };
  }

  // All allowed folders.
  if (!mailboxHasAllow(ctx, a.mailbox, ["search", "read_headers"])) throw new PolicyError();
  if (a.cursor !== undefined && typeof a.cursor !== "string") throw new ToolError("INVALID_INPUT", "Invalid cursor for a multi-folder search");
  const cursor = a.cursor !== undefined ? decodeCursor(a.cursor as string) : {};
  const all = (await b.listFolders(a.mailbox)).filter(selectable).map((f) => f.path);
  const folders = filterAllowedFolders(ctx, a.mailbox, ["search"], all).filter((f) => isOpAllowed(ctx, a.mailbox, f, "read_headers"));
  if (folders.length === 0) throw new PolicyError();

  const active = folders.filter((f) => cursor[f] !== 0);
  const settled = await mapLimit(active, 4, (f) => searchFolder(b, a.mailbox, f, criteria, a.text, limit, cursor[f] || undefined));
  const pages: FolderPage[] = [];
  let firstErr: unknown;
  settled.forEach((s) => { if (s.status === "fulfilled") pages.push(s.value); else firstErr ??= s.reason; });
  if (pages.length === 0 && firstErr) throw firstErr;

  const live = pages.filter((p) => stillReadable(p.folder));
  const heads = live.map((p) => ({ p, i: 0 }));
  const out: { h: Header; folder: string }[] = [];
  const taken = new Map<string, number>();
  while (out.length < limit) {
    let best: (typeof heads)[number] | undefined;
    for (const h of heads) {
      if (h.i >= h.p.items.length) continue;
      if (!best || dateKey(h.p.items[h.i]) > dateKey(best.p.items[best.i])) best = h;
    }
    if (!best) break;
    out.push({ h: best.p.items[best.i], folder: best.p.folder });
    taken.set(best.p.folder, best.i + 1);
    best.i++;
  }
  // total over the folders that were allowed (and still are) only
  const totals = await mapLimit(live.map((p) => p.folder), 4, (f) => countMatches(b, a.mailbox, f, criteria, a.text));
  const total = totals.reduce((n, t, i) => (t.status === "fulfilled" && stillReadable(live[i].folder) ? n + t.value : n), 0);
  const state: Record<string, number> = {};
  let more = false;
  for (const f of folders) {
    const p = live.find((x) => x.folder === f);
    if (!p) { if (cursor[f] !== undefined) state[f] = cursor[f]; continue; } // failed/denied this round: keep position
    const n = taken.get(f) ?? 0;
    const remaining = p.items.length - n > 0 || p.hasMore;
    if (!remaining) { state[f] = 0; continue; }
    more = true;
    if (n > 0) state[f] = p.items[n - 1].uid;
    else if (cursor[f] !== undefined) state[f] = cursor[f];
  }
  // multi-folder: the folder differs per hit, so record the per-folder breakdown
  const byFolder = new Map<string, { folder: string; uidValidity: number; uids: number[] }>();
  for (const x of out) {
    const e = byFolder.get(x.folder) ?? { folder: x.folder, uidValidity: x.h.uidValidity, uids: [] };
    e.uids.push(x.h.uid);
    byFolder.set(x.folder, e);
  }
  auditNote({ mailboxId: a.mailbox, refs: [...byFolder.values()] });
  return {
    limit,
    total,
    messages: out.map((x) => msg(x.h, x.folder)),
    nextCursor: more ? encodeCursor(state) : null,
  };
}

// ---------- read_message ----------
/** Denied read of a ref: no read access to the mailbox => FORBIDDEN, else the same answer as a nonexistent folder. */
function deniedRead(ctx: TokenContext, ref: MessageRef): never {
  if (!mailboxHasAllow(ctx, ref.mailbox, ["read_headers", "read_body"])) throw new PolicyError();
  auditNote({ denied: true });
  throw new ToolError("NOT_FOUND", "Folder not found");
}

async function readMessageImpl(ctx: TokenContext, a: { ref: MessageRef; include?: ("headers" | "body")[] }) {
  const { ref } = a;
  auditNote({ mailboxId: ref.mailbox, folder: ref.folder, uidValidity: ref.uidValidity, uids: [ref.uid] });
  const want = new Set(a.include && a.include.length ? a.include : ["headers", "body"]);
  const headers = want.has("headers") && isOpAllowed(ctx, ref.mailbox, ref.folder, "read_headers");
  const body = want.has("body") && isOpAllowed(ctx, ref.mailbox, ref.folder, "read_body");
  if (!headers && !body) deniedRead(ctx, ref);
  const b = getBackend();

  let h: Header | undefined;
  if (headers) {
    const fetchOne = async () => (await b.fetchHeaders(ref.mailbox, ref.folder, ref.uidValidity, [ref.uid])).find((x) => x.uid === ref.uid);
    h = await fetchOne();
    if (!h) {
      // Cache miss: the cached view may be older than the server (new mail, UIDVALIDITY change). Re-sync once before deciding.
      await invalidateAfterWrite(ref.mailbox, [ref.folder]);
      h = await fetchOne();
    }
    if (!h) throw new ToolError("NOT_FOUND", "Message not found");
  }
  let bodyRes: BodyResult | undefined;
  if (body) bodyRes = await b.fetchBody(ref.mailbox, ref.folder, ref.uidValidity, ref.uid, MAX_BODY_BYTES);

  // Recheck after the data arrived: revocation in the meantime withholds the corresponding part.
  const headersOut = headers && isOpAllowed(ctx, ref.mailbox, ref.folder, "read_headers") ? h : undefined;
  const bodyOut = body && isOpAllowed(ctx, ref.mailbox, ref.folder, "read_body") ? bodyRes : undefined;
  if (!headersOut && !bodyOut) deniedRead(ctx, ref);

  const out: Record<string, unknown> = { ref };
  if (headersOut) {
    Object.assign(out, {
      subject: headersOut.subject, from: headersOut.from, to: headersOut.to, cc: headersOut.cc,
      date: headersOut.date, messageId: headersOut.messageId, inReplyTo: null, flags: headersOut.flags,
    });
  }
  if (bodyOut) {
    let text = bodyOut.text ?? bodyOut.html ?? "";
    let truncated = bodyOut.truncated;
    if (Buffer.byteLength(text) > MAX_BODY_BYTES) { text = Buffer.from(text).subarray(0, MAX_BODY_BYTES).toString("utf8"); truncated = true; }
    Object.assign(out, {
      bodyType: bodyOut.text ? "text/plain" : bodyOut.html ? "text/html" : null,
      body: text, truncated, attachments: [],
    });
  } else if (want.has("body")) {
    out.bodyDenied = true; // the caller learns only about its own rights, never about the mailbox
  }
  return out;
}

// ---------- create_draft ----------
export interface DraftArgs { mailbox: string; to?: string[]; cc?: string[]; subject: string; body: string; inReplyTo?: string }

function build(opts: ConstructorParameters<typeof MailComposer>[0]): Promise<Buffer> {
  return new Promise((resolve, reject) =>
    new MailComposer(opts).compile().build((err, buf) => (err ? reject(err) : resolve(buf))));
}

async function createDraftImpl(ctx: TokenContext, a: DraftArgs) {
  const row = getDb().prepare("SELECT drafts_folder FROM mailboxes WHERE id = ?").get(a.mailbox) as { drafts_folder: string | null } | undefined;
  const folder = row?.drafts_folder;
  // `draft` is evaluated against the mailbox's configured Drafts folder; an unconfigured/unknown mailbox is just denied.
  if (!folder) { if (!mailboxHasAllow(ctx, a.mailbox, ["draft"])) throw new PolicyError(); throw new ToolError("INVALID_INPUT", "No Drafts folder is configured for this mailbox"); }
  assertOp(ctx, a.mailbox, folder, "draft");
  assertMailboxUsable(a.mailbox); // latched mailbox: answer AUTH_FAILED without contacting the server
  auditNote({ mailboxId: a.mailbox, folder });

  const creds = getMailboxCredentials(a.mailbox);
  const messageId = `<${randomUUID()}@imap2mcp.invalid>`;
  const raw = await build({
    from: creds.user.includes("@") ? creds.user : undefined,
    to: a.to, cc: a.cc, subject: a.subject, text: a.body, messageId,
    inReplyTo: a.inReplyTo, references: a.inReplyTo,
  });

  const done = (uidValidity: number, uid: number, dest: string, reconciled: boolean) => {
    auditNote({ uidValidity, uids: [uid], ...(reconciled ? { reconciled: true } : {}) });
    return { ref: { mailbox: a.mailbox, folder: dest, uidValidity, uid }, messageId, ...(reconciled ? { reconciled: true } : {}) };
  };
  const unknown = (why: string) => new ToolError("UNKNOWN_OUTCOME",
    `${why} The draft may or may not exist in the Drafts folder; it will not be re-created automatically. Check the Drafts folder (Message-ID is in the response) before retrying.`,
    { messageId }, { retryable: false });
  /** Verify by Message-ID after an ambiguous failure. Policy is re-checked first: a revoked client must not read. */
  const reconcile = async () => {
    try {
      assertOp(ctx, a.mailbox, folder, "draft");
      const f = await findByMessageId(a.mailbox, folder, messageId, () => assertOp(ctx, a.mailbox, folder, "draft"));
      if (f.uids.length && f.uidValidity) return done(f.uidValidity, f.uids[f.uids.length - 1], folder, true);
    } catch (e) {
      log.warn("draft reconcile could not verify", { mailboxId: a.mailbox, errorCode: normalizeError(e, true).code });
    }
    return null;
  };

  // From here on the outcome may be ambiguous: the APPEND is never replayed.
  let res: Awaited<ReturnType<ImapFlow["append"]>>;
  try {
    res = await withImap(a.mailbox, (c) => {
      assertOp(ctx, a.mailbox, folder, "draft"); // recheck immediately before the write executes
      return c.append(folder, raw, ["\\Draft"]);
    }, { timeoutMs: writeTimeoutMs() });
  } catch (e) {
    try {
      if (!isAmbiguousWriteFailure(e)) {
        const err = writeError(e);
        if (err.code === "UNKNOWN_OUTCOME") err.extra = { messageId };
        throw err;
      }
      const r = await reconcile();
      if (r) return r;
      throw unknown("The connection failed or timed out after the append was sent and the result could not be verified.");
    } finally {
      await invalidateAfterWrite(a.mailbox, [folder]);
    }
  }
  await invalidateAfterWrite(a.mailbox, [folder]);
  if (res && res.uid && res.uidValidity) return done(Number(res.uidValidity), Number(res.uid), res.destination || folder, false);
  // Server accepted but gave no stable reference (no UIDPLUS): resolve it by Message-ID.
  const r = await reconcile();
  if (r) return r;
  throw unknown("Draft append was not confirmed with a stable reference.");
}

// ---------- move_message ----------
async function moveMessageImpl(ctx: TokenContext, a: { ref: MessageRef; destination: string }) {
  const { ref, destination } = a;
  assertOp(ctx, ref.mailbox, ref.folder, "move"); // source AND destination folder, same mailbox
  assertOp(ctx, ref.mailbox, destination, "move");
  if (destination === ref.folder) throw new ToolError("INVALID_INPUT", "Destination equals source folder");
  assertMailboxUsable(ref.mailbox);
  auditNote({ mailboxId: ref.mailbox, folder: ref.folder, uidValidity: ref.uidValidity, uids: [ref.uid] });
  let sent = false;
  let messageId: string | undefined;
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
        assertOp(ctx, ref.mailbox, ref.folder, "move"); // recheck right before the write
        assertOp(ctx, ref.mailbox, destination, "move");
        // Message-ID is only needed to verify the outcome if the connection fails mid-move (best effort).
        try { messageId = (await c.fetchOne(String(ref.uid), { envelope: true }, { uid: true }) || undefined)?.envelope?.messageId || undefined; } catch { /* reconcile will be inconclusive */ }
        const opts = { uid: true } as const;
        let map: { destination?: string; uidValidity?: bigint; uidMap?: Map<number, number> } | false;
        sent = true;
        if (c.capabilities.has("MOVE")) {
          map = await strictWrite(c, "move", () => c.messageMove(String(ref.uid), destination, opts));
        } else if (c.capabilities.has("UIDPLUS")) {
          // COPY, then flag only this UID and UID EXPUNGE it (imapflow uses UID EXPUNGE when UIDPLUS is present).
          map = await strictWrite(c, "copy", () => c.messageCopy(String(ref.uid), destination, opts));
          try {
            await strictWrite(c, "flag", () => c.messageFlagsAdd(String(ref.uid), ["\\Deleted"], opts));
            await strictWrite(c, "delete", () => c.messageDelete(String(ref.uid), opts));
          } catch {
            throw new ToolError("UNKNOWN_OUTCOME", "Message was copied but the original could not be removed", {});
          }
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
    }, { timeoutMs: writeTimeoutMs() });
  } catch (e) {
    if (!sent || !isAmbiguousWriteFailure(e)) throw writeError(e);
    return await reconcileMove(ctx, ref, destination, messageId);
  } finally {
    if (sent) await invalidateAfterWrite(ref.mailbox, [ref.folder, destination]);
  }
}

/**
 * Ambiguous MOVE (connection dropped/timed out after the command was sent): verify, never replay.
 * destination has the Message-ID and the source UID is gone => success (reconciled);
 * source still present and destination lacks it => UNKNOWN_OUTCOME with likelyNotApplied; anything else => UNKNOWN_OUTCOME.
 */
async function reconcileMove(ctx: TokenContext, ref: MessageRef, destination: string, messageId: string | undefined) {
  const unknown = (likelyNotApplied: boolean) => new ToolError("UNKNOWN_OUTCOME",
    likelyNotApplied
      ? "The move was probably not applied (the message is still in the source folder), but this could not be fully confirmed. It was not retried automatically."
      : "The move may or may not have been applied and could not be verified. It was not retried automatically; search both folders before retrying.",
    likelyNotApplied ? { likelyNotApplied: true } : undefined, { retryable: false });
  try {
    // Policy is re-checked before EVERY reconcile read: a revocation mid-failure must not read.
    assertOp(ctx, ref.mailbox, ref.folder, "move");
    assertOp(ctx, ref.mailbox, destination, "move");
    const srcState = await withImap(ref.mailbox, (c) => withFolder(c, ref.folder, true, async () => {
      assertOp(ctx, ref.mailbox, ref.folder, "move");
      assertOp(ctx, ref.mailbox, destination, "move");
      if (uidValidityOf(c) !== ref.uidValidity) return "unknown" as const;
      const m = await c.fetchOne(String(ref.uid), { uid: true }, { uid: true });
      return m ? ("present" as const) : ("gone" as const);
    }));
    if (!messageId) throw unknown(false);
    assertOp(ctx, ref.mailbox, ref.folder, "move");
    assertOp(ctx, ref.mailbox, destination, "move");
    const dest = await findByMessageId(ref.mailbox, destination, messageId, () => {
      assertOp(ctx, ref.mailbox, ref.folder, "move");
      assertOp(ctx, ref.mailbox, destination, "move");
    });
    if (dest.uids.length && srcState === "gone") {
      const uid = dest.uids[dest.uids.length - 1];
      auditNote({ reconciled: true });
      return { moved: true, from: ref, newRef: { mailbox: ref.mailbox, folder: destination, uidValidity: dest.uidValidity, uid }, reconciled: true };
    }
    if (!dest.uids.length && srcState === "present") throw unknown(true);
  } catch (e) {
    if (e instanceof ToolError) throw e;
    log.warn("move reconcile could not verify", { mailboxId: ref.mailbox, errorCode: normalizeError(e, true).code });
  }
  throw unknown(false);
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

type Outcome = { ref: MessageRef; status: "ok" | "error"; code?: string; message?: string; reconciled?: boolean };

const sameFlag = (a: string, b: string) => a.toLowerCase() === b.toLowerCase();

async function setFlagsImpl(ctx: TokenContext, a: { refs: MessageRef[]; add?: string[]; remove?: string[] }) {
  const add = validateFlags(a.add);
  const remove = validateFlags(a.remove);
  if (add.length + remove.length === 0) throw new ToolError("INVALID_INPUT", "Provide at least one flag to add or remove");
  const lower = new Set(add.map((f) => f.toLowerCase()));
  if (remove.some((f) => lower.has(f.toLowerCase()))) throw new ToolError("INVALID_INPUT", "A flag cannot be both added and removed");
  if (a.refs.length === 0 || a.refs.length > MAX_BATCH) throw new ToolError("INVALID_INPUT", `refs must contain 1..${MAX_BATCH} items`);

  // Authorize every (mailbox, folder) up front: nothing is executed if any is denied.
  for (const k of new Set(a.refs.map((r) => JSON.stringify([r.mailbox, r.folder])))) {
    const [m, f] = JSON.parse(k) as [string, string];
    assertOp(ctx, m, f, "flag");
  }
  for (const m of new Set(a.refs.map((r) => r.mailbox))) assertMailboxUsable(m);

  const groups = new Map<string, MessageRef[]>();
  for (const r of a.refs) {
    const k = JSON.stringify([r.mailbox, r.folder, r.uidValidity]);
    groups.set(k, [...(groups.get(k) ?? []), r]);
  }
  const outcomes: Outcome[] = [];
  const fail = (r: MessageRef, e: unknown) => {
    const te = writeError(e);
    outcomes.push({ ref: r, status: "error", code: te.code, message: te.message });
  };
  const unknownFor = (r: MessageRef, why: string) =>
    outcomes.push({ ref: r, status: "error", code: "UNKNOWN_OUTCOME", message: why });

  /** Ambiguous STORE failure: re-FETCH flags and compare with the desired state. Policy re-checked before the read. */
  const reconcileGroup = async (refs: MessageRef[]) => {
    const { mailbox, folder } = refs[0];
    const pending = () => { const d = new Set(outcomes.map((o) => o.ref)); return refs.filter((r) => !d.has(r)); };
    const why = "The connection failed or timed out while the flags were being changed and the result could not be verified; they may or may not have been applied. Not retried automatically.";
    try {
      assertOp(ctx, mailbox, folder, "flag");
      const uids = [...new Set(pending().map((r) => r.uid))];
      const state = await withImap(mailbox, (c) => withFolder(c, folder, true, async () => {
        if (uidValidityOf(c) !== refs[0].uidValidity) return null;
        const m = new Map<number, Set<string>>();
        for await (const msg of c.fetch(uids.join(","), { uid: true, flags: true }, { uid: true })) m.set(msg.uid, new Set([...(msg.flags ?? [])]));
        return m;
      }));
      for (const r of pending()) {
        const fl = state?.get(r.uid);
        if (!fl) { unknownFor(r, why); continue; }
        const have = [...fl];
        const matches = add.every((f) => have.some((h) => sameFlag(h, f))) && remove.every((f) => !have.some((h) => sameFlag(h, f)));
        if (matches) { outcomes.push({ ref: r, status: "ok", reconciled: true }); auditNote({ reconciled: true }); }
        else unknownFor(r, why);
      }
    } catch (e) {
      log.warn("flag reconcile could not verify", { mailboxId: mailbox, errorCode: normalizeError(e, true).code });
      for (const r of pending()) unknownFor(r, why);
    }
  };

  for (const refs of groups.values()) {
    const { mailbox, folder } = refs[0];
    let attempted = false;
    let storeStarted = false;
    try {
      assertOp(ctx, mailbox, folder, "flag"); // recheck immediately before execution
      attempted = true;
      await withImap(mailbox, (c) => withFolder(c, folder, false, async () => {
        try { checkFresh(c, refs[0]); } catch (e) { refs.forEach((r) => fail(r, e)); return; }
        const uids = [...new Set(refs.map((r) => r.uid))];
        const present = new Set<number>();
        for await (const m of c.fetch(uids.join(","), { uid: true }, { uid: true })) present.add(m.uid);
        const live = uids.filter((u) => present.has(u));
        for (const r of refs) if (!present.has(r.uid)) outcomes.push({ ref: r, status: "error", code: "NOT_FOUND", message: "Message not found" });
        if (live.length === 0) return;
        assertOp(ctx, mailbox, folder, "flag"); // final recheck right before STORE
        const range = live.join(",");
        storeStarted = true;
        if (add.length) await strictWrite(c, "flag change", () => c.messageFlagsAdd(range, add, { uid: true }));
        if (remove.length) await strictWrite(c, "flag change", () => c.messageFlagsRemove(range, remove, { uid: true }));
        for (const r of refs) if (present.has(r.uid)) outcomes.push({ ref: r, status: "ok" });
      }), { timeoutMs: writeTimeoutMs() });
    } catch (e) {
      if (storeStarted && isAmbiguousWriteFailure(e)) await reconcileGroup(refs);
      else {
        const done = new Set(outcomes.map((o) => o.ref));
        refs.filter((r) => !done.has(r)).forEach((r) => fail(r, e));
      }
    } finally {
      if (attempted) await invalidateAfterWrite(mailbox, [folder]);
    }
  }
  const affected = outcomes.filter((o) => o.status === "ok").map((o) => o.ref);
  const gk = new Set(a.refs.map((r) => JSON.stringify([r.mailbox, r.folder, r.uidValidity])));
  const first = a.refs[0];
  auditNote({
    mailboxId: first.mailbox,
    ...(gk.size === 1 ? { folder: first.folder, uidValidity: first.uidValidity } : {}),
    uids: affected.map((r) => r.uid),
  });
  return {
    results: a.refs.map((r) => outcomes.find((o) => o.ref === r)!),
    succeeded: outcomes.filter((o) => o.status === "ok").length,
    failed: outcomes.filter((o) => o.status === "error").length,
  };
}

// ---------- budgeted entry points ----------
// Every upstream tool operation (including retries and reconciliation) must finish within 30 s in total.
export const listFoldersTool = (ctx: TokenContext, a: { mailbox: string }) => withBudget(() => listFoldersImpl(ctx, a));
export const searchMessagesTool = (ctx: TokenContext, a: SearchArgs) => withBudget(() => searchMessagesImpl(ctx, a));
export const readMessageTool = (ctx: TokenContext, a: { ref: MessageRef; include?: ("headers" | "body")[] }) => withBudget(() => readMessageImpl(ctx, a));
export const createDraftTool = (ctx: TokenContext, a: DraftArgs) => withBudget(() => createDraftImpl(ctx, a));
export const moveMessageTool = (ctx: TokenContext, a: { ref: MessageRef; destination: string }) => withBudget(() => moveMessageImpl(ctx, a));
export const setFlagsTool = (ctx: TokenContext, a: { refs: MessageRef[]; add?: string[]; remove?: string[] }) => withBudget(() => setFlagsImpl(ctx, a));
