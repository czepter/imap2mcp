/**
 * Security view of one message, parsed from its raw header block (read_message include: ["security"]).
 *
 * Pure module: no app imports, no IO. Every header value is attacker-controlled text. It is cut to a length cap and
 * stripped of control and bidi-format characters, but never decoded further, followed or interpreted (the only
 * decoding is RFC 2047 in Reply-To / Sender display names). `parseSecurity` never throws.
 */

export const MAX_RAW_HEADER_BYTES = 256 * 1024;

export type Verdict = "pass" | "fail" | "softfail" | "neutral" | "none" | "temperror" | "permerror" | "policy";
export interface SecAddr { name?: string; address: string }
export interface SecurityInfo {
  auth: { spf: Verdict | null; dkim: Verdict | null; dmarc: Verdict | null; dkimDomains: string[]; raw: string[] };
  replyTo: SecAddr[];
  returnPath: string | null;
  sender: SecAddr | null;
  listUnsubscribe: string | null;
  listId: string | null;
  spam: { flag: string | null; status: string | null; score: number | null };
  xMailer: string | null;
  receivedCount: number;
}

const VERDICTS: ReadonlySet<string> = new Set(["pass", "fail", "softfail", "neutral", "none", "temperror", "permerror", "policy"]);
const verdictOf = (s: string | undefined): Verdict | null => {
  const v = s?.trim().toLowerCase();
  return v && VERDICTS.has(v) ? (v as Verdict) : null;
};

const MAX_VALUE = 512;
const MAX_RAW_AR = 1024;
/** Longest header value kept for parsing; the rest is dropped while unfolding. */
const MAX_HEADER_CHARS = 8192;
const MAX_AR_HEADERS = 3;
const MAX_REPLY_TO = 10;
const MAX_DKIM_DOMAINS = 10;

// C0 (tab is turned into a space first), DEL, C1, line/paragraph separators, zero-width and bidi formatting characters.
const STRIPPED: ReadonlyArray<readonly [number, number]> = [
  [0x00, 0x08], [0x0a, 0x1f], [0x7f, 0x9f], [0x2028, 0x2029], [0x200b, 0x200f], [0x202a, 0x202e], [0x2060, 0x2064], [0x2066, 0x2069], [0xfeff, 0xfeff], [0x061c, 0x061c], [0xe0000, 0xe007f],
];
const isStripped = (cp: number): boolean => {
  for (const [lo, hi] of STRIPPED) if (cp >= lo && cp <= hi) return true;
  return false;
};

/** Remove control and bidi characters, trim, cut to `max` code points (never inside a surrogate pair). Empty => null. */
export function sanitize(s: string, max = MAX_VALUE): string | null {
  if (typeof s !== "string") return null;
  // Work on a bounded prefix: a value never needs more than 2 code units per kept code point plus stripped characters.
  const bounded = (s.length > max * 8 ? s.slice(0, max * 8) : s).trimStart();
  let out = "";
  let n = 0;
  for (const ch of bounded) {
    if (n >= max) break;
    const cp = ch.codePointAt(0) as number;
    if (cp === 0x09) { out += " "; n++; continue; }
    if (isStripped(cp)) continue;
    out += ch;
    n++;
  }
  const t = out.trim();
  return t || null;
}

// ---------- header block ----------
interface HeaderLine { name: string; value: string }

const FIELD_NAME = /^[\x21-\x39\x3b-\x7e]+$/;

/** Unfolded headers of the block, topmost first. Stops at the first empty line. */
function splitHeaders(raw: string): HeaderLine[] {
  const out: HeaderLine[] = [];
  let cur: HeaderLine | undefined;
  let pos = 0;
  const len = raw.length;
  while (pos < len) {
    let nl = raw.indexOf("\n", pos);
    if (nl < 0) nl = len;
    let line = raw.slice(pos, nl);
    pos = nl + 1;
    if (line.endsWith("\r")) line = line.slice(0, -1);
    if (line === "") break;
    const c = line.charCodeAt(0);
    if (c === 0x20 || c === 0x09) {
      if (cur && cur.value.length < MAX_HEADER_CHARS) cur.value += ` ${line.replace(/^[ \t]+/, "")}`;
      continue;
    }
    cur = undefined;
    const colon = line.indexOf(":");
    if (colon <= 0) continue;
    const name = line.slice(0, colon);
    if (!FIELD_NAME.test(name)) continue;
    cur = { name: name.toLowerCase(), value: line.slice(colon + 1).replace(/^[ \t]+/, "") };
    out.push(cur);
  }
  for (const h of out) if (h.value.length > MAX_HEADER_CHARS) h.value = h.value.slice(0, MAX_HEADER_CHARS);
  return out;
}

// ---------- comments and quoted strings ----------
/** Remove RFC 5322 comments (nestable, quote- and escape-aware); each comment becomes one space. Linear. */
function stripComments(s: string): string {
  let out = "";
  let depth = 0;
  let inQuote = false;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (depth > 0) {
      if (ch === "\\") i++;
      else if (ch === "(") depth++;
      else if (ch === ")") { depth--; if (depth === 0) out += " "; }
      continue;
    }
    if (inQuote) {
      out += ch;
      if (ch === "\\" && i + 1 < s.length) out += s[++i];
      else if (ch === '"') inQuote = false;
      continue;
    }
    if (ch === '"') { inQuote = true; out += ch; } else if (ch === "(") depth = 1; else out += ch;
  }
  return out;
}

/** Split on `;` outside quoted strings. */
function splitSemicolons(s: string): string[] {
  const parts: string[] = [];
  let cur = "";
  let inQuote = false;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (inQuote) {
      cur += ch;
      if (ch === "\\" && i + 1 < s.length) cur += s[++i];
      else if (ch === '"') inQuote = false;
    } else if (ch === '"') { inQuote = true; cur += ch; } else if (ch === ";") { parts.push(cur); cur = ""; } else cur += ch;
  }
  parts.push(cur);
  return parts;
}

function unquote(v: string): string {
  if (v.length >= 2 && v.startsWith('"') && v.endsWith('"')) return v.slice(1, -1).replace(/\\(.)/g, "$1");
  return v;
}

// ---------- Authentication-Results (RFC 8601, lenient) ----------
interface AuthResult { method: string; verdict: Verdict | null; props: Map<string, string> }

const RESULT_HEAD = /^([A-Za-z0-9_-]+)(?:\/\d{1,4})?\s*=\s*([A-Za-z0-9_-]*)/;
const PROP = /\s*([A-Za-z0-9_.-]{1,64})\s*=\s*("(?:[^"\\]|\\.)*"|[^\s;]*)/y;

function parseResult(seg: string): AuthResult | null {
  const s = seg.trim();
  const m = RESULT_HEAD.exec(s);
  if (!m) return null;
  const props = new Map<string, string>();
  let pos = m[0].length;
  while (pos < s.length) {
    PROP.lastIndex = pos;
    const p = PROP.exec(s);
    if (p) {
      const key = p[1].toLowerCase();
      if (!props.has(key)) props.set(key, unquote(p[2]));
      pos = PROP.lastIndex;
      if (p[0].length === 0) pos++;
    } else {
      const sp = s.slice(pos).search(/\s\S/);
      if (sp < 0) break;
      pos += sp + 1;
    }
  }
  return { method: m[1].toLowerCase(), verdict: verdictOf(m[2]), props };
}

/** Stands in for the authserv-id of a header that has none (Microsoft 365 / Outlook.com): never equal to a real id (a token containing `=` maps here, so no token can equal it otherwise). */
const NO_ID = "=";

/** Lowercased authserv-id; NO_ID when the header starts directly with a result (`spf=pass ...`); "" when unusable. */
const authservId = (value: string): string => {
  const v = stripComments(value).trim();
  const end = v.search(/[;\s]/);
  const tok = end < 0 ? v : v.slice(0, end);
  return tok.includes("=") ? NO_ID : tok.toLowerCase();
};

const DOMAIN = /^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$/;

function parseAuth(arValues: string[], receivedSpf: string | undefined): SecurityInfo["auth"] {
  const auth: SecurityInfo["auth"] = { spf: null, dkim: null, dmarc: null, dkimDomains: [], raw: [] };
  let spfSeen = false;
  let dmarcSeen = false;
  let dkimSeen = false;

  // Trusted: the topmost header's authserv-id. Only the contiguous run below it with the same id is used; a top header without id is used alone.
  const trusted = arValues.length ? authservId(arValues[0]) : "";
  if (trusted) {
    const used: string[] = [];
    for (const v of arValues) {
      // An id-less header gives nothing to match later headers against (a forger can plant one): it is used alone.
      if (used.length >= MAX_AR_HEADERS || (trusted === NO_ID && used.length >= 1) || authservId(v) !== trusted) break;
      used.push(v);
    }
    for (const v of used) {
      const r = sanitize(v, MAX_RAW_AR);
      if (r) auth.raw.push(r);
      const segs = splitSemicolons(stripComments(v));
      // Segment 0 is `authserv-id [version]`, unless the header has no id and starts with a result.
      for (let i = authservId(v) === NO_ID ? 0 : 1; i < segs.length; i++) {
        const res = parseResult(segs[i]);
        if (!res) continue;
        if (res.method === "spf") {
          if (!spfSeen) auth.spf = res.verdict;
          spfSeen = true;
        } else if (res.method === "dmarc") {
          if (!dmarcSeen) auth.dmarc = res.verdict;
          dmarcSeen = true;
        } else if (res.method === "dkim") {
          if (!dkimSeen) auth.dkim = res.verdict;
          dkimSeen = true;
          if (res.verdict !== "pass") continue;
          auth.dkim = "pass";
          for (const key of ["header.d", "header.i"]) {
            let d = res.props.get(key);
            if (d === undefined) continue;
            if (key === "header.i") d = d.slice(d.lastIndexOf("@") + 1);
            d = d.trim().toLowerCase();
            if (DOMAIN.test(d) && !auth.dkimDomains.includes(d) && auth.dkimDomains.length < MAX_DKIM_DOMAINS) auth.dkimDomains.push(d);
          }
        }
      }
    }
  }
  // Received-SPF only fills a missing spf result; a present but unknown one stays null.
  if (!spfSeen && receivedSpf !== undefined) auth.spf = verdictOf(stripComments(receivedSpf).trim().split(/\s+/, 1)[0]);
  return auth;
}

// ---------- addresses ----------
const ENCODED_WORD = /=\?([^?\s]{1,40})\?([bBqQ])\?([^?\s]{0,200})\?=/g;

function decodeWord(charset: string, enc: string, text: string): string | null {
  try {
    let bytes: Uint8Array;
    if (enc.toLowerCase() === "b") {
      const bin = atob(text);
      bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    } else {
      const t = text.replace(/_/g, " ");
      const arr: number[] = [];
      for (let i = 0; i < t.length; i++) {
        if (t[i] === "=" && /^[0-9A-Fa-f]{2}$/.test(t.slice(i + 1, i + 3))) { arr.push(parseInt(t.slice(i + 1, i + 3), 16)); i += 2; } else arr.push(t.charCodeAt(i) & 0xff);
      }
      bytes = Uint8Array.from(arr);
    }
    return new TextDecoder(charset.split("*")[0], { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

function decodeEncodedWords(s: string): string {
  if (!s.includes("=?")) return s;
  return s.replace(/\?=\s+=\?/g, "?==?").replace(ENCODED_WORD, (all, cs: string, enc: string, text: string) => decodeWord(cs, enc, text) ?? all);
}

interface RawEntry { text: string; addr: string; comment: string; angle: boolean }

/** RFC 5322 address list, flattened (group names dropped). Quote-, comment- and angle-aware, single pass. */
function parseAddressList(value: string, limit: number): SecAddr[] {
  const entries: RawEntry[] = [];
  let e: RawEntry = { text: "", addr: "", comment: "", angle: false };
  let inQuote = false;
  let depth = 0;
  let inAngle = false;
  const push = () => { entries.push(e); e = { text: "", addr: "", comment: "", angle: false }; inAngle = false; };

  for (let i = 0; i < value.length && entries.length < limit * 4; i++) {
    const ch = value[i];
    if (depth > 0) {
      if (ch === "\\") i++;
      else if (ch === "(") depth++;
      else if (ch === ")") depth--;
      else if (depth === 1 && e.comment.length < MAX_VALUE) e.comment += ch;
      continue;
    }
    if (inQuote) {
      let c = ch;
      if (ch === "\\" && i + 1 < value.length) c = value[++i];
      else if (ch === '"') { inQuote = false; continue; }
      if (inAngle) e.addr += c; else e.text += c;
      continue;
    }
    switch (ch) {
      case '"': inQuote = true; break;
      case "(": depth = 1; break;
      case "<": inAngle = true; e.angle = true; e.addr = ""; break;
      case ">": inAngle = false; break;
      case ",": if (inAngle) e.addr += ch; else push(); break;
      case ";": if (inAngle) e.addr += ch; else push(); break;
      case ":": if (inAngle) e.addr = ""; else { e.text = ""; e.comment = ""; } break;
      default: if (inAngle) e.addr += ch; else e.text += ch;
    }
  }
  push();

  const out: SecAddr[] = [];
  for (const x of entries) {
    const rawAddr = (x.angle ? x.addr : x.text).replace(/\s+/g, "");
    const rawName = x.angle ? x.text : x.comment;
    const address = sanitize(rawAddr);
    if (!address || address.split("@").length !== 2 || address.startsWith("@") || address.endsWith("@")) continue;
    const name = sanitize(decodeEncodedWords(rawName.trim()));
    out.push(name ? { name, address } : { address });
    if (out.length >= limit) break;
  }
  return out;
}

// ---------- parseSecurity ----------
const empty = (): SecurityInfo => ({
  auth: { spf: null, dkim: null, dmarc: null, dkimDomains: [], raw: [] },
  replyTo: [], returnPath: null, sender: null, listUnsubscribe: null, listId: null,
  spam: { flag: null, status: null, score: null }, xMailer: null, receivedCount: 0,
});

const NUMBER = /^-?\d+(\.\d+)?$/;

export function parseSecurity(raw: string): SecurityInfo {
  try {
    return parse(typeof raw === "string" ? raw : "");
  } catch {
    return empty();
  }
}

function parse(raw: string): SecurityInfo {
  const out = empty();
  const headers = splitHeaders(raw);
  const by = new Map<string, string[]>();
  for (const h of headers) {
    const l = by.get(h.name);
    if (l) l.push(h.value); else by.set(h.name, [h.value]);
  }
  const top = (n: string): string | undefined => by.get(n)?.[0];
  const single = (n: string): string | null => { const v = top(n); return v === undefined ? null : sanitize(v); };

  out.receivedCount = by.get("received")?.length ?? 0;
  out.auth = parseAuth(by.get("authentication-results") ?? [], top("received-spf"));

  out.listUnsubscribe = single("list-unsubscribe");
  out.listId = single("list-id");
  out.xMailer = single("x-mailer");
  out.spam.flag = single("x-spam-flag");
  out.spam.status = single("x-spam-status");

  const scoreHeader = top("x-spam-score")?.trim();
  if (scoreHeader !== undefined && NUMBER.test(scoreHeader) && Number.isFinite(Number(scoreHeader))) out.spam.score = Number(scoreHeader);
  else {
    const m = /\bscore=(-?\d+(?:\.\d+)?)/i.exec((top("x-spam-status") ?? "").slice(0, 2048));
    if (m && Number.isFinite(Number(m[1]))) out.spam.score = Number(m[1]);
  }

  const rp = top("return-path");
  if (rp !== undefined) {
    let v = rp.trim();
    if (v.startsWith("<") && v.endsWith(">")) v = v.slice(1, -1);
    out.returnPath = sanitize(v);
  }

  const reply = top("reply-to");
  if (reply !== undefined) out.replyTo = parseAddressList(reply, MAX_REPLY_TO);
  const sender = top("sender");
  if (sender !== undefined) out.sender = parseAddressList(sender, 1)[0] ?? null;
  return out;
}
