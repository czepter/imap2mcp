/**
 * Minimal in-process IMAP-over-TLS server used as the integration fixture.
 *
 * It implements just enough of RFC 3501 (+UIDPLUS, MOVE, ID, NAMESPACE) for imapflow, and it
 * records every command so tests can assert on wire behaviour (no \Seen side effects, no plain
 * EXPUNGE, no SMTP, ...). It is deliberately faithful where tests depend on it: a non-PEEK
 * BODY[...] fetch DOES set \Seen, plain EXPUNGE DOES remove every \Deleted message.
 */
import tls from "node:tls";
import type { AddressInfo } from "node:net";

export interface FakeMessage {
  uid: number;
  flags: Set<string>;
  raw: Buffer;
  date: Date;
}
export interface FakeFolder {
  name: string;
  uidValidity: number;
  uidNext: number;
  messages: FakeMessage[];
  special?: string; // e.g. \Drafts
}
export interface FakeAccount {
  user: string;
  pass: string;
  folders: Map<string, FakeFolder>;
}
export interface LoggedCommand {
  user: string | null;
  selected: string | null;
  line: string; // literal payloads elided
}

type Tok = string | Buffer | Tok[];

export class FakeImapServer {
  accounts = new Map<string, FakeAccount>();
  commands: LoggedCommand[] = [];
  private server!: tls.Server;
  private sockets = new Set<import("node:net").Socket>();
  port = 0;

  constructor(private opts: { key: string; cert: string }) {}

  async start(): Promise<void> {
    this.server = tls.createServer({ key: this.opts.key, cert: this.opts.cert }, (s) => this.onConn(s));
    await new Promise<void>((r) => this.server.listen(0, "127.0.0.1", r));
    this.port = (this.server.address() as AddressInfo).port;
  }
  async stop(): Promise<void> {
    for (const s of this.sockets) s.destroy();
    await new Promise<void>((r) => this.server.close(() => r()));
  }

  addAccount(user: string, pass: string, folderNames: string[] = ["INBOX", "Drafts", "Archive", "Sent"]): FakeAccount {
    const acct: FakeAccount = { user, pass, folders: new Map() };
    for (const n of folderNames) {
      acct.folders.set(n, {
        name: n,
        uidValidity: 1000 + acct.folders.size,
        uidNext: 1,
        messages: [],
        special: n === "Drafts" ? "\\Drafts" : n === "Sent" ? "\\Sent" : undefined,
      });
    }
    this.accounts.set(user, acct);
    return acct;
  }

  addMessage(user: string, folder: string, raw: string | Buffer, flags: string[] = []): FakeMessage {
    const f = this.accounts.get(user)!.folders.get(folder)!;
    const m: FakeMessage = { uid: f.uidNext++, flags: new Set(flags), raw: Buffer.from(raw), date: new Date("2026-01-02T03:04:05Z") };
    f.messages.push(m);
    return m;
  }
  folder(user: string, name: string): FakeFolder {
    return this.accounts.get(user)!.folders.get(name)!;
  }
  /** Simulate a UIDVALIDITY change (folder recreated). */
  bumpUidValidity(user: string, name: string): void {
    const f = this.folder(user, name);
    f.uidValidity += 7777;
  }
  clearLog(): void {
    this.commands = [];
  }
  commandsFor(user: string): string[] {
    return this.commands.filter((c) => c.user === user).map((c) => c.line);
  }

  // ---------------------------------------------------------------- connection handling
  private onConn(sock: tls.TLSSocket) {
    this.sockets.add(sock);
    sock.on("close", () => this.sockets.delete(sock));
    sock.on("error", () => {});
    const st: { user: string | null; acct: FakeAccount | null; sel: FakeFolder | null } = { user: null, acct: null, sel: null };
    let buf = Buffer.alloc(0);
    let pending: { parts: Buffer[]; need: number; lineSoFar: string; tag: string } | null = null;
    let authTag: string | null = null;

    const write = (s: string | Buffer) => sock.write(s);
    write("* OK [CAPABILITY IMAP4rev1 UIDPLUS MOVE ID NAMESPACE AUTH=PLAIN] fake imap ready\r\n");

    const pump = () => {
      for (;;) {
        if (pending && pending.need > 0) {
          if (buf.length < pending.need) return;
          pending.parts.push(buf.subarray(0, pending.need));
          buf = buf.subarray(pending.need);
          pending.need = 0;
        }
        const idx = buf.indexOf("\r\n");
        if (idx < 0) return;
        const line = buf.subarray(0, idx).toString("utf8");
        buf = buf.subarray(idx + 2);

        if (authTag) {
          const tag = authTag;
          authTag = null;
          const [, u, p] = Buffer.from(line.trim(), "base64").toString("utf8").split("\0");
          this.doLogin(tag, u, p, st, write);
          continue;
        }

        if (pending) {
          pending.lineSoFar += line;
          const m = /\{(\d+)(\+?)\}$/.exec(line);
          if (m) {
            pending.need = parseInt(m[1], 10);
            if (!m[2]) write("+ go ahead\r\n");
            continue;
          }
          const done = pending;
          pending = null;
          this.handle(done.tag, done.lineSoFar, done.parts, st, write, sock);
          continue;
        }

        const m = /\{(\d+)(\+?)\}$/.exec(line);
        const sp = line.indexOf(" ");
        const tag = sp > 0 ? line.slice(0, sp) : line;
        if (m) {
          pending = { parts: [], need: parseInt(m[1], 10), lineSoFar: line, tag };
          if (!m[2]) write("+ go ahead\r\n");
          continue;
        }
        if (/^\S+ AUTHENTICATE PLAIN\s*$/i.test(line)) {
          authTag = tag;
          write("+ \r\n");
          continue;
        }
        this.handle(tag, line, [], st, write, sock);
      }
    };
    sock.on("data", (d) => {
      buf = Buffer.concat([buf, d]);
      pump();
    });
  }

  private doLogin(tag: string, u: string, p: string, st: any, write: (s: string | Buffer) => void) {
    this.commands.push({ user: null, selected: null, line: `${tag} LOGIN-ATTEMPT ${u} ***` });
    const a = this.accounts.get(u);
    if (a && a.pass === p) {
      st.user = u;
      st.acct = a;
      write(`${tag} OK [CAPABILITY IMAP4rev1 UIDPLUS MOVE ID NAMESPACE] logged in\r\n`);
    } else {
      write(`${tag} NO [AUTHENTICATIONFAILED] bad credentials\r\n`);
    }
  }

  private handle(tag: string, line: string, literals: Buffer[], st: any, write: (s: string | Buffer) => void, sock: tls.TLSSocket) {
    // tokenise (literals get substituted in order)
    const rest = line.slice(tag.length + 1);
    const logLine = /^(LOGIN|AUTHENTICATE)/i.test(rest) ? rest.split(" ")[0] + " ***" : rest.replace(/\{\d+\+?\}/g, "{literal}");
    this.commands.push({ user: st.user, selected: st.sel?.name ?? null, line: logLine });

    let toks: Tok[];
    try {
      toks = tokenize(rest, [...literals]);
    } catch {
      return write(`${tag} BAD parse error\r\n`);
    }
    const cmd = String(toks[0]).toUpperCase();
    const args = toks.slice(1);
    const ok = (msg = "completed") => write(`${tag} OK ${cmd} ${msg}\r\n`);
    const no = (msg: string) => write(`${tag} NO ${msg}\r\n`);
    const needAuth = () => {
      if (!st.acct) {
        write(`${tag} NO not authenticated\r\n`);
        return true;
      }
      return false;
    };

    switch (cmd) {
      case "CAPABILITY":
        write("* CAPABILITY IMAP4rev1 UIDPLUS MOVE ID NAMESPACE AUTH=PLAIN\r\n");
        return ok();
      case "NOOP":
      case "CHECK":
        return ok();
      case "ID":
        write('* ID ("name" "fake-imap")\r\n');
        return ok();
      case "ENABLE":
        return ok();
      case "LOGOUT":
        write("* BYE bye\r\n");
        ok();
        sock.end();
        return;
      case "LOGIN":
        return this.doLogin(tag, String(args[0]), String(args[1]), st, write);
      case "NAMESPACE":
        write('* NAMESPACE (("" "/")) NIL NIL\r\n');
        return ok();
    }
    if (needAuth()) return;
    const acct: FakeAccount = st.acct;

    switch (cmd) {
      case "LIST":
      case "LSUB": {
        const pattern = String(args[args.length - 1]);
        if (pattern === "") {
          write(`* ${cmd} (\\Noselect) "/" ""\r\n`);
          return ok();
        }
        for (const f of acct.folders.values()) {
          if (matchPattern(pattern, f.name)) {
            const flags = ["\\HasNoChildren", ...(f.special ? [f.special] : [])].join(" ");
            write(`* ${cmd} (${flags}) "/" ${quote(f.name)}\r\n`);
          }
        }
        return ok();
      }
      case "STATUS": {
        const f = acct.folders.get(String(args[0]));
        if (!f) return no("[NONEXISTENT] no such mailbox");
        const items = (args[1] as Tok[]).map((x) => String(x).toUpperCase());
        const out: string[] = [];
        for (const it of items) {
          if (it === "MESSAGES") out.push(`MESSAGES ${f.messages.length}`);
          else if (it === "UIDNEXT") out.push(`UIDNEXT ${f.uidNext}`);
          else if (it === "UIDVALIDITY") out.push(`UIDVALIDITY ${f.uidValidity}`);
          else if (it === "UNSEEN") out.push(`UNSEEN ${f.messages.filter((m) => !m.flags.has("\\Seen")).length}`);
          else if (it === "RECENT") out.push("RECENT 0");
        }
        write(`* STATUS ${quote(f.name)} (${out.join(" ")})\r\n`);
        return ok();
      }
      case "SELECT":
      case "EXAMINE": {
        const f = acct.folders.get(String(args[0]));
        if (!f) {
          st.sel = null;
          return no("[NONEXISTENT] no such mailbox");
        }
        st.sel = f;
        write(`* ${f.messages.length} EXISTS\r\n* 0 RECENT\r\n* OK [UIDVALIDITY ${f.uidValidity}] ok\r\n* OK [UIDNEXT ${f.uidNext}] ok\r\n`);
        write("* FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)\r\n* OK [PERMANENTFLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft \\*)] ok\r\n");
        return write(`${tag} OK [${cmd === "SELECT" ? "READ-WRITE" : "READ-ONLY"}] ${cmd} completed\r\n`);
      }
      case "CLOSE":
      case "UNSELECT":
        st.sel = null;
        return ok();
      case "CREATE":
      case "SUBSCRIBE":
        return ok();
      case "APPEND": {
        const f = acct.folders.get(String(args[0]));
        if (!f) return no("[TRYCREATE] no such mailbox");
        const lit = args.find((a) => Buffer.isBuffer(a)) as Buffer | undefined;
        if (!lit) return write(`${tag} BAD missing literal\r\n`);
        const flagList = args.find((a) => Array.isArray(a)) as Tok[] | undefined;
        const m: FakeMessage = { uid: f.uidNext++, flags: new Set((flagList ?? []).map(String)), raw: lit, date: new Date() };
        f.messages.push(m);
        return write(`${tag} OK [APPENDUID ${f.uidValidity} ${m.uid}] APPEND completed\r\n`);
      }
    }

    // ---- commands needing a selected folder
    const sel: FakeFolder | null = st.sel;
    if (!sel) return no("no mailbox selected");
    const isUid = cmd === "UID";
    const sub = isUid ? String(args[0]).toUpperCase() : cmd;
    const a = isUid ? args.slice(1) : args;
    const seq = (m: FakeMessage) => sel.messages.indexOf(m) + 1;
    const pick = (set: string) => resolveSet(set, sel, isUid);

    switch (sub) {
      case "SEARCH": {
        let crit = a;
        if (String(crit[0]).toUpperCase() === "CHARSET") crit = crit.slice(2);
        const hits = sel.messages.filter((m) => evalCrit(crit, m, sel));
        write(`* SEARCH${hits.map((m) => " " + (isUid ? m.uid : seq(m))).join("")}\r\n`);
        return ok();
      }
      case "FETCH": {
        const msgs = pick(String(a[0]));
        let items = a[1];
        const macro = typeof items === "string" ? items.toUpperCase() : null;
        if (macro === "ALL") items = ["FLAGS", "INTERNALDATE", "RFC822.SIZE", "ENVELOPE"];
        else if (macro === "FAST") items = ["FLAGS", "INTERNALDATE", "RFC822.SIZE"];
        else if (macro === "FULL") items = ["FLAGS", "INTERNALDATE", "RFC822.SIZE", "ENVELOPE", "BODY"];
        const list = (Array.isArray(items) ? items : [items]).map(String);
        if (isUid && !list.some((x) => x.toUpperCase() === "UID")) list.unshift("UID");
        for (const m of msgs) this.emitFetch(m, seq(m), list, write);
        return ok();
      }
      case "STORE": {
        const msgs = pick(String(a[0]));
        const mode = String(a[1]).toUpperCase();
        const silent = mode.endsWith(".SILENT");
        const flags = (Array.isArray(a[2]) ? (a[2] as Tok[]) : [a[2]]).map(String);
        for (const m of msgs) {
          if (mode.startsWith("+FLAGS")) flags.forEach((f) => m.flags.add(f));
          else if (mode.startsWith("-FLAGS")) flags.forEach((f) => m.flags.delete(f));
          else {
            m.flags.clear();
            flags.forEach((f) => m.flags.add(f));
          }
          if (!silent) write(`* ${seq(m)} FETCH (${isUid ? `UID ${m.uid} ` : ""}FLAGS (${[...m.flags].join(" ")}))\r\n`);
        }
        return ok();
      }
      case "COPY":
      case "MOVE": {
        const dest = acct.folders.get(String(a[1]));
        if (!dest) return no("[TRYCREATE] no such mailbox");
        const msgs = pick(String(a[0]));
        const srcUids: number[] = [];
        const dstUids: number[] = [];
        const removedSeqs: number[] = [];
        for (const m of msgs) {
          const copy: FakeMessage = { uid: dest.uidNext++, flags: new Set(m.flags), raw: m.raw, date: m.date };
          dest.messages.push(copy);
          srcUids.push(m.uid);
          dstUids.push(copy.uid);
        }
        if (sub === "MOVE") {
          for (const m of msgs) removedSeqs.push(seq(m));
          write(`* OK [COPYUID ${dest.uidValidity} ${srcUids.join(",")} ${dstUids.join(",")}] moved\r\n`);
          // report expunges highest seq first so earlier numbers stay valid
          for (const s of [...removedSeqs].sort((x, y) => y - x)) {
            sel.messages.splice(s - 1, 1);
            write(`* ${s} EXPUNGE\r\n`);
          }
        } else {
          write(`${tag} OK [COPYUID ${dest.uidValidity} ${srcUids.join(",")} ${dstUids.join(",")}] COPY completed\r\n`);
          return;
        }
        return ok();
      }
      case "EXPUNGE": {
        // UID EXPUNGE <set> removes only listed \Deleted; plain EXPUNGE removes ALL \Deleted (dangerous).
        const victims = isUid ? pick(String(a[0])).filter((m) => m.flags.has("\\Deleted")) : sel.messages.filter((m) => m.flags.has("\\Deleted"));
        for (const m of [...victims].sort((x, y) => seq(y) - seq(x))) {
          const s = seq(m);
          sel.messages.splice(s - 1, 1);
          write(`* ${s} EXPUNGE\r\n`);
        }
        return ok();
      }
    }
    write(`${tag} BAD unsupported command ${cmd}\r\n`);
  }

  private emitFetch(m: FakeMessage, seqNo: number, items: string[], write: (s: string | Buffer) => void) {
    const { headerBuf, bodyBuf } = splitMessage(m.raw);
    let setSeen = false;
    const out: Buffer[] = [];
    const lit = (label: string, data: Buffer) => out.push(Buffer.concat([Buffer.from(`${label} {${data.length}}\r\n`), data]));
    const str = (x: string) => out.push(Buffer.from(x));
    let flagsIdx = -1;
    for (const raw of items) {
      const it = raw.toUpperCase();
      if (it === "UID") str(`UID ${m.uid}`);
      else if (it === "FLAGS") {
        flagsIdx = out.length;
        str("FLAGS_PLACEHOLDER");
      } else if (it === "INTERNALDATE") str(`INTERNALDATE "${fmtDate(m.date)}"`);
      else if (it === "RFC822.SIZE") str(`RFC822.SIZE ${m.raw.length}`);
      else if (it === "ENVELOPE") str(`ENVELOPE ${envelope(headerBuf.toString("utf8"))}`);
      else if (it === "BODYSTRUCTURE" || it === "BODY") {
        const lines = bodyBuf.toString("utf8").split("\n").length;
        str(`${it} ("TEXT" "PLAIN" ("CHARSET" "utf-8") NIL NIL "7BIT" ${bodyBuf.length} ${lines}${it === "BODYSTRUCTURE" ? " NIL NIL NIL" : ""})`);
      } else if (it === "RFC822" || it === "RFC822.TEXT" || it === "RFC822.HEADER") {
        if (it !== "RFC822.HEADER") setSeen = true;
        lit(it, it === "RFC822" ? m.raw : it === "RFC822.TEXT" ? bodyBuf : headerBuf);
      } else {
        const mm = /^BODY(\.PEEK)?\[(.*?)\](<(\d+)(?:\.(\d+))?>)?$/is.exec(raw);
        if (!mm) continue;
        if (!mm[1]) setSeen = true; // non-PEEK fetch sets \Seen, exactly like a real server
        const section = mm[2];
        let data: Buffer;
        const secU = section.toUpperCase();
        if (section === "") data = m.raw;
        else if (secU === "HEADER") data = headerBuf;
        else if (secU === "TEXT" || /^1(\.TEXT)?$/.test(secU) || secU === "1.1") data = bodyBuf;
        else if (secU.startsWith("HEADER.FIELDS")) {
          const names = /\(([^)]*)\)/.exec(section)?.[1].split(/\s+/).map((x) => x.toLowerCase()) ?? [];
          const not = secU.includes(".NOT");
          const lines = unfold(headerBuf.toString("utf8")).filter((l) => {
            const n = l.split(":")[0].toLowerCase();
            return not ? !names.includes(n) : names.includes(n);
          });
          data = Buffer.from(lines.join("\r\n") + "\r\n\r\n");
        } else if (secU === "1.MIME" || secU === "MIME") data = Buffer.from("Content-Type: text/plain; charset=utf-8\r\n\r\n");
        else data = Buffer.alloc(0);
        let label = `BODY[${section}]`;
        if (mm[3]) {
          const start = parseInt(mm[4], 10);
          const len = mm[5] ? parseInt(mm[5], 10) : undefined;
          data = data.subarray(start, len === undefined ? undefined : start + len);
          label += `<${start}>`;
        }
        lit(label, data);
      }
    }
    const hadSeen = m.flags.has("\\Seen");
    if (setSeen && !hadSeen) {
      m.flags.add("\\Seen");
      if (flagsIdx < 0) {
        flagsIdx = out.length;
        str("FLAGS_PLACEHOLDER");
      }
    }
    if (flagsIdx >= 0) out[flagsIdx] = Buffer.from(`FLAGS (${[...m.flags].join(" ")})`);
    const sp = Buffer.from(" ");
    const body: Buffer[] = [];
    out.forEach((b, i) => {
      if (i) body.push(sp);
      body.push(b);
    });
    write(Buffer.concat([Buffer.from(`* ${seqNo} FETCH (`), ...body, Buffer.from(")\r\n")]));
  }
}

// ------------------------------------------------------------------ helpers
function fmtDate(d: Date): string {
  const mon = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"][d.getUTCMonth()];
  const p = (n: number) => String(n).padStart(2, "0");
  return `${p(d.getUTCDate())}-${mon}-${d.getUTCFullYear()} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())} +0000`;
}
function quote(s: string): string {
  return `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}
function nstr(s: string | undefined): string {
  return s === undefined || s === "" ? "NIL" : quote(s);
}
function matchPattern(pattern: string, name: string): boolean {
  const re = new RegExp("^" + pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/%/g, "[^/]*") + "$");
  return re.test(name);
}
function splitMessage(raw: Buffer): { headerBuf: Buffer; bodyBuf: Buffer } {
  const i = raw.indexOf("\r\n\r\n");
  if (i < 0) return { headerBuf: Buffer.concat([raw, Buffer.from("\r\n\r\n")]), bodyBuf: Buffer.alloc(0) };
  return { headerBuf: raw.subarray(0, i + 4), bodyBuf: raw.subarray(i + 4) };
}
function unfold(h: string): string[] {
  const out: string[] = [];
  for (const l of h.split(/\r?\n/)) {
    if (!l) continue;
    if (/^\s/.test(l) && out.length) out[out.length - 1] += " " + l.trim();
    else out.push(l);
  }
  return out;
}
function headerMap(h: string): Record<string, string> {
  const r: Record<string, string> = {};
  for (const l of unfold(h)) {
    const i = l.indexOf(":");
    if (i > 0) r[l.slice(0, i).toLowerCase()] = l.slice(i + 1).trim();
  }
  return r;
}
function addrList(v: string | undefined): string {
  if (!v) return "NIL";
  const items = v.split(",").map((s) => s.trim()).filter(Boolean);
  const out = items.map((s) => {
    const m = /^(.*?)\s*<([^>]+)>$/.exec(s);
    const name = m ? m[1].replace(/^"|"$/g, "") : "";
    const addr = m ? m[2] : s;
    const [mb, host] = addr.split("@");
    return `(${nstr(name)} NIL ${nstr(mb)} ${nstr(host)})`;
  });
  return `(${out.join("")})`;
}
function envelope(h: string): string {
  const m = headerMap(h);
  return `(${nstr(m["date"])} ${nstr(m["subject"])} ${addrList(m["from"])} ${addrList(m["from"])} ${addrList(m["from"])} ${addrList(m["to"])} ${addrList(m["cc"])} NIL NIL ${nstr(m["message-id"])})`;
}
function resolveSet(set: string, f: FakeFolder, byUid: boolean): FakeMessage[] {
  const maxVal = byUid ? Math.max(0, ...f.messages.map((m) => m.uid)) : f.messages.length;
  const wanted = new Set<number>();
  for (const part of set.split(",")) {
    const [a, b] = part.split(":");
    const lo = a === "*" ? maxVal : parseInt(a, 10);
    const hi = b === undefined ? lo : b === "*" ? maxVal : parseInt(b, 10);
    for (let i = Math.min(lo, hi); i <= Math.max(lo, hi); i++) wanted.add(i);
  }
  return f.messages.filter((m, i) => wanted.has(byUid ? m.uid : i + 1));
}
function evalCrit(crit: Tok[], m: FakeMessage, f: FakeFolder): boolean {
  let i = 0;
  const hdr = () => headerMap(splitMessage(m.raw).headerBuf.toString("utf8"));
  const text = () => m.raw.toString("utf8").toLowerCase();
  const one = (): boolean => {
    const t = crit[i++];
    if (Array.isArray(t)) return evalCrit(t, m, f);
    const k = String(t).toUpperCase();
    const arg = () => String(crit[i++]).toLowerCase();
    switch (k) {
      case "ALL":
        return true;
      case "SEEN":
        return m.flags.has("\\Seen");
      case "UNSEEN":
        return !m.flags.has("\\Seen");
      case "FLAGGED":
        return m.flags.has("\\Flagged");
      case "UNFLAGGED":
        return !m.flags.has("\\Flagged");
      case "ANSWERED":
        return m.flags.has("\\Answered");
      case "DRAFT":
        return m.flags.has("\\Draft");
      case "DELETED":
        return m.flags.has("\\Deleted");
      case "NEW":
      case "RECENT":
        return false;
      case "NOT":
        return !one();
      case "OR": {
        const a = one();
        const b = one();
        return a || b;
      }
      case "FROM":
        return (hdr()["from"] ?? "").toLowerCase().includes(arg());
      case "TO":
        return (hdr()["to"] ?? "").toLowerCase().includes(arg());
      case "CC":
        return (hdr()["cc"] ?? "").toLowerCase().includes(arg());
      case "SUBJECT":
        return (hdr()["subject"] ?? "").toLowerCase().includes(arg());
      case "BODY":
        return splitMessage(m.raw).bodyBuf.toString("utf8").toLowerCase().includes(arg());
      case "TEXT":
        return text().includes(arg());
      case "HEADER": {
        const n = arg();
        const v = arg();
        return (hdr()[n] ?? "").toLowerCase().includes(v);
      }
      case "UID":
        return resolveSet(String(crit[i++]), f, true).includes(m);
      case "SINCE":
      case "BEFORE":
      case "ON":
      case "SENTSINCE":
      case "SENTBEFORE":
      case "SENTON":
      case "LARGER":
      case "SMALLER":
      case "KEYWORD":
      case "UNKEYWORD":
        i++;
        return true;
      default:
        if (/^[\d*:,]+$/.test(k)) return resolveSet(k, f, false).includes(m);
        return true;
    }
  };
  while (i < crit.length) if (!one()) return false;
  return true;
}

function tokenize(s: string, literals: Buffer[]): Tok[] {
  let i = 0;
  const parseList = (): Tok[] => {
    const out: Tok[] = [];
    while (i < s.length) {
      const c = s[i];
      if (c === " ") i++;
      else if (c === ")") {
        i++;
        return out;
      } else out.push(parseTok());
    }
    return out;
  };
  const parseTok = (): Tok => {
    const c = s[i];
    if (c === "(") {
      i++;
      return parseList();
    }
    if (c === '"') {
      let r = "";
      i++;
      while (i < s.length && s[i] !== '"') {
        if (s[i] === "\\") i++;
        r += s[i++];
      }
      i++;
      return r;
    }
    if (c === "{") {
      const end = s.indexOf("}", i);
      i = end + 1;
      return literals.shift() ?? Buffer.alloc(0);
    }
    let r = "";
    while (i < s.length && s[i] !== " " && s[i] !== ")" && !(s[i] === "(" && r === "")) {
      if (s[i] === "[") {
        const end = findClose(s, i);
        r += s.slice(i, end + 1);
        i = end + 1;
        continue;
      }
      if (s[i] === "(") break;
      r += s[i++];
    }
    return r;
  };
  const out: Tok[] = [];
  while (i < s.length) {
    if (s[i] === " ") i++;
    else out.push(parseTok());
  }
  return out;
}
function findClose(s: string, start: number): number {
  let depth = 0;
  for (let j = start; j < s.length; j++) {
    if (s[j] === "[") depth++;
    else if (s[j] === "]" && --depth === 0) return j;
  }
  return s.length - 1;
}
