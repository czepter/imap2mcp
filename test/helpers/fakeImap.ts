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
export interface FetchStat {
  /** FETCHes that asked for ENVELOPE (a "header fetch") */
  envelope: number;
  /** FETCHes that asked for flags only (reconciliation) */
  flags: number;
  /** FETCHes that returned any body section */
  body: number;
}
export interface LoggedCommand {
  user: string | null;
  selected: string | null;
  line: string; // literal payloads elided
  ts?: number;
}

// ---------------------------------------------------------------- v2 fault injection types
export type FaultSpec =
  /** hold the command for `ms`, then process it normally */
  | { kind: "delay"; ms: number }
  /** receive the command and never answer (accept-then-stall at command level) */
  | { kind: "hang" }
  /** close the TCP connection right after RECEIVING the command; it is NOT applied */
  | { kind: "drop" }
  /** APPLY the command, then close the connection before any response bytes are sent (the classic ambiguous write) */
  | { kind: "drop-after-apply" }
  /** apply the command, send only the first `bytes` of the response, then close */
  | { kind: "drop-mid-response"; bytes: number }
  /** answer with syntactically broken data (default) followed by nothing useful; `{tag}` is substituted */
  | { kind: "malformed"; raw?: string }
  /** answer with this tagged text, e.g. "NO [OVERQUOTA] mailbox full" (command is NOT applied) */
  | { kind: "reply"; text: string };
export interface FaultHandle {
  /** how many times the fault fired */
  readonly hits: number;
  remove(): void;
}
export interface IdleSession {
  user: string;
  folder: string;
  start: number;
  end?: number;
  endedBy?: "done" | "drop" | "timeout" | "close";
}

type Tok = string | Buffer | Tok[];

export class FakeImapServer {
  accounts = new Map<string, FakeAccount>();
  commands: LoggedCommand[] = [];
  /** Per (user, folder, uid) counters of what was FETCHed; makes "unchanged messages are not refetched" assertable. */
  fetchStats = new Map<string, Map<number, FetchStat>>();
  /** Artificial one-way-ish delay: every response batch is held back this long (== injected RTT per round trip). */
  latencyMs = 0;
  // ---- v2 fault knobs (all default off)
  /** true / predicate => LOGIN and AUTHENTICATE are rejected with `loginRejectText` */
  rejectLogins: boolean | ((user: string) => boolean) = false;
  loginRejectText = "NO [AUTHENTICATIONFAILED] bad credentials";
  /** delay (ms) before answering a LOGIN / AUTHENTICATE; may be a function so a test can open the window only after some event */
  loginDelay: number | (() => number) = 0;
  /** every LOGIN / AUTHENTICATE attempt, in order, with wall-clock time */
  loginAttempts: Array<{ ts: number; user: string; ok: boolean }> = [];
  /** every accepted TCP+TLS connection (incl. refused ones) */
  connectLog: Array<{ ts: number; refused: boolean }> = [];
  /** accept the connection, then drop it at once (network flaps; each attempt is still visible in connectLog) */
  refuseConnections = false;
  /** accept and never send the greeting */
  stallGreeting = false;
  /** advertise IDLE and implement it (off by default: imapflow would auto-IDLE on the Node write path) */
  idleCap = false;
  /** server-side IDLE limit: an IDLE not terminated within this many ms gets `* BYE` and is closed (0 = none) */
  idleMaxMs = 0;
  /** server-side inactivity auto-logout (any connection, reset by every received byte; 0 = none) */
  autoLogoutMs = 0;
  idleSessions: IdleSession[] = [];
  autoLogouts = 0;
  private faults: Array<{ match: (line: string, user: string | null, selected: string | null) => boolean; spec: FaultSpec; left: number; hits: number }> = [];
  private idleLive = new Set<{ sess: IdleSession; sock: import("node:net").Socket; write: (s: string | Buffer) => unknown; timer?: NodeJS.Timeout }>();
  private holds: Array<{ pred: (line: string, user: string | null, selected: string | null) => boolean; arrived: () => void; released: Promise<void> }> = [];
  private server!: tls.Server;
  private sockets = new Set<import("node:net").Socket>();
  port = 0;

  constructor(private opts: { key: string; cert: string; move?: boolean }) {}

  private caps(): string {
    return `IMAP4rev1 UIDPLUS ${this.opts.move === false ? "" : "MOVE "}${this.idleCap ? "IDLE " : ""}ID NAMESPACE AUTH=PLAIN`.replace("  ", " ");
  }
  /** Kill every open connection (simulates server restart; clients must reconnect and re-SELECT). */
  dropConnections(): void {
    for (const s of this.sockets) s.destroy();
  }

  /** Destroy only connections that are currently in IDLE (simulates an IDLE-specific drop). */
  dropIdleConnections(): number {
    let n = 0;
    for (const l of [...this.idleLive]) {
      l.sess.endedBy = "drop";
      l.sock.destroy();
      n++;
    }
    return n;
  }
  /** Push untagged data to every connection IDLEing on (user, folder). */
  notifyIdle(user: string, folder: string, kind: "exists" | "expunge" = "exists"): number {
    const f = this.accounts.get(user)?.folders.get(folder);
    if (!f) return 0;
    let n = 0;
    for (const l of this.idleLive) {
      if (l.sess.user === user && l.sess.folder === folder) {
        l.write(kind === "exists" ? `* ${f.messages.length} EXISTS\r\n` : `* ${Math.max(1, f.messages.length)} EXPUNGE\r\n`);
        n++;
      }
    }
    return n;
  }
  activeIdle(user?: string, folder?: string): number {
    return [...this.idleLive].filter((l) => (!user || l.sess.user === user) && (!folder || l.sess.folder === folder)).length;
  }
  /**
   * Inject a fault for commands whose text (without tag, e.g. `UID FETCH 5 (BODY.PEEK[])`, literals elided) matches.
   * Fires `times` times (default 1; Infinity = until removed). First matching live fault wins.
   */
  inject(match: RegExp | ((line: string, user: string | null, selected: string | null) => boolean), spec: FaultSpec, times = 1): FaultHandle {
    const f = { match: match instanceof RegExp ? (l: string) => match.test(l) : match, spec, left: times, hits: 0 };
    this.faults.push(f);
    return { get hits() { return f.hits; }, remove: () => { f.left = 0; } };
  }
  clearFaults(): void {
    this.faults = [];
  }
  /** all logged commands (any user, incl. pre-login) matching `re` */
  countAll(re: RegExp): number {
    return this.commands.filter((c) => re.test(c.line)).length;
  }
  loginAttemptsSince(ts: number, user?: string): number {
    return this.loginAttempts.filter((a) => a.ts >= ts && (!user || a.user === user)).length;
  }

  async start(): Promise<void> {
    this.server = tls.createServer({ key: this.opts.key, cert: this.opts.cert }, (s) => this.onConn(s));
    // dual-stack so "localhost" works whichever family it resolves to first
    await new Promise<void>((resolve, reject) => {
      this.server.once("error", reject);
      this.server.listen({ port: 0, host: "::", ipv6Only: false }, resolve);
    }).catch(async () => {
      await new Promise<void>((r) => this.server.listen(0, "127.0.0.1", r));
    });
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

  // ---------------------------------------------------------------- v1 helpers (large mailboxes, external changes, hooks)
  /**
   * Adds `count` messages whose raw bytes are generated on demand (nothing is kept in memory per message besides the
   * small descriptor), with ~`headerBytes` of envelope data (long To/Cc lists). Returns the uid range.
   */
  addGenerated(user: string, folder: string, count: number, opts: { headerBytes?: number; subject?: (i: number) => string; flags?: (i: number) => string[]; bodyBytes?: number } = {}): { first: number; last: number } {
    const f = this.folder(user, folder);
    const first = f.uidNext;
    const headerBytes = opts.headerBytes ?? 2048;
    const bodyBytes = opts.bodyBytes ?? 200;
    for (let i = 0; i < count; i++) {
      const uid = f.uidNext++;
      const subject = opts.subject ? opts.subject(i) : `Generated message ${uid}`;
      const m = { uid, flags: new Set(opts.flags ? opts.flags(i) : []), date: new Date(Date.UTC(2025, 0, 1) + uid * 60_000) } as FakeMessage;
      Object.defineProperty(m, "raw", { enumerable: true, get: () => genRaw(uid, subject, headerBytes, bodyBytes) });
      f.messages.push(m);
    }
    return { first, last: f.uidNext - 1 };
  }
  addFolder(user: string, name: string, special?: string): FakeFolder {
    const acct = this.accounts.get(user)!;
    const f: FakeFolder = { name, uidValidity: 2000 + acct.folders.size, uidNext: 1, messages: [], special };
    acct.folders.set(name, f);
    return f;
  }
  /** Folder deleted and re-created: new UIDVALIDITY, UIDs restart at 1 (so old UIDs would silently alias new mail if trusted). */
  recreateFolder(user: string, name: string): FakeFolder {
    const f = this.folder(user, name);
    f.uidValidity += 7777;
    f.uidNext = 1;
    f.messages = [];
    return f;
  }
  /** Another client expunges these UIDs behind the bridge's back. */
  externalExpunge(user: string, name: string, uids: number[]): void {
    const f = this.folder(user, name);
    const gone = new Set(uids);
    f.messages = f.messages.filter((m) => !gone.has(m.uid));
  }
  /** Another client changes flags behind the bridge's back. */
  externalSetFlags(user: string, name: string, uid: number, add: string[] = [], remove: string[] = []): void {
    const m = this.folder(user, name).messages.find((x) => x.uid === uid);
    if (!m) throw new Error(`no uid ${uid}`);
    add.forEach((x) => m.flags.add(x));
    remove.forEach((x) => m.flags.delete(x));
  }
  /** Another client delivers mail (UIDNEXT advances). */
  externalDeliver(user: string, name: string, count: number, subject: (i: number) => string = (i) => `Fresh arrival ${i}`) {
    return this.addGenerated(user, name, count, { subject });
  }
  private statKey(user: string | null, folder: string) {
    return `${user}\u0000${folder}`;
  }
  fetchStat(user: string, folder: string, uid: number): FetchStat {
    return this.fetchStats.get(this.statKey(user, folder))?.get(uid) ?? { envelope: 0, flags: 0, body: 0 };
  }
  /** Total FETCH counts of a kind for a folder, optionally restricted to a uid range. */
  fetchTotal(user: string, folder: string, kind: keyof FetchStat, range?: [number, number]): number {
    let n = 0;
    for (const [uid, st] of this.fetchStats.get(this.statKey(user, folder)) ?? []) if (!range || (uid >= range[0] && uid <= range[1])) n += st[kind];
    return n;
  }
  resetFetchStats(): void {
    this.fetchStats.clear();
  }
  private recordFetch(user: string | null, folder: string, uid: number, items: string[]) {
    const k = this.statKey(user, folder);
    let per = this.fetchStats.get(k);
    if (!per) this.fetchStats.set(k, (per = new Map()));
    let st = per.get(uid);
    if (!st) per.set(uid, (st = { envelope: 0, flags: 0, body: 0 }));
    const up = items.map((x) => x.toUpperCase());
    const hasBody = up.some((x) => x.startsWith("BODY[") || x.startsWith("BODY.PEEK[") || x === "RFC822" || x === "RFC822.TEXT");
    if (hasBody) st.body++;
    if (up.includes("ENVELOPE")) st.envelope++;
    else if (!hasBody) st.flags++;
  }
  /**
   * Holds back the next command (on any connection) matching `pred` until `release()` is called. `arrived` resolves when
   * the command has been received, so a test can change state (e.g. revoke a policy) while a write is "in flight".
   */
  holdNext(pred: (line: string, user: string | null, selected: string | null) => boolean): { arrived: Promise<void>; release(): void } {
    let arrive!: () => void;
    let rel!: () => void;
    const arrived = new Promise<void>((r) => (arrive = r));
    const released = new Promise<void>((r) => (rel = r));
    this.holds.push({ pred, arrived: arrive, released });
    return { arrived, release: rel };
  }
  /** Number of logged commands for `user` matching `re`. */
  countCommands(user: string, re: RegExp): number {
    return this.commands.filter((c) => c.user === user && re.test(c.line)).length;
  }
  commandsFor(user: string): string[] {
    return this.commands.filter((c) => c.user === user).map((c) => c.line);
  }

  // ---------------------------------------------------------------- connection handling
  private onConn(sock: tls.TLSSocket) {
    this.connectLog.push({ ts: Date.now(), refused: this.refuseConnections });
    this.sockets.add(sock);
    sock.on("close", () => this.sockets.delete(sock));
    sock.on("error", () => {});
    if (this.refuseConnections) {
      sock.destroy();
      return;
    }
    const st: { user: string | null; acct: FakeAccount | null; sel: FakeFolder | null; idle?: { tag: string; live: any } | null } = { user: null, acct: null, sel: null, idle: null };
    let alTimer: NodeJS.Timeout | null = null;
    const armAutoLogout = () => {
      if (!this.autoLogoutMs) return;
      if (alTimer) clearTimeout(alTimer);
      alTimer = setTimeout(() => {
        this.autoLogouts++;
        if (!sock.destroyed) {
          sock.write("* BYE Autologout; idle for too long\r\n");
          sock.end();
        }
      }, this.autoLogoutMs);
      alTimer.unref?.();
    };
    sock.on("close", () => {
      if (alTimer) clearTimeout(alTimer);
      if (st.idle) this.endIdle(st.idle.live, "close");
    });
    armAutoLogout();
    let buf = Buffer.alloc(0);
    let pending: { parts: Buffer[]; need: number; lineSoFar: string; tag: string } | null = null;
    let authTag: string | null = null;

    let outQ: Array<string | Buffer> = [];
    let outTimer: NodeJS.Timeout | null = null;
    const write = (s: string | Buffer) => {
      if (this.latencyMs <= 0) return sock.write(s);
      // everything produced within one tick is flushed together after the injected delay (== one RTT per round trip)
      outQ.push(s);
      if (!outTimer)
        outTimer = setTimeout(() => {
          const q = outQ;
          outQ = [];
          outTimer = null;
          if (!sock.destroyed) sock.write(Buffer.concat(q.map((x) => (typeof x === "string" ? Buffer.from(x) : x))));
        }, this.latencyMs);
      return true;
    };
    if (!this.stallGreeting) write(`* OK [CAPABILITY ${this.caps()}] fake imap ready\r\n`);

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

        if (st.idle && /^DONE$/i.test(line.trim())) {
          const { tag, live } = st.idle;
          st.idle = null;
          this.endIdle(live, "done");
          write(`${tag} OK IDLE terminated\r\n`);
          continue;
        }
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
      armAutoLogout();
      buf = Buffer.concat([buf, d]);
      pump();
    });
  }

  private endIdle(live: { sess: IdleSession; timer?: NodeJS.Timeout }, by: IdleSession["endedBy"]) {
    if (!this.idleLive.has(live as any)) return;
    this.idleLive.delete(live as any);
    if (live.timer) clearTimeout(live.timer);
    live.sess.end = Date.now();
    live.sess.endedBy ??= by;
  }

  private doLogin(tag: string, u: string, p: string, st: any, write: (s: string | Buffer) => void) {
    const d = typeof this.loginDelay === "function" ? this.loginDelay() : this.loginDelay;
    if (d > 0) {
      setTimeout(() => this.doLoginNow(tag, u, p, st, write), d);
      return;
    }
    this.doLoginNow(tag, u, p, st, write);
  }
  private doLoginNow(tag: string, u: string, p: string, st: any, write: (s: string | Buffer) => void) {
    this.commands.push({ user: null, selected: null, line: `${tag} LOGIN-ATTEMPT ${u} ***`, ts: Date.now() });
    const a = this.accounts.get(u);
    const rejected = typeof this.rejectLogins === "function" ? this.rejectLogins(u) : this.rejectLogins;
    if (rejected) {
      this.loginAttempts.push({ ts: Date.now(), user: u, ok: false });
      write(`${tag} ${this.loginRejectText}\r\n`);
      return;
    }
    this.loginAttempts.push({ ts: Date.now(), user: u, ok: !!(a && a.pass === p) });
    if (a && a.pass === p) {
      st.user = u;
      st.acct = a;
      write(`${tag} OK [CAPABILITY ${this.caps().replace(" AUTH=PLAIN", "")}] logged in\r\n`);
    } else {
      write(`${tag} NO [AUTHENTICATIONFAILED] bad credentials\r\n`);
    }
  }

  private handle(tag: string, line: string, literals: Buffer[], st: any, write: (s: string | Buffer) => void, sock: tls.TLSSocket) {
    const rest0 = line.slice(tag.length + 1);
    const hi = this.holds.findIndex((h) => h.pred(rest0, st.user, st.sel?.name ?? null));
    if (hi >= 0) {
      const [h] = this.holds.splice(hi, 1);
      h.arrived();
      void h.released.then(() => this.handleNow(tag, line, literals, st, write, sock));
      return;
    }
    this.afterHold(tag, line, literals, st, write, sock);
  }

  private logOnly(rest: string, st: any) {
    const logLine = /^(LOGIN|AUTHENTICATE)/i.test(rest) ? rest.split(" ")[0] + " ***" : rest.replace(/\{\d+\+?\}/g, "{literal}");
    this.commands.push({ user: st.user, selected: st.sel?.name ?? null, line: logLine, ts: Date.now() });
  }

  private afterHold(tag: string, line: string, literals: Buffer[], st: any, write: (s: string | Buffer) => void, sock: tls.TLSSocket) {
    const rest = line.slice(tag.length + 1);
    const f = this.faults.find((x) => x.left > 0 && x.match(rest, st.user, st.sel?.name ?? null));
    if (!f) return this.handleNow(tag, line, literals, st, write, sock);
    f.left--;
    f.hits++;
    const sp = f.spec;
    switch (sp.kind) {
      case "delay":
        setTimeout(() => !sock.destroyed && this.handleNow(tag, line, literals, st, write, sock), sp.ms);
        return;
      case "hang":
        this.logOnly(rest, st);
        return;
      case "drop":
        this.logOnly(rest, st);
        sock.destroy();
        return;
      case "drop-after-apply":
        this.handleNow(tag, line, literals, st, () => true, sock);
        setImmediate(() => sock.destroy());
        return;
      case "drop-mid-response": {
        const chunks: Buffer[] = [];
        this.handleNow(tag, line, literals, st, (x) => { chunks.push(typeof x === "string" ? Buffer.from(x) : x); return true; }, sock);
        const all = Buffer.concat(chunks);
        sock.write(all.subarray(0, sp.bytes), () => setImmediate(() => sock.destroy()));
        return;
      }
      case "malformed":
        this.logOnly(rest, st);
        write((sp.raw ?? "* 1 FETCH (UID ((( \u0001\u0002 {zz}\r\n{tag} OK garbage\r\n").replace(/\{tag\}/g, tag));
        return;
      case "reply":
        this.logOnly(rest, st);
        write(`${tag} ${sp.text}\r\n`);
        return;
    }
  }

  private handleNow(tag: string, line: string, literals: Buffer[], st: any, write: (s: string | Buffer) => void, sock: tls.TLSSocket) {
    // tokenise (literals get substituted in order)
    const rest = line.slice(tag.length + 1);
    const logLine = /^(LOGIN|AUTHENTICATE)/i.test(rest) ? rest.split(" ")[0] + " ***" : rest.replace(/\{\d+\+?\}/g, "{literal}");
    this.commands.push({ user: st.user, selected: st.sel?.name ?? null, line: logLine, ts: Date.now() });

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
        write(`* CAPABILITY ${this.caps()}\r\n`);
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
    if (cmd === "IDLE") {
      if (!this.idleCap) return write(`${tag} BAD IDLE not supported\r\n`);
      const sess: IdleSession = { user: st.user, folder: sel.name, start: Date.now() };
      const live: { sess: IdleSession; sock: import("node:net").Socket; write: (s: string | Buffer) => unknown; timer?: NodeJS.Timeout } = { sess, sock, write };
      if (this.idleMaxMs > 0) {
        live.timer = setTimeout(() => {
          sess.endedBy = "timeout";
          this.endIdle(live, "timeout");
          if (!sock.destroyed) {
            sock.write("* BYE IDLE limit exceeded\r\n");
            sock.end();
          }
        }, this.idleMaxMs);
        live.timer.unref?.();
      }
      this.idleSessions.push(sess);
      this.idleLive.add(live);
      st.idle = { tag, live };
      return write("+ idling\r\n");
    }
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
        const seqOf = msgs.length > 64 ? new Map(sel.messages.map((x, i) => [x, i + 1] as const)) : null;
        for (const m of msgs) {
          this.recordFetch(st.user, sel.name, m.uid, list);
          this.emitFetch(m, seqOf ? seqOf.get(m)! : seq(m), list, write);
        }
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
        if (sub === "MOVE" && this.opts.move === false) return write(`${tag} BAD MOVE not supported\r\n`);
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
function genRaw(uid: number, subject: string, headerBytes: number, bodyBytes: number): Buffer {
  const rcpt: string[] = [];
  let n = 0;
  while (rcpt.join(", ").length < Math.max(0, headerBytes - 400)) {
    rcpt.push(`Recipient Number${n} <rcpt${uid}-${n}@bulk.example.org>`);
    n++;
  }
  const half = Math.ceil(rcpt.length / 2);
  const h =
    `From: Sender ${uid % 97} <sender${uid % 97}@example.org>\r\n` +
    `To: ${rcpt.slice(0, half).join(", ")}\r\n` +
    (rcpt.length > half ? `Cc: ${rcpt.slice(half).join(", ")}\r\n` : "") +
    `Subject: ${subject}\r\nDate: Fri, 02 Jan 2026 03:04:05 +0000\r\nMessage-ID: <gen-${uid}@gen.example.org>\r\n` +
    `Content-Type: text/plain; charset=utf-8\r\n\r\n`;
  return Buffer.from(h + "gen-body-" + uid + " " + "x".repeat(Math.max(0, bodyBytes)) + "\r\n");
}
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
