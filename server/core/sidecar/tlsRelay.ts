import { timingSafeEqual } from "node:crypto";
import { chmodSync, rmSync } from "node:fs";
import net from "node:net";
import tls from "node:tls";
import { getMailboxCredentials } from "../imap/mailboxes.js";
import { assertHostAllowed } from "../imap/ssrf.js";
import { log } from "../log.js";

const relayLog = log.child({ component: "tls-relay" });

const MAX_HELLO_BYTES = 4096;
const HELLO_TIMEOUT_MS = 5_000;
const CONNECT_TIMEOUT_MS = 30_000;

export type MailboxTarget = { host: string; port: number };
export interface TlsRelayOptions {
  socketPath: string;
  /** Current shared secret of the sidecar RPC (changes whenever the sidecar restarts). */
  getSecret: () => string;
  /** Destination lookup by mailbox id; throws for unknown ids. Default reads the mailbox table. */
  target?: (mailboxId: string) => MailboxTarget;
  /** SSRF-vetted addresses for a host. Default is the shared SSRF policy. */
  resolve?: (host: string) => Promise<string[]>;
  /** Extra tls.connect options (tests only). */
  tlsOptions?: tls.ConnectionOptions;
}

const defaultTarget = (id: string): MailboxTarget => {
  const c = getMailboxCredentials(id); // user and password are not used here
  return { host: c.host, port: c.port };
};

/** `IMAP_TLS_RELAY`: default on; 0|false|off|no disables. */
export function tlsRelayEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  return !["0", "false", "off", "no"].includes((env.IMAP_TLS_RELAY ?? "").trim().toLowerCase());
}

function safeEqual(a: string, b: string): boolean {
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

/**
 * Unix-socket server that terminates TLS for the Go sidecar with Node's TLS stack.
 * Protocol: the client sends one JSON line {"auth","mailboxId"}; the relay answers "OK\n" (then pipes plaintext
 * both ways) or "ERR <reason>\n" and closes. The destination is always the mailbox's own stored host/port,
 * so this is never an open proxy.
 */
export class TlsRelay {
  private server: net.Server | null = null;
  private readonly conns = new Set<net.Socket>();
  private readonly o: TlsRelayOptions;

  constructor(opts: TlsRelayOptions) { this.o = opts; }

  get socketPath(): string { return this.o.socketPath; }

  async start(): Promise<void> {
    if (this.server) return;
    rmSync(this.o.socketPath, { force: true });
    const server = net.createServer((s) => this.onConnection(s));
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(this.o.socketPath, () => { server.off("error", reject); resolve(); });
    });
    server.on("error", (e) => relayLog.warn("relay server error", { err: e }));
    try { chmodSync(this.o.socketPath, 0o600); } catch { /* best effort; the data dir is 0700 */ }
    this.server = server;
  }

  async stop(): Promise<void> {
    const server = this.server;
    this.server = null;
    for (const s of this.conns) s.destroy();
    this.conns.clear();
    if (server) await new Promise<void>((r) => server.close(() => r()));
    try { rmSync(this.o.socketPath, { force: true }); } catch { /* ignore */ }
  }

  private onConnection(sock: net.Socket): void {
    this.conns.add(sock);
    sock.once("close", () => this.conns.delete(sock));
    sock.on("error", () => sock.destroy());

    let buf = Buffer.alloc(0);
    const timer = setTimeout(() => sock.destroy(), HELLO_TIMEOUT_MS);
    const onData = (d: Buffer) => {
      buf = Buffer.concat([buf, d]);
      const nl = buf.indexOf(0x0a);
      if (nl < 0) {
        if (buf.length > MAX_HELLO_BYTES) { clearTimeout(timer); sock.destroy(); }
        return;
      }
      clearTimeout(timer);
      sock.off("data", onData);
      sock.pause();
      const line = buf.subarray(0, nl);
      const rest = buf.subarray(nl + 1);
      if (line.length > MAX_HELLO_BYTES) { sock.destroy(); return; }
      void this.handshake(sock, line.toString("utf8"), rest);
    };
    sock.on("data", onData);
  }

  private async handshake(sock: net.Socket, line: string, rest: Buffer): Promise<void> {
    let hello: { auth?: unknown; mailboxId?: unknown };
    try { hello = JSON.parse(line); } catch { sock.destroy(); return; }
    if (typeof hello.auth !== "string" || typeof hello.mailboxId !== "string" || !safeEqual(hello.auth, this.o.getSecret())) {
      sock.destroy(); // no reply, no information
      return;
    }
    const mailboxId = hello.mailboxId;
    let upstream: tls.TLSSocket | null = null;
    try {
      let target: MailboxTarget;
      try { target = (this.o.target ?? defaultTarget)(mailboxId); } catch { throw new RelayError("unknown mailbox"); }
      let addrs: string[];
      try { addrs = await (this.o.resolve ?? assertHostAllowed)(target.host); }
      catch (e) { throw new RelayError((e as { code?: string })?.code === "HOST_NOT_ALLOWED" ? "host not allowed" : "host could not be resolved"); }
      const ip = addrs[0];
      upstream = await connectTls(ip, target.port, target.host, this.o.tlsOptions);
      if (sock.destroyed) { upstream.destroy(); return; }
      relayLog.info("tls relay connected", {
        mailboxId, remote: `${ip}:${target.port}`, tlsProtocol: upstream.getProtocol(), cipher: upstream.getCipher()?.name,
      });
      const up = upstream;
      const kill = () => { sock.destroy(); up.destroy(); };
      sock.on("error", kill); up.on("error", kill);
      sock.on("close", kill); up.on("close", kill);
      sock.write("OK\n");
      if (rest.length) up.write(rest);
      sock.pipe(up);
      up.pipe(sock);
      sock.resume();
    } catch (e) {
      upstream?.destroy();
      const reason = e instanceof RelayError ? e.message : describeTlsError(e);
      relayLog.warn("tls relay failed", { mailboxId, reason });
      if (!sock.destroyed) sock.end(`ERR ${reason}\n`);
    }
  }
}

class RelayError extends Error {}

function describeTlsError(e: unknown): string {
  const code = String((e as { code?: string })?.code ?? "");
  const msg = String((e as Error)?.message ?? "");
  if (code === "ETIMEDOUT" || /timed out|timeout/i.test(msg)) return "connection timed out";
  if (code === "ECONNREFUSED") return "connection refused";
  if (/certificate|self.signed|CERT_|ERR_TLS|SSL|altnames/i.test(code + msg)) return "tls certificate validation failed";
  return "upstream connection failed";
}

function connectTls(ip: string, port: number, servername: string, extra?: tls.ConnectionOptions): Promise<tls.TLSSocket> {
  return new Promise((resolve, reject) => {
    const s = tls.connect({ host: ip, port, servername, rejectUnauthorized: true, ...extra });
    const timer = setTimeout(() => { s.destroy(); reject(Object.assign(new Error("timed out"), { code: "ETIMEDOUT" })); }, CONNECT_TIMEOUT_MS);
    s.once("secureConnect", () => { clearTimeout(timer); s.off("error", reject); s.on("error", () => {}); resolve(s); });
    s.once("error", (e) => { clearTimeout(timer); reject(e); });
  });
}
