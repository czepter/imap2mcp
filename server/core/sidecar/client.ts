import net from "node:net";
import { SidecarRpcError, SidecarTimeoutError, SidecarUnavailableError, RPC_AUTH } from "./errors.js";

export interface SidecarClientOptions {
  socketPath: string;
  /** Hex/base64 secret, sent as params.auth on every request. */
  secret: string;
  /** Default per-call deadline (sidecar's own upstream timeout is 30 s). */
  timeoutMs?: number;
  connectTimeoutMs?: number;
  maxLineBytes?: number;
}

interface Pending {
  method: string;
  resolve: (v: unknown) => void;
  reject: (e: Error) => void;
  timer: NodeJS.Timeout;
}

/**
 * Newline-delimited JSON-RPC 2.0 client over a Unix domain socket.
 * One lazily (re)established connection; requests are multiplexed by id.
 * The secret is only ever written to the socket, never logged or included in errors.
 */
export class SidecarClient {
  private sock: net.Socket | null = null;
  private connecting: Promise<net.Socket> | null = null;
  private pending = new Map<number, Pending>();
  private nextId = 1;
  private secret: string;
  private closed = false;
  private readonly timeoutMs: number;
  private readonly connectTimeoutMs: number;
  private readonly maxLine: number;

  constructor(private readonly opts: SidecarClientOptions) {
    this.secret = opts.secret;
    this.timeoutMs = opts.timeoutMs ?? 35_000;
    this.connectTimeoutMs = opts.connectTimeoutMs ?? 3_000;
    this.maxLine = opts.maxLineBytes ?? 64 * 1024 * 1024;
  }

  /** Switch to a new secret (sidecar restarted) and drop the old connection. */
  setSecret(secret: string): void {
    this.secret = secret;
    this.reset(new SidecarUnavailableError("Sidecar restarted"));
  }

  /** Drop the connection and fail all in-flight calls. Client may be reused afterwards. */
  reset(reason: Error = new SidecarUnavailableError("Sidecar connection reset")): void {
    const s = this.sock;
    this.sock = null;
    this.connecting = null;
    if (s) { s.removeAllListeners(); s.on("error", () => {}); s.destroy(); }
    this.failAll(reason);
  }

  close(): void {
    this.closed = true;
    this.reset(new SidecarUnavailableError("Sidecar client closed"));
  }

  private failAll(e: Error): void {
    const all = [...this.pending.values()];
    this.pending.clear();
    for (const p of all) { clearTimeout(p.timer); p.reject(e); }
  }

  private connect(): Promise<net.Socket> {
    if (this.closed) return Promise.reject(new SidecarUnavailableError("Sidecar client closed"));
    if (this.sock && !this.sock.destroyed) return Promise.resolve(this.sock);
    if (this.connecting) return this.connecting;
    const p = new Promise<net.Socket>((resolve, reject) => {
      const s = net.createConnection({ path: this.opts.socketPath });
      const timer = setTimeout(() => { s.destroy(); reject(new SidecarUnavailableError("Sidecar connect timed out")); }, this.connectTimeoutMs);
      s.once("error", () => { clearTimeout(timer); s.destroy(); reject(new SidecarUnavailableError("Cannot connect to sidecar")); });
      s.once("connect", () => {
        clearTimeout(timer);
        s.removeAllListeners("error");
        this.attach(s);
        this.sock = s;
        resolve(s);
      });
    }).finally(() => { if (this.connecting === p) this.connecting = null; });
    this.connecting = p;
    return p;
  }

  private attach(s: net.Socket): void {
    let buf = "";
    s.setEncoding("utf8");
    s.on("data", (chunk: string) => {
      buf += chunk;
      if (buf.length > this.maxLine) { this.drop(s, new SidecarUnavailableError("Sidecar response too large")); return; }
      let i: number;
      while ((i = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, i).trim();
        buf = buf.slice(i + 1);
        if (line) this.onLine(line);
      }
    });
    const gone = () => this.drop(s, new SidecarUnavailableError("Sidecar connection closed"));
    s.on("error", gone);
    s.on("close", gone);
  }

  private drop(s: net.Socket, reason: Error): void {
    if (this.sock === s) this.sock = null;
    s.removeAllListeners();
    s.on("error", () => {});
    s.destroy();
    this.failAll(reason);
  }

  private onLine(line: string): void {
    let msg: { id?: unknown; result?: unknown; error?: { code?: number; message?: string } };
    try { msg = JSON.parse(line); } catch { return; }
    if (typeof msg.id !== "number") return;
    const p = this.pending.get(msg.id);
    if (!p) return;
    this.pending.delete(msg.id);
    clearTimeout(p.timer);
    if (msg.error) {
      const code = Number(msg.error.code ?? -32603);
      p.reject(new SidecarRpcError(code, String(msg.error.message ?? "Sidecar error")));
      if (code === RPC_AUTH) this.reset(new SidecarUnavailableError("Sidecar authentication failed"));
    } else {
      p.resolve(msg.result);
    }
  }

  async call<T = unknown>(method: string, params: Record<string, unknown> = {}, timeoutMs = this.timeoutMs): Promise<T> {
    const sock = await this.connect();
    const id = this.nextId++;
    // auth is spread last so callers can never override it.
    const payload = JSON.stringify({ jsonrpc: "2.0", id, method, params: { ...params, auth: this.secret } }) + "\n";
    return new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new SidecarTimeoutError(method));
      }, timeoutMs);
      timer.unref?.();
      this.pending.set(id, { method, resolve: resolve as (v: unknown) => void, reject, timer });
      sock.write(payload, (err) => {
        if (err && this.pending.delete(id)) {
          clearTimeout(timer);
          reject(new SidecarUnavailableError("Sidecar write failed"));
        }
      });
    });
  }
}
