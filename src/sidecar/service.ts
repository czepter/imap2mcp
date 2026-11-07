import { getMailboxCredentials } from "../imap/mailboxes.js";
import { assertHostAllowed } from "../imap/ssrf.js";
import { Supervisor, type SupervisorOptions } from "./supervisor.js";
import { RPC_UNKNOWN_MAILBOX, SidecarRpcError } from "./errors.js";

export interface OpenParams {
  mailboxId: string; host: string; ip: string; port: number; servername: string; user: string; pass: string;
}

/** Resolves credentials + SSRF-vetted IP for a mailbox. Default uses the real stores; tests inject a fake. */
export type OpenParamsProvider = (mailboxId: string) => Promise<OpenParams>;

export const defaultOpenParams: OpenParamsProvider = async (mailboxId) => {
  const c = getMailboxCredentials(mailboxId);
  const addrs = await assertHostAllowed(c.host); // same SSRF policy + DNS pinning as the v0 direct path
  return { mailboxId, host: c.host, ip: addrs[0], port: c.port, servername: c.host, user: c.user, pass: c.password };
};

export interface SidecarServiceOptions extends SupervisorOptions {
  openParams?: OpenParamsProvider;
  /** How long to wait for a restarting sidecar before failing a call. */
  readyWaitMs?: number;
  /** Re-send credentials to the sidecar after this long (picks up admin password edits). */
  reopenAfterMs?: number;
}

/**
 * The Node-side facade used by MCP tools: supervised process + authenticated client +
 * lazy `open` of mailboxes (re-`open` after restart or on -32002, retrying the call once).
 */
export class SidecarService {
  readonly supervisor: Supervisor;
  private opened = new Map<string, { gen: number; at: number }>();
  private opening = new Map<string, Promise<void>>();
  private readonly openParams: OpenParamsProvider;
  private readonly readyWaitMs: number;
  private readonly reopenAfterMs: number;

  constructor(opts: SidecarServiceOptions) {
    this.supervisor = new Supervisor(opts);
    this.openParams = opts.openParams ?? defaultOpenParams;
    this.readyWaitMs = opts.readyWaitMs ?? 5_000;
    this.reopenAfterMs = opts.reopenAfterMs ?? 5 * 60_000;
  }

  start(): Promise<void> { return this.supervisor.start(); }
  async stop(): Promise<void> { this.opened.clear(); await this.supervisor.stop(); }

  private async ready(): Promise<void> {
    if (this.supervisor.state !== "ready") await this.supervisor.whenReady(this.readyWaitMs);
  }

  /** Non-mailbox RPC (ping, stats). */
  async call<T = unknown>(method: string, params: Record<string, unknown> = {}): Promise<T> {
    await this.ready();
    return this.supervisor.client.call<T>(method, params);
  }

  private ensureOpen(mailboxId: string, force = false): Promise<void> {
    const gen = this.supervisor.generation;
    const o = this.opened.get(mailboxId);
    if (!force && o && o.gen === gen && Date.now() - o.at < this.reopenAfterMs) return Promise.resolve();
    let p = this.opening.get(mailboxId);
    if (!p) {
      p = (async () => {
        const params = await this.openParams(mailboxId);
        await this.supervisor.client.call("open", { ...params });
        this.opened.set(mailboxId, { gen, at: Date.now() });
      })().finally(() => this.opening.delete(mailboxId));
      this.opening.set(mailboxId, p);
    }
    return p;
  }

  /** Mailbox-scoped RPC. Opens lazily; on -32002 re-opens and retries exactly once. */
  async callMailbox<T = unknown>(mailboxId: string, method: string, params: Record<string, unknown> = {}): Promise<T> {
    await this.ready();
    await this.ensureOpen(mailboxId);
    const run = () => this.supervisor.client.call<T>(method, { ...params, mailboxId });
    try {
      return await run();
    } catch (e) {
      if (e instanceof SidecarRpcError && e.code === RPC_UNKNOWN_MAILBOX) {
        this.opened.delete(mailboxId);
        await this.ensureOpen(mailboxId, true);
        return await run();
      }
      throw e;
    }
  }

  /** Mark cached data stale after a Node-side write. Best effort: an unknown/unreachable sidecar has nothing stale. */
  async invalidate(mailboxId: string, folder?: string): Promise<void> {
    try {
      await this.ready();
      await this.supervisor.client.call("invalidate", folder === undefined ? { mailboxId } : { mailboxId, folder }, 5_000);
    } catch (e) {
      void e;
      // Failure to invalidate must not fail an already-executed write; the sidecar reconciles within SYNC_RECONCILE_SECS.
    }
  }

  /** Forget a mailbox (deleted / credentials changed). Best effort. */
  async closeMailbox(mailboxId: string): Promise<void> {
    this.opened.delete(mailboxId);
    try { await this.call("close", { mailboxId }); } catch { /* ignore */ }
  }
}
