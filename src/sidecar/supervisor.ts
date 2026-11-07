import { spawn, type ChildProcess } from "node:child_process";
import { randomBytes } from "node:crypto";
import { EventEmitter } from "node:events";
import { chmodSync, existsSync, mkdirSync, rmSync } from "node:fs";
import { dirname } from "node:path";
import { SidecarClient } from "./client.js";
import { SidecarUnavailableError } from "./errors.js";

export interface SupervisorOptions {
  bin: string;
  args?: string[];
  socketPath: string;
  /** Extra env for the child. The parent env is NOT inherited (keeps SESSION_SECRET etc. out of it). */
  env?: Record<string, string>;
  startTimeoutMs?: number;
  healthIntervalMs?: number;
  healthTimeoutMs?: number;
  healthFailures?: number;
  backoffBaseMs?: number;
  backoffMaxMs?: number;
  /** Uptime after which the backoff counter resets. */
  stableAfterMs?: number;
  killGraceMs?: number;
  log?: (msg: string) => void;
}

export type SupervisorState = "stopped" | "starting" | "ready" | "backoff";

/**
 * Spawns the sidecar binary, performs the stdin secret handshake, pings for health,
 * restarts with capped exponential backoff, and shuts down gracefully.
 * Emits: "ready" (generation:number), "exit" (code, signal).
 */
export class Supervisor extends EventEmitter {
  readonly client: SidecarClient;
  state: SupervisorState = "stopped";
  /** Incremented on every successful (re)start; callers use it to invalidate per-process state (opened mailboxes). */
  generation = 0;
  restarts = 0;
  private child: ChildProcess | null = null;
  private stopping = false;
  private failures = 0; // consecutive crash count for backoff
  private healthTimer: NodeJS.Timeout | null = null;
  private retryTimer: NodeJS.Timeout | null = null;
  private healthFails = 0;
  private readySince = 0;
  private readyWaiters: Array<{ resolve: () => void; reject: (e: Error) => void; timer: NodeJS.Timeout }> = [];
  private readonly o: Required<Omit<SupervisorOptions, "args" | "env" | "log">> & Pick<SupervisorOptions, "args" | "env" | "log">;

  constructor(opts: SupervisorOptions) {
    super();
    this.o = {
      startTimeoutMs: 10_000, healthIntervalMs: 10_000, healthTimeoutMs: 3_000, healthFailures: 3,
      backoffBaseMs: 500, backoffMaxMs: 30_000, stableAfterMs: 60_000, killGraceMs: 5_000, ...opts,
    };
    this.client = new SidecarClient({ socketPath: opts.socketPath, secret: "unset" });
  }

  private log(m: string): void { (this.o.log ?? ((s) => console.log(`[sidecar] ${s}`)))(m); }

  /** Start supervising. Resolves after the first successful ready, rejects if the first start fails (supervision then continues). */
  async start(): Promise<void> {
    if (this.state !== "stopped") throw new Error("Supervisor already started");
    this.stopping = false;
    this.failures = 0;
    const first = new Promise<void>((resolve, reject) => {
      const onReady = () => { cleanup(); resolve(); };
      const onFail = (e: Error) => { cleanup(); reject(e); };
      const cleanup = () => { this.off("ready", onReady); this.off("startFailed", onFail); };
      this.once("ready", onReady);
      this.once("startFailed", onFail);
    });
    void this.spawnChild();
    return first;
  }

  private async spawnChild(): Promise<void> {
    if (this.stopping) return;
    this.state = "starting";
    const secret = randomBytes(32).toString("hex");
    try {
      const dir = dirname(this.o.socketPath);
      mkdirSync(dir, { recursive: true, mode: 0o700 });
      try { chmodSync(dir, 0o700); } catch { /* not ours to chmod */ }
      rmSync(this.o.socketPath, { force: true }); // stale socket from a previous run
    } catch (e) {
      this.onStartFailure(new Error(`Cannot prepare socket directory: ${(e as Error).message}`));
      return;
    }
    const env: Record<string, string> = { PATH: process.env.PATH ?? "", SIDECAR_SOCKET: this.o.socketPath, ...(this.o.env ?? {}) };
    let child: ChildProcess;
    try {
      child = spawn(this.o.bin, this.o.args ?? [], { stdio: ["pipe", "pipe", "pipe"], env });
    } catch (e) {
      this.onStartFailure(new Error(`Cannot spawn sidecar: ${(e as Error).message}`));
      return;
    }
    this.child = child;
    let exited = false;
    const forward = (s: NodeJS.ReadableStream | null) => {
      let buf = "";
      s?.setEncoding?.("utf8");
      s?.on("data", (d: string) => {
        buf += d;
        let i: number;
        while ((i = buf.indexOf("\n")) >= 0) { this.log(buf.slice(0, i).slice(0, 500)); buf = buf.slice(i + 1); }
        if (buf.length > 4096) buf = "";
      });
    };
    forward(child.stdout); forward(child.stderr);
    child.stdin?.on("error", () => {});
    child.once("error", (e) => { if (!exited) { exited = true; this.onExit(child, null, null, e); } });
    child.once("exit", (code, signal) => { if (!exited) { exited = true; this.onExit(child, code, signal); } });

    // Secret handshake: one line on stdin, never argv/env. Stdin stays open (EOF = parent death for the child).
    child.stdin?.write(secret + "\n");
    this.client.setSecret(secret);

    try {
      await this.waitHealthy(child);
    } catch {
      // If the child already exited, onExit handled the restart; otherwise kill it so onExit does.
      if (!exited) child.kill("SIGKILL");
      return;
    }
    if (this.stopping || this.child !== child) return;
    this.generation++;
    this.state = "ready";
    this.readySince = Date.now();
    this.healthFails = 0;
    this.startHealth(child);
    this.log("ready");
    this.emit("ready", this.generation);
    const w = this.readyWaiters; this.readyWaiters = [];
    w.forEach((x) => { clearTimeout(x.timer); x.resolve(); });
  }

  private async waitHealthy(child: ChildProcess): Promise<void> {
    const deadline = Date.now() + this.o.startTimeoutMs;
    for (;;) {
      if (this.child !== child || child.exitCode !== null || child.signalCode !== null) throw new SidecarUnavailableError("Sidecar exited during startup");
      if (existsSync(this.o.socketPath)) {
        try { await this.client.call("ping", {}, this.o.healthTimeoutMs); return; } catch { /* not yet */ }
      }
      if (Date.now() > deadline) throw new SidecarUnavailableError("Sidecar did not become ready in time");
      await new Promise((r) => setTimeout(r, 100));
    }
  }

  private startHealth(child: ChildProcess): void {
    this.stopHealth();
    this.healthTimer = setInterval(() => {
      this.client.call("ping", {}, this.o.healthTimeoutMs).then(
        () => { this.healthFails = 0; },
        () => {
          if (++this.healthFails >= this.o.healthFailures && this.child === child) {
            this.log("health check failed, restarting sidecar");
            child.kill("SIGKILL"); // exit handler schedules the restart
          }
        },
      );
    }, this.o.healthIntervalMs);
    this.healthTimer.unref?.();
  }

  private stopHealth(): void { if (this.healthTimer) clearInterval(this.healthTimer); this.healthTimer = null; }

  private onExit(child: ChildProcess, code: number | null, signal: NodeJS.Signals | null, err?: Error): void {
    if (this.child !== child) return;
    this.child = null;
    this.stopHealth();
    this.client.reset(new SidecarUnavailableError("Sidecar exited"));
    this.emit("exit", code, signal);
    if (this.stopping) { this.state = "stopped"; return; }
    if (this.state === "ready" && Date.now() - this.readySince > this.o.stableAfterMs) this.failures = 0;
    const wasStarting = this.state === "starting";
    this.log(err ? `failed to run: ${err.message}` : `exited (code=${code}, signal=${signal})`);
    if (wasStarting && this.generation === 0) this.emit("startFailed", err ?? new Error("Sidecar exited during startup"));
    this.scheduleRestart();
  }

  private onStartFailure(e: Error): void {
    this.log(e.message);
    if (this.generation === 0) this.emit("startFailed", e);
    this.scheduleRestart();
  }

  private scheduleRestart(): void {
    if (this.stopping) return;
    this.state = "backoff";
    const delay = Math.min(this.o.backoffMaxMs, this.o.backoffBaseMs * 2 ** this.failures);
    this.failures++;
    this.restarts++;
    this.retryTimer = setTimeout(() => { this.retryTimer = null; void this.spawnChild(); }, delay);
    this.retryTimer.unref?.();
  }

  /** Resolve when the sidecar is ready; reject after `timeoutMs`. */
  whenReady(timeoutMs: number): Promise<void> {
    if (this.state === "ready") return Promise.resolve();
    if (this.state === "stopped") return Promise.reject(new SidecarUnavailableError("Sidecar is not running"));
    return new Promise((resolve, reject) => {
      const w = {
        resolve, reject,
        timer: setTimeout(() => {
          this.readyWaiters = this.readyWaiters.filter((x) => x !== w);
          reject(new SidecarUnavailableError("Sidecar is not ready"));
        }, timeoutMs),
      };
      this.readyWaiters.push(w);
    });
  }

  /** Graceful shutdown: SIGTERM, then SIGKILL after the grace period. Idempotent. */
  async stop(): Promise<void> {
    this.stopping = true;
    this.stopHealth();
    if (this.retryTimer) { clearTimeout(this.retryTimer); this.retryTimer = null; }
    const waiters = this.readyWaiters; this.readyWaiters = [];
    waiters.forEach((w) => { clearTimeout(w.timer); w.reject(new SidecarUnavailableError("Sidecar stopped")); });
    this.client.close();
    const child = this.child;
    if (child && child.exitCode === null && child.signalCode === null) {
      await new Promise<void>((resolve) => {
        const kill = setTimeout(() => child.kill("SIGKILL"), this.o.killGraceMs);
        child.once("exit", () => { clearTimeout(kill); resolve(); });
        try { child.stdin?.end(); } catch { /* ignore */ }
        child.kill("SIGTERM");
      });
    }
    this.child = null;
    this.state = "stopped";
    try { rmSync(this.o.socketPath, { force: true }); } catch { /* ignore */ }
  }
}
