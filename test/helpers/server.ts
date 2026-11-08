import { spawn, type ChildProcess } from "node:child_process";
import { createServer } from "node:net";
import { randomBytes } from "node:crypto";
import { mkdtempSync, writeFileSync, chmodSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import Database from "better-sqlite3";

export const REPO = resolve(import.meta.dirname, "../..");

export async function freePort(): Promise<number> {
  return new Promise((res, rej) => {
    const s = createServer();
    s.once("error", rej);
    s.listen(0, "127.0.0.1", () => {
      const p = (s.address() as { port: number }).port;
      s.close(() => res(p));
    });
  });
}

export interface Workdir {
  dir: string;
  dataDir: string;
  keyFile: string;
  keyHex: string;
  sessionSecret: string;
  cleanup(): void;
}

export function makeWorkdir(): Workdir {
  const dir = mkdtempSync(join(tmpdir(), "imap2mcp-it-"));
  const keyHex = randomBytes(32).toString("hex");
  const keyFile = join(dir, "master.key");
  writeFileSync(keyFile, keyHex + "\n");
  chmodSync(keyFile, 0o600);
  return { dir, dataDir: join(dir, "data"), keyFile, keyHex, sessionSecret: randomBytes(32).toString("hex"), cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

export interface RunningServer {
  baseUrl: string;
  port: number;
  proc: ChildProcess;
  /** combined stdout+stderr so far (used for the "no secrets in logs" assertions) */
  output(): string;
  exited(): Promise<number | null>;
  stop(): Promise<void>;
  /** read-only handle on the live DB (WAL-safe) */
  db(): Database.Database;
}

export interface StartOpts {
  work: Workdir;
  port?: number;
  caFile?: string;
  env?: Record<string, string | undefined>;
  /** if true, do not wait for readiness (used for fail-closed startup tests) */
  expectExit?: boolean;
}

/** Spawns the real server (`tsx src/index.ts`) as a child process on a free port. */
export async function startServer(o: StartOpts): Promise<RunningServer> {
  const port = o.port ?? (await freePort());
  const baseUrl = `http://127.0.0.1:${port}`;
  const env: Record<string, string | undefined> = {
    PATH: process.env.PATH,
    HOME: process.env.HOME,
    NODE_ENV: "test",
    PORT: String(port),
    BASE_URL: baseUrl,
    DATA_DIR: o.work.dataDir,
    ENCRYPTION_KEY_FILE: o.work.keyFile,
    SESSION_SECRET: o.work.sessionSecret,
    REGISTRATION_MODE: "dynamic",
    ALLOW_PRIVATE_HOSTS: "localhost",
    ...(o.caFile ? { NODE_EXTRA_CA_CERTS: o.caFile, SIDECAR_EXTRA_CA_FILE: o.caFile } : {}),
    ...o.env,
  };
  for (const k of Object.keys(env)) if (env[k] === undefined) delete env[k];

  const proc = spawn(process.execPath, [resolve(REPO, "node_modules/tsx/dist/cli.mjs"), resolve(REPO, "src/index.ts")], {
    cwd: REPO,
    env: env as NodeJS.ProcessEnv,
    stdio: ["ignore", "pipe", "pipe"],
    detached: true, // own process group: tsx spawns the real server as a child, so stop() must signal the whole group
  });
  const killGroup = (sig: NodeJS.Signals) => { try { process.kill(-proc.pid!, sig); } catch { /* already gone */ } };
  let out = "";
  proc.stdout!.on("data", (d) => (out += d));
  proc.stderr!.on("data", (d) => (out += d));
  const exited = new Promise<number | null>((r) => proc.once("exit", (c) => r(c)));

  const srv: RunningServer = {
    baseUrl,
    port,
    proc,
    output: () => out,
    exited: () => exited,
    async stop() {
      if (proc.exitCode === null && proc.signalCode === null) {
        killGroup("SIGTERM");
        const t = setTimeout(() => killGroup("SIGKILL"), 10_000);
        await exited;
        clearTimeout(t);
      }
      killGroup("SIGKILL"); // no orphaned server child may keep the database open after stop() returns
    },
    db() {
      return new Database(join(o.work.dataDir, "bridge.db"), { readonly: false });
    },
  };
  if (o.expectExit) return srv;

  const deadline = Date.now() + 40_000;
  for (;;) {
    if (proc.exitCode !== null) throw new Error(`server exited early (${proc.exitCode}):\n${out}`);
    try {
      const r = await fetch(`${baseUrl}/.well-known/oauth-authorization-server`);
      if (r.ok) break;
    } catch {
      /* not up yet */
    }
    if (Date.now() > deadline) {
      await srv.stop();
      throw new Error(`server did not start:\n${out}`);
    }
    await new Promise((r) => setTimeout(r, 150));
  }
  return srv;
}

/** Pulls the one-time bootstrap token from the server's stdout. */
export function bootstrapTokenFrom(output: string): string | null {
  const m = /bootstrap token:\s*\n\s*(\S+)/i.exec(output);
  return m ? m[1] : null;
}
