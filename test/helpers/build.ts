/**
 * Builds the Nuxt/Nitro server (`.output/server/index.mjs`) when it is missing or older than the sources.
 * Safe to call from several processes at once: a lock directory in the OS temp dir serialises builds, and
 * whoever waits re-checks freshness afterwards instead of building again.
 *
 * Environment: IMAP2MCP_BUILD=never  -> never build (fail if the output is missing; used when CI built it already)
 *              IMAP2MCP_BUILD=always -> rebuild unconditionally
 */
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readdirSync, rmSync, statSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

export const REPO_ROOT = resolve(import.meta.dirname, "../..");
export const SERVER_ENTRY = join(REPO_ROOT, ".output/server/index.mjs");

const SOURCE_DIRS = ["app", "server", "shared", "public", "assets"];
const SOURCE_FILES = ["nuxt.config.ts", "package.json", "package-lock.json", "components.json", "tsconfig.json"];
const BUILD_TIMEOUT_MS = 15 * 60_000;

function newestMtime(path: string): number {
  let st;
  try { st = statSync(path); } catch { return 0; }
  if (!st.isDirectory()) return st.mtimeMs;
  let newest = 0;
  for (const e of readdirSync(path, { withFileTypes: true })) {
    if (e.name === "node_modules" || e.name === ".nuxt" || e.name === ".output") continue;
    newest = Math.max(newest, newestMtime(join(path, e.name)));
  }
  return newest;
}

export function buildIsFresh(): boolean {
  if (!existsSync(SERVER_ENTRY)) return false;
  const built = statSync(SERVER_ENTRY).mtimeMs;
  const sources = Math.max(...SOURCE_DIRS.map((d) => newestMtime(join(REPO_ROOT, d))), ...SOURCE_FILES.map((f) => newestMtime(join(REPO_ROOT, f))));
  return built >= sources;
}

const lockDir = join(tmpdir(), `imap2mcp-build-${createHash("sha1").update(REPO_ROOT).digest("hex").slice(0, 12)}.lock`);

function pidAlive(pid: number): boolean {
  try { process.kill(pid, 0); return true; } catch { return false; }
}

async function acquire(): Promise<() => void> {
  const end = Date.now() + BUILD_TIMEOUT_MS + 60_000;
  for (;;) {
    try {
      mkdirSync(lockDir);
      writeFileSync(join(lockDir, "pid"), String(process.pid));
      return () => { try { rmSync(lockDir, { recursive: true, force: true }); } catch { /* gone */ } };
    } catch {
      // held by someone else: steal it if the holder died
      try {
        const pid = Number(readFileSync(join(lockDir, "pid"), "utf8"));
        if (pid && !pidAlive(pid)) rmSync(lockDir, { recursive: true, force: true });
      } catch { /* pid file not written yet */ }
      if (Date.now() > end) throw new Error(`timed out waiting for the build lock ${lockDir}`);
      await new Promise((r) => setTimeout(r, 500));
    }
  }
}

function runBuild(): Promise<void> {
  return new Promise((res, rej) => {
    const nuxt = join(REPO_ROOT, "node_modules/nuxt/bin/nuxt.mjs");
    const env = { ...process.env, NODE_ENV: "production", NUXT_TELEMETRY_DISABLED: "1" } as NodeJS.ProcessEnv;
    if (!/max-old-space-size/.test(env.NODE_OPTIONS ?? "")) env.NODE_OPTIONS = `${env.NODE_OPTIONS ?? ""} --max-old-space-size=3072`.trim();
    const p = spawn(process.execPath, [nuxt, "build"], { cwd: REPO_ROOT, env, stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    p.stdout.on("data", (d) => { out += d; });
    p.stderr.on("data", (d) => { out += d; });
    const t = setTimeout(() => { p.kill("SIGKILL"); }, BUILD_TIMEOUT_MS);
    p.on("close", (code) => {
      clearTimeout(t);
      if (code === 0) res();
      else rej(new Error(`nuxt build failed (exit ${code}):\n${out.slice(-6000)}`));
    });
  });
}

let ensured: Promise<void> | undefined;

/** Idempotent per process; cheap when the output is fresh. */
export function ensureBuild(): Promise<void> {
  ensured ??= (async () => {
    await buildIfNeeded();
  })();
  // a failed build must not poison later attempts in the same process
  ensured.catch(() => { ensured = undefined; });
  return ensured;
}

async function buildIfNeeded(): Promise<void> {
  {
    const mode = process.env.IMAP2MCP_BUILD;
    if (mode === "never") {
      if (!existsSync(SERVER_ENTRY)) throw new Error(`IMAP2MCP_BUILD=never but ${SERVER_ENTRY} does not exist`);
      return;
    }
    if (mode !== "always" && buildIsFresh()) return;
    const release = await acquire();
    try {
      // someone else may have built while we waited for the lock
      if (mode !== "always" && buildIsFresh()) return;
      console.info("[test build] running `nuxt build` (output missing or older than sources)...");
      const t = Date.now();
      await runBuild();
      console.info(`[test build] done in ${((Date.now() - t) / 1000).toFixed(0)} s`);
      if (mode === "always") process.env.IMAP2MCP_BUILD = "never"; // worker processes inherit this: build once per run
    } finally {
      release();
    }
  }
}
