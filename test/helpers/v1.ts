/**
 * v1 integration helpers: a stack with the Go sidecar enabled, direct policy_rules management (the rule-editor UI is
 * exercised by its owner; here we need exact rule sets), process lookup for forced sidecar kills, polling.
 */
import { randomUUID } from "node:crypto";
import { existsSync, readdirSync, readFileSync, readlinkSync, realpathSync } from "node:fs";
import { resolve } from "node:path";
import { createStack, obtainToken, Mcp, sleep, type Stack, type ToolResult } from "./stack.js";
import { REPO } from "./server.js";

export const SIDECAR_BIN = resolve(process.env.SIDECAR_BIN ?? resolve(REPO, "sidecar/bin/sidecar"));
export const haveSidecar = existsSync(SIDECAR_BIN);
if (!haveSidecar) console.warn(`SKIPPED v1 sidecar tests: ${SIDECAR_BIN} not built (scripts/go.sh build -o bin/sidecar ./cmd/sidecar)`);

export type Op = "search" | "read_headers" | "read_body" | "draft" | "move" | "flag";
export const ALL_OPS: Op[] = ["search", "read_headers", "read_body", "draft", "move", "flag"];
export type Rule = [folder: string, op: Op, effect: "allow" | "deny"];
export const ALICE = "alice@example.test";

export async function createV1Stack(o: { reconcileSecs?: number; env?: Record<string, string | undefined> } = {}): Promise<Stack> {
  return createStack({
    env: { SIDECAR_BIN, SYNC_RECONCILE_SECS: String(o.reconcileSecs ?? 2), ...o.env },
  });
}

/** Replaces ALL policy rules of a client for one mailbox (live DB, takes effect on the next call). */
export function setRules(s: Stack, clientId: string, mailboxId: string, rules: Rule[]): void {
  const db = s.srv.db();
  try {
    db.pragma("busy_timeout = 5000");
    db.transaction(() => {
      db.prepare("DELETE FROM policy_rules WHERE client_id = ? AND mailbox_id = ?").run(clientId, mailboxId);
      const ins = db.prepare("INSERT INTO policy_rules (id, client_id, mailbox_id, folder, operation, effect) VALUES (?, ?, ?, ?, ?, ?)");
      for (const [folder, op, effect] of rules) ins.run(randomUUID(), clientId, mailboxId, folder, op, effect);
    })();
  } finally {
    db.close();
  }
}
export const allowAll = (folder = "*"): Rule[] => ALL_OPS.map((op) => [folder, op, "allow"] as Rule);

export interface Client { clientId: string; token: string; mcp: Mcp }
/** Registers + consents (all scopes) through the real OAuth flow, then installs exactly `rules`. */
export async function newClient(s: Stack, mailbox: string, rules: Rule[], name = "v1-client"): Promise<Client> {
  const { clientId, tokens } = await obtainToken(s, [[mailbox, "read"], [mailbox, "draft"], [mailbox, "organize"]], { name });
  setRules(s, clientId, mailbox, rules);
  const mcp = await new Mcp(s.base, tokens.access_token).connect();
  return { clientId, token: tokens.access_token, mcp };
}

/** Like Mcp.call but transport-level failures (401 after revocation) are returned as a denied result, not thrown. */
export async function tryCall(mcp: Mcp, name: string, args: Record<string, unknown> = {}): Promise<ToolResult & { transportError?: string }> {
  try {
    return await mcp.call(name, args);
  } catch (e) {
    return { isError: true, data: null, text: String(e), transportError: String(e) };
  }
}

export async function poll<T>(fn: () => Promise<T | null | undefined | false> | T | null | undefined | false, ms = 15000, every = 150): Promise<T> {
  const end = Date.now() + ms;
  let last: unknown;
  for (;;) {
    try {
      const v = await fn();
      if (v) return v as T;
    } catch (e) {
      last = e;
    }
    if (Date.now() > end) throw new Error(`poll timed out after ${ms} ms${last ? ` (last error: ${String(last)})` : ""}`);
    await sleep(every);
  }
}

export const subjects = (r: ToolResult): string[] => (r.data?.messages ?? []).map((m: any) => m.subject);
export const folderOf = (m: any): string | undefined => m.ref?.folder ?? m.folder;

/** PIDs of sidecar processes that are descendants of `rootPid` (the server under test); other stacks' sidecars are ignored. */
export function sidecarPids(rootPid: number): number[] {
  const real = realpathSync(SIDECAR_BIN);
  const ppid = new Map<number, number>();
  const exe = new Map<number, string>();
  for (const d of readdirSync("/proc")) {
    if (!/^\d+$/.test(d)) continue;
    try {
      const st = readFileSync(`/proc/${d}/stat`, "utf8");
      ppid.set(Number(d), Number(st.slice(st.lastIndexOf(")") + 2).split(" ")[1]));
      exe.set(Number(d), readlinkSync(`/proc/${d}/exe`));
    } catch { /* process vanished / not ours */ }
  }
  const under = (pid: number): boolean => {
    for (let p = ppid.get(pid), n = 0; p && n < 20; p = ppid.get(p), n++) if (p === rootPid) return true;
    return false;
  };
  return [...exe].filter(([pid, e]) => e === real && under(pid)).map(([pid]) => pid);
}
export function rssKb(pid: number): number {
  const m = /VmRSS:\s+(\d+) kB/.exec(readFileSync(`/proc/${pid}/status`, "utf8"));
  return m ? Number(m[1]) : 0;
}
