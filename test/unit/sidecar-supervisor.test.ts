import { chmodSync, existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { SidecarService, type OpenParams } from "../../src/sidecar/service.js";
import { SidecarRpcError, SidecarUnavailableError } from "../../src/sidecar/errors.js";

const FAKE = resolve(import.meta.dirname, "fake-sidecar.mjs");
let dir: string;
let svc: SidecarService | null;
let opens: string[];

const params = async (id: string): Promise<OpenParams> => {
  opens.push(id);
  return { mailboxId: id, host: "imap.example.test", ip: "203.0.113.5", port: 993, servername: "imap.example.test", user: "u", pass: "pw-123" };
};

function make(extra: Partial<ConstructorParameters<typeof SidecarService>[0]> = {}): SidecarService {
  svc = new SidecarService({
    bin: FAKE, socketPath: join(dir, "sidecar.sock"), openParams: params, log: () => {},
    healthIntervalMs: 100, healthTimeoutMs: 300, backoffBaseMs: 50, backoffMaxMs: 200, startTimeoutMs: 5000, killGraceMs: 1000,
    ...extra,
  });
  return svc;
}

beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "scs-")); chmodSync(FAKE, 0o755); svc = null; opens = []; });
afterEach(async () => { await svc?.stop(); rmSync(dir, { recursive: true, force: true }); });

describe("sidecar supervisor / service", () => {
  it("starts via stdin secret handshake (secret not in argv/env) and answers ping", async () => {
    const s = make();
    await s.start();
    expect(s.supervisor.state).toBe("ready");
    const pong = await s.call<{ version: string }>("ping");
    expect(pong.version).toBe("fake");
    const st = await s.call<{ leak: boolean }>("debug.state");
    expect(st.leak).toBe(false);
  });

  it("opens a mailbox lazily with vetted ip + servername, only once", async () => {
    const s = make();
    await s.start();
    await s.callMailbox("m1", "listFolders");
    await s.callMailbox("m1", "listFolders");
    expect(opens).toEqual(["m1"]);
    const st = await s.call<{ openParams: Record<string, any> }>("debug.state");
    expect(st.openParams.m1).toMatchObject({ host: "imap.example.test", ip: "203.0.113.5", servername: "imap.example.test", port: 993, user: "u", pass: "pw-123" });
  });

  it("re-opens on -32002 and retries the call once", async () => {
    const s = make();
    await s.start();
    await s.callMailbox("m1", "listFolders");
    await s.call("debug.forget"); // sidecar loses its mailboxes without Node knowing
    const r = await s.callMailbox<{ folders: unknown[] }>("m1", "listFolders");
    expect(r.folders).toHaveLength(1);
    expect(opens).toEqual(["m1", "m1"]);
  });

  it("does not retry other errors", async () => {
    const s = make();
    await s.start();
    await expect(s.callMailbox("m1", "debug.upstream")).rejects.toMatchObject({ code: -32020 });
    expect(opens).toEqual(["m1"]);
  });

  it("restarts after a crash with a new secret, and re-opens mailboxes afterwards", async () => {
    const s = make();
    await s.start();
    await s.callMailbox("m1", "listFolders");
    const gen = s.supervisor.generation;
    await s.call("debug.crash");
    await new Promise<void>((resolveReady) => {
      const t = setInterval(() => { if (s.supervisor.generation > gen && s.supervisor.state === "ready") { clearInterval(t); resolveReady(); } }, 20);
    });
    const r = await s.callMailbox<{ folders: unknown[] }>("m1", "listFolders");
    expect(r.folders).toHaveLength(1);
    expect(opens).toEqual(["m1", "m1"]);
    expect(s.supervisor.restarts).toBeGreaterThanOrEqual(1);
  });

  it("health ping failure kills a hung sidecar and restarts it", async () => {
    const s = make({ healthFailures: 2 });
    await s.start();
    const gen = s.supervisor.generation;
    const pid1 = (await s.call<{ pid: number }>("debug.state")).pid;
    // Hang the only worker path: the fake answers each connection independently, so SIGSTOP the process instead.
    process.kill(pid1, "SIGSTOP");
    await new Promise<void>((resolveReady, reject) => {
      const end = Date.now() + 8000;
      const t = setInterval(() => {
        if (s.supervisor.generation > gen && s.supervisor.state === "ready") { clearInterval(t); resolveReady(); }
        else if (Date.now() > end) { clearInterval(t); reject(new Error("no restart")); }
      }, 50);
    });
    const pid2 = (await s.call<{ pid: number }>("debug.state")).pid;
    expect(pid2).not.toBe(pid1);
  });

  it("backs off and reports unavailable when the binary cannot run, without throwing from callers' perspective", async () => {
    const s = make({ bin: join(dir, "missing-binary"), readyWaitMs: 150 });
    await expect(s.start()).rejects.toBeTruthy();
    await expect(s.callMailbox("m1", "listFolders")).rejects.toBeInstanceOf(SidecarUnavailableError);
    expect(s.supervisor.state === "backoff" || s.supervisor.state === "starting").toBe(true);
  });

  it("invalidate is best effort and forwards folder", async () => {
    const s = make();
    await s.start();
    await s.callMailbox("m1", "listFolders");
    await s.invalidate("m1", "INBOX");
    await s.invalidate("m1");
    const st = await s.call<{ invalidated: unknown[] }>("debug.state");
    expect(st.invalidated).toEqual([["m1", "INBOX"], ["m1", null]]);
    await s.stop();
    await expect(s.invalidate("m1", "INBOX")).resolves.toBeUndefined();
  });

  it("graceful stop terminates the child and removes the socket", async () => {
    const s = make();
    await s.start();
    const pid = (await s.call<{ pid: number }>("debug.state")).pid;
    await s.stop();
    expect(existsSync(join(dir, "sidecar.sock"))).toBe(false);
    expect(() => process.kill(pid, 0)).toThrow();
    expect(s.supervisor.state).toBe("stopped");
  });

  it("rpc errors keep their code", async () => {
    const s = make();
    await s.start();
    const e = await s.call("nope").catch((x) => x);
    expect(e).toBeInstanceOf(SidecarRpcError);
    expect(e.code).toBe(-32601);
  });
});
