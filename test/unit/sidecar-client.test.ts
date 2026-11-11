import net from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { SidecarClient } from "../../server/core/sidecar/client.js";
import { SidecarRpcError, SidecarTimeoutError, SidecarUnavailableError } from "../../server/core/sidecar/errors.js";

let dir: string;
let sockPath: string;
let server: net.Server;
let conns: net.Socket[];
let onLine: (c: net.Socket, req: any) => void;

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), "sc-"));
  sockPath = join(dir, "s.sock");
  conns = [];
  onLine = () => {};
  server = net.createServer((c) => {
    conns.push(c);
    c.on("error", () => {});
    let buf = "";
    c.on("data", (d) => {
      buf += d.toString();
      let i;
      while ((i = buf.indexOf("\n")) >= 0) { const l = buf.slice(0, i); buf = buf.slice(i + 1); if (l) onLine(c, JSON.parse(l)); }
    });
  });
  await new Promise<void>((r) => server.listen(sockPath, r));
});
afterEach(async () => {
  conns.forEach((c) => c.destroy());
  await new Promise((r) => server.close(r));
  rmSync(dir, { recursive: true, force: true });
});

const reply = (c: net.Socket, id: number, result: unknown) => c.write(JSON.stringify({ jsonrpc: "2.0", id, result }) + "\n");

describe("SidecarClient framing", () => {
  it("sends newline-delimited JSON-RPC 2.0 with auth, and callers cannot override auth", async () => {
    const seen: any[] = [];
    onLine = (c, req) => { seen.push(req); reply(c, req.id, { ok: true }); };
    const cl = new SidecarClient({ socketPath: sockPath, secret: "s3cret" });
    await cl.call("open", { mailboxId: "m", auth: "evil" });
    expect(seen[0]).toMatchObject({ jsonrpc: "2.0", method: "open", params: { mailboxId: "m", auth: "s3cret" } });
    expect(typeof seen[0].id).toBe("number");
    cl.close();
  });

  it("handles responses split across chunks, several per chunk, and out of order", async () => {
    const reqs: any[] = [];
    onLine = (c, req) => {
      reqs.push(req);
      if (reqs.length < 3) return;
      const [a, b, d] = reqs;
      const m = (r: any) => JSON.stringify({ jsonrpc: "2.0", id: r.id, result: r.params.n }) + "\n";
      // d and b in one chunk, then a split in the middle
      c.write(m(d) + m(b));
      const half = m(a);
      c.write(half.slice(0, 7));
      setTimeout(() => c.write(half.slice(7)), 20);
    };
    const cl = new SidecarClient({ socketPath: sockPath, secret: "x" });
    const out = await Promise.all([1, 2, 3].map((n) => cl.call("echo", { n })));
    expect(out).toEqual([1, 2, 3]);
    cl.close();
  });

  it("maps JSON-RPC errors to SidecarRpcError with the code", async () => {
    onLine = (c, req) => c.write(JSON.stringify({ jsonrpc: "2.0", id: req.id, error: { code: -32010, message: "stale" } }) + "\n");
    const cl = new SidecarClient({ socketPath: sockPath, secret: "x" });
    await expect(cl.call("fetchHeaders")).rejects.toMatchObject({ name: "SidecarRpcError", code: -32010 });
    cl.close();
  });

  it("times out and ignores the late response", async () => {
    let held: { c: net.Socket; id: number } | undefined;
    onLine = (c, req) => { if (req.method === "slow") held = { c, id: req.id }; else reply(c, req.id, "fine"); };
    const cl = new SidecarClient({ socketPath: sockPath, secret: "x" });
    await expect(cl.call("slow", {}, 80)).rejects.toBeInstanceOf(SidecarTimeoutError);
    reply(held!.c, held!.id, "late");
    await expect(cl.call("fast")).resolves.toBe("fine");
    cl.close();
  });

  it("fails in-flight calls when the connection drops and reconnects afterwards", async () => {
    onLine = (c, req) => { if (req.method === "die") c.destroy(); else reply(c, req.id, "ok"); };
    const cl = new SidecarClient({ socketPath: sockPath, secret: "x" });
    await expect(cl.call("die")).rejects.toBeInstanceOf(SidecarUnavailableError);
    await expect(cl.call("again")).resolves.toBe("ok");
    cl.close();
  });

  it("reports unavailable when nothing listens", async () => {
    const cl = new SidecarClient({ socketPath: join(dir, "nope.sock"), secret: "x" });
    await expect(cl.call("ping")).rejects.toBeInstanceOf(SidecarUnavailableError);
    cl.close();
  });
});

describe("SidecarClient authentication failure", () => {
  it("surfaces -32001, drops the connection, and does not leak the secret in the error", async () => {
    onLine = (c, req) => {
      if (req.params.auth !== "right") {
        c.write(JSON.stringify({ jsonrpc: "2.0", id: req.id, error: { code: -32001, message: "unauthorized" } }) + "\n");
        c.end();
      } else reply(c, req.id, "ok");
    };
    const cl = new SidecarClient({ socketPath: sockPath, secret: "wrong-secret-value" });
    const err = await cl.call("ping").catch((e) => e);
    expect(err).toBeInstanceOf(SidecarRpcError);
    expect(err.code).toBe(-32001);
    expect(String(err.message)).not.toContain("wrong-secret-value");
    cl.setSecret("right");
    await expect(cl.call("ping")).resolves.toBe("ok");
    cl.close();
  });
});
