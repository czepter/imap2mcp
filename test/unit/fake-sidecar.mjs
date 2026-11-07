#!/usr/bin/env node
// Minimal fake of the sidecar contract for Node-side tests: secret on stdin, UDS at $SIDECAR_SOCKET, NDJSON JSON-RPC.
import net from "node:net";
import { createInterface } from "node:readline";

const sock = process.env.SIDECAR_SOCKET;
const rl = createInterface({ input: process.stdin });
const startedAt = Date.now();
const opened = new Map(); // mailboxId -> open params
const invalidated = [];
let secret = null;

function leak() {
  const hay = JSON.stringify([process.argv, process.env]);
  return secret ? hay.includes(secret) : null;
}

function handle(method, p) {
  switch (method) {
    case "ping": return { version: "fake", uptimeSecs: Math.floor((Date.now() - startedAt) / 1000), rssBytes: 1 };
    case "open": opened.set(p.mailboxId, p); return { ok: true };
    case "close": opened.delete(p.mailboxId); return { ok: true };
    case "invalidate": invalidated.push([p.mailboxId, p.folder ?? null]); return { ok: true };
    case "listFolders":
      if (!opened.has(p.mailboxId)) throw { code: -32002, message: "unknown mailbox" };
      return { folders: [{ path: "INBOX", delimiter: "/", flags: [] }] };
    case "debug.state": return { opened: [...opened.keys()], openParams: Object.fromEntries(opened), invalidated, leak: leak(), pid: process.pid };
    case "debug.forget": opened.clear(); return { ok: true };
    case "debug.crash": setTimeout(() => process.exit(3), 10); return { ok: true };
    case "debug.hang": return new Promise(() => {});
    case "debug.upstream": throw { code: -32020, message: "upstream error" };
    default: throw { code: -32601, message: "method not found" };
  }
}

rl.once("line", (line) => {
  secret = line.trim();
  const server = net.createServer((c) => {
    let buf = "";
    c.on("error", () => {});
    c.on("data", async (d) => {
      buf += d.toString("utf8");
      let i;
      while ((i = buf.indexOf("\n")) >= 0) {
        const l = buf.slice(0, i); buf = buf.slice(i + 1);
        if (!l.trim()) continue;
        const req = JSON.parse(l);
        if (req.params?.auth !== secret) {
          c.write(JSON.stringify({ jsonrpc: "2.0", id: req.id, error: { code: -32001, message: "unauthorized" } }) + "\n");
          c.end();
          return;
        }
        try {
          const result = await handle(req.method, req.params);
          c.write(JSON.stringify({ jsonrpc: "2.0", id: req.id, result }) + "\n");
        } catch (e) {
          c.write(JSON.stringify({ jsonrpc: "2.0", id: req.id, error: { code: e.code ?? -32603, message: e.message ?? "error" } }) + "\n");
        }
      }
    });
  });
  server.listen(sock);
  const quit = () => { server.close(); process.exit(0); };
  process.on("SIGTERM", quit);
  rl.on("close", quit);
});
