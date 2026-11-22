import { mkdtempSync, rmSync, statSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import tls from "node:tls";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { TlsRelay, tlsRelayEnabled } from "../../server/core/sidecar/tlsRelay.js";
import { makeSelfSignedCert } from "../helpers/certs.js";

const cert = makeSelfSignedCert();
const d = cert ? describe : describe.skip;
const SECRET = "relay-secret-0123456789abcdef";

function exchange(sock: string, send: string, opts: { keepOpen?: boolean } = {}): Promise<{ reply: string; closed: boolean; sock: net.Socket }> {
  return new Promise((resolve) => {
    const c = net.connect(sock);
    let reply = "";
    c.setEncoding("utf8");
    c.on("data", (x) => { reply += x; if (opts.keepOpen && reply.includes("\n")) resolve({ reply, closed: false, sock: c }); });
    c.on("error", () => {});
    c.on("close", () => resolve({ reply, closed: true, sock: c }));
    c.write(send);
  });
}

d("TLS relay", () => {
  let dir: string;
  let upstream: tls.Server;
  let upstreamPort = 0;
  let accepted = 0;
  let relay: TlsRelay;
  let sockPath: string;

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), "relay-"));
    upstream = tls.createServer({ key: cert!.key, cert: cert!.cert }, (s) => {
      accepted++;
      s.write("* OK hello\r\n");
      s.on("data", (b) => s.write(`echo:${b}`));
      s.on("error", () => {});
    });
    await new Promise<void>((r) => upstream.listen(0, "127.0.0.1", r));
    upstreamPort = (upstream.address() as net.AddressInfo).port;
    sockPath = join(dir, "r.sock");
    relay = new TlsRelay({
      socketPath: sockPath,
      getSecret: () => SECRET,
      target: (id) => {
        if (id === "mb1") return { host: "localhost", port: upstreamPort };
        if (id === "bad-cert") return { host: "not-localhost.invalid", port: upstreamPort };
        throw new Error("Mailbox not found");
      },
      resolve: async () => ["127.0.0.1"],
      tlsOptions: { ca: cert!.cert },
    });
    await relay.start();
  });
  afterAll(async () => {
    await relay.stop();
    await new Promise((r) => upstream.close(r));
    rmSync(dir, { recursive: true, force: true });
  });

  it("listens on a 0600 socket", () => {
    expect(statSync(sockPath).mode & 0o777).toBe(0o600);
  });

  it("closes without connecting upstream on a wrong secret", async () => {
    const before = accepted;
    const r = await exchange(sockPath, JSON.stringify({ auth: "nope", mailboxId: "mb1" }) + "\n");
    expect(r.closed).toBe(true);
    expect(r.reply).toBe("");
    expect(accepted).toBe(before);
  });

  it("closes on malformed input", async () => {
    const r = await exchange(sockPath, "not json\n");
    expect(r.closed).toBe(true);
    expect(r.reply).toBe("");
  });

  it("answers ERR for an unknown mailbox", async () => {
    const r = await exchange(sockPath, JSON.stringify({ auth: SECRET, mailboxId: "nope" }) + "\n");
    expect(r.reply).toBe("ERR unknown mailbox\n");
    expect(r.closed).toBe(true);
  });

  it("answers ERR when the certificate does not match the host", async () => {
    const r = await exchange(sockPath, JSON.stringify({ auth: SECRET, mailboxId: "bad-cert" }) + "\n");
    expect(r.reply).toBe("ERR tls certificate validation failed\n");
  });

  it("answers OK and pipes bytes both ways", async () => {
    const { reply, sock } = await exchange(sockPath, JSON.stringify({ auth: SECRET, mailboxId: "mb1" }) + "\n", { keepOpen: true });
    expect(reply.startsWith("OK\n")).toBe(true);
    const got = await new Promise<string>((resolve) => {
      let acc = reply.slice(3);
      const check = () => { if (acc.includes("echo:ping")) resolve(acc); };
      sock.on("data", (x) => { acc += x; check(); });
      sock.write("ping");
      check();
    });
    expect(got).toContain("* OK hello");
    expect(got).toContain("echo:ping");
    const closed = new Promise<void>((r) => sock.once("close", () => r()));
    sock.end();
    await closed;
  });
});

describe("tlsRelayEnabled", () => {
  it("is on by default and off for 0|false|off|no", () => {
    expect(tlsRelayEnabled({})).toBe(true);
    for (const v of ["0", "false", "off", "no", "OFF"]) expect(tlsRelayEnabled({ IMAP_TLS_RELAY: v })).toBe(false);
    expect(tlsRelayEnabled({ IMAP_TLS_RELAY: "1" })).toBe(true);
  });
});
