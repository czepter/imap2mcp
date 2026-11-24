import { chmodSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SidecarService, type OpenParams } from "../../server/core/sidecar/service.js";
import { sidecarBackend } from "../../server/core/mcp/backend-sidecar.js";
import { reliableBackend } from "../../server/core/mcp/reliability.js";
import { runWithAudit } from "../../server/core/audit/context.js";

const holder = vi.hoisted(() => ({ svc: null as unknown }));
vi.mock("../../server/core/sidecar/index.js", () => ({ sidecarEnabled: () => true, getSidecar: () => holder.svc }));

const FAKE = resolve(import.meta.dirname, "fake-sidecar.mjs");
let dir: string;
let svc: SidecarService;

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), "scs-"));
  chmodSync(FAKE, 0o755);
  const openParams = async (id: string): Promise<OpenParams> => ({ mailboxId: id, host: "imap.example.test", ip: "203.0.113.5", port: 993, servername: "imap.example.test", user: "u", pass: "pw-123" });
  svc = new SidecarService({
    bin: FAKE, socketPath: join(dir, "sidecar.sock"), openParams, log: () => {},
    healthIntervalMs: 100, healthTimeoutMs: 300, backoffBaseMs: 50, backoffMaxMs: 200, startTimeoutMs: 5000, killGraceMs: 1000,
  });
  await svc.start();
  holder.svc = svc;
});
afterEach(async () => { holder.svc = null; await svc.stop(); rmSync(dir, { recursive: true, force: true }); });

describe("sidecarBackend.fetchRawHeader", () => {
  it("sends the RPC with folder, uidValidity, uid and maxBytes and decodes base64 UTF-8", async () => {
    const r = await sidecarBackend.fetchRawHeader("m1", "INBOX", 7, 1, 4096);
    expect(r.raw).toBe(`Subject: gr${String.fromCodePoint(0xfc, 0xdf)}e\r\nAuthentication-Results: mx.recv.example; spf=pass\r\n\r\n`);
    expect(r.truncated).toBe(false);
    const st = await svc.call<{ lastRawHeader: unknown }>("debug.state");
    expect(st.lastRawHeader).toEqual({ folder: "INBOX", uidValidity: 7, uid: 1, maxBytes: 4096 });
  });

  it("passes truncated through", async () => {
    const r = await sidecarBackend.fetchRawHeader("m1", "INBOX", 7, 2, 64);
    expect(r.raw).toBe("X".repeat(64));
    expect(r.truncated).toBe(true);
  });

  it("is exposed by reliableBackend, and a gone message (-32010) becomes STALE_REFERENCE", async () => {
    const b = reliableBackend(sidecarBackend);
    const ok = await b.fetchRawHeader("m1", "INBOX", 7, 1, 4096);
    expect(ok.raw).toContain("Authentication-Results");
    await expect(b.fetchRawHeader("m1", "INBOX", 7, 99, 4096)).rejects.toMatchObject({ code: "STALE_REFERENCE" });
  });

  it("is never cached: the audit note says cached: false", async () => {
    const b = reliableBackend(sidecarBackend);
    const scope = { requestId: "r1", note: {} as { cached?: boolean } };
    await runWithAudit(scope, async () => { await b.fetchRawHeader("m1", "INBOX", 7, 1, 4096); });
    expect(scope.note.cached).toBe(false);
  });
});
