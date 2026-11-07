/**
 * Version 1 acceptance criteria 2 and 3: the sidecar boundary and sync correctness, end to end over real HTTP/OAuth with
 * the Go sidecar running. Cache identity (mailbox, folder, UIDVALIDITY, UID), UIDNEXT-guided arrivals, UID/flag
 * reconciliation, UIDVALIDITY invalidation, forced sidecar kill + rebuild, and the "private channel" properties.
 */
import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import net from "node:net";
import { readFileSync, readdirSync, readlinkSync, statSync } from "node:fs";
import { join } from "node:path";
import { makeSelfSignedCert } from "../helpers/certs.js";
import { msg, sleep, type Stack } from "../helpers/stack.js";
import { ALICE, allowAll, createV1Stack, haveSidecar, newClient, poll, sidecarPids, subjects, type Client } from "../helpers/v1.js";

// polling tests wait on the sidecar's 5 s implicit sync / reconcile interval; the default 30 s per-test budget is too tight on a busy host
vi.setConfig({ testTimeout: 120_000, hookTimeout: 120_000 });

const ok = !!makeSelfSignedCert() && haveSidecar;
const BIG = 1500;
const pad = (i: number) => String(i).padStart(5, "0");

describe.skipIf(!ok)("v1 sidecar: boundary, cache and sync correctness", () => {
  let s: Stack;
  let box: string;
  let c: Client;
  const search = (folder: string, args: Record<string, unknown> = {}) =>
    c.mcp.call("search_messages", { mailbox: box, folder, ...args });
  const bigStat = (uid: number) => s.fake.fetchStat(ALICE, "Big", uid);

  beforeAll(async () => {
    s = await createV1Stack({ reconcileSecs: 2 });
    box = s.mailbox[ALICE];
    s.fake.addFolder(ALICE, "Big");
    s.fake.addGenerated(ALICE, "Big", BIG, { subject: (i) => `base-${pad(i)}` });
    s.fake.addFolder(ALICE, "Rebirth");
    s.fake.addGenerated(ALICE, "Rebirth", 40, { subject: (i) => `old-life-${i}` });
    c = await newClient(s, box, allowAll(), "sidecar-tests");
  });
  afterAll(async () => {
    await c?.mcp.close();
    await s?.teardown();
  });

  describe("sidecar boundary (criterion 2)", () => {
    it("exactly one sidecar runs; it listens on no TCP port and carries no credentials in argv/env", async () => {
      await search("Sent", { subject: "peek" }); // make sure it is up and has the mailbox open (Big stays cold for the sync test)
      const pids = await poll(() => { const p = sidecarPids(s.srv.proc.pid!); return p.length ? p : null; }, 10_000);
      expect(pids).toHaveLength(1);
      const pid = pids[0];
      const inodes = new Set<string>();
      for (const f of ["/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"]) {
        for (const line of readFileSync(f, "utf8").split("\n").slice(1)) {
          const cols = line.trim().split(/\s+/);
          if (cols.length > 9 && (cols[3] === "0A" || f.includes("udp"))) inodes.add(cols[9]);
        }
      }
      const owned = readdirSync(`/proc/${pid}/fd`).map((fd) => { try { return readlinkSync(`/proc/${pid}/fd/${fd}`); } catch { return ""; } });
      const listening = owned.filter((l) => /^socket:\[(\d+)\]$/.test(l) && inodes.has(/\[(\d+)\]/.exec(l)![1]));
      expect(listening, "sidecar must not listen on TCP/UDP").toEqual([]);
      const cmd = readFileSync(`/proc/${pid}/cmdline`, "utf8");
      const env = readFileSync(`/proc/${pid}/environ`, "utf8");
      for (const secret of Object.values(s.imapPasswords)) {
        expect(cmd).not.toContain(secret);
        expect(env).not.toContain(secret);
      }
    });

    it("the socket and its directory are private (0600 / 0700)", () => {
      const sock = join(s.work.dataDir, "sidecar.sock");
      expect(statSync(sock).mode & 0o777).toBe(0o600);
      expect(statSync(s.work.dataDir).mode & 0o777).toBe(0o700);
    });

    const rpc = (payload: object) =>
      new Promise<{ replies: any[]; closed: boolean }>((resolve, reject) => {
        const sock = net.connect(join(s.work.dataDir, "sidecar.sock"));
        const replies: any[] = [];
        let buf = "";
        sock.on("data", (d) => {
          buf += d;
          for (let i = buf.indexOf("\n"); i >= 0; i = buf.indexOf("\n")) {
            try { replies.push(JSON.parse(buf.slice(0, i))); } catch { /* ignore */ }
            buf = buf.slice(i + 1);
          }
        });
        sock.on("error", reject);
        sock.on("close", () => resolve({ replies, closed: true }));
        sock.write(JSON.stringify(payload) + "\n");
        setTimeout(() => sock.destroy(), 2000);
      });

    it("a request without the per-process secret is rejected (-32001) and never serves data", async () => {
      const r = await rpc({ jsonrpc: "2.0", id: 1, method: "ping", params: {} });
      expect(r.replies[0]?.error?.code).toBe(-32001);
      expect(r.replies[0]?.result).toBeUndefined();
      const r2 = await rpc({ jsonrpc: "2.0", id: 2, method: "listFolders", params: { auth: "0".repeat(64), mailboxId: box } });
      expect(r2.replies[0]?.error?.code).toBe(-32001);
      expect(JSON.stringify(r2.replies)).not.toMatch(/INBOX|Archive/);
    });

    it("bodies are never cached: every read_message goes to IMAP, with BODY.PEEK (no \\Seen)", async () => {
      s.fake.addMessage(ALICE, "Sent", msg("peek-me", "peek body text"));
      const m = (await poll(async () => {
        const r = await search("Sent", { subject: "peek-me" });
        return r.data?.messages?.length ? r : null; // the sidecar's implicit sync may take up to 5 s to notice new mail
      }, 20_000)).data.messages[0];
      s.fake.resetFetchStats();
      for (let i = 0; i < 3; i++) expect((await c.mcp.call("read_message", { ref: m.ref })).data.body).toContain("peek body text");
      expect(s.fake.fetchStat(ALICE, "Sent", m.ref.uid).body).toBeGreaterThanOrEqual(3);
      expect(s.fake.folder(ALICE, "Sent").messages.find((x) => x.uid === m.ref.uid)!.flags.has("\\Seen")).toBe(false);
    });
  });

  describe("cold sync and cache reuse", () => {
    it("fetches every header once and answers repeated searches from the cache", async () => {
      s.fake.resetFetchStats();
      const first = await search("Big", { subject: "base-00077" });
      expect(first.isError, first.text).toBe(false);
      expect(subjects(first)).toEqual(["base-00077"]);
      expect(first.data.messages.every((m: any) => m.ref.uidValidity === s.fake.folder(ALICE, "Big").uidValidity)).toBe(true);
      const cold = s.fake.fetchTotal(ALICE, "Big", "envelope");
      expect(cold).toBeGreaterThanOrEqual(BIG);
      expect(cold).toBeLessThanOrEqual(BIG + 5);
      s.fake.resetFetchStats();
      for (let i = 0; i < 5; i++) await search("Big", { subject: `base-00${i}00` });
      expect(s.fake.fetchTotal(ALICE, "Big", "envelope")).toBe(0);
    });
  });

  describe("UIDNEXT arrivals", () => {
    it("new mail becomes searchable and unchanged messages are not re-FETCHed", async () => {
      await search("Big", { subject: "base-00001" });
      s.fake.resetFetchStats();
      const added = s.fake.externalDeliver(ALICE, "Big", 25, (i) => `arrival-${i}`);
      const t0 = Date.now();
      const hit = await poll(async () => {
        const r = await search("Big", { subject: "arrival-", limit: 50 });
        return r.data?.messages?.length === 25 ? r : null;
      }, 15_000);
      expect(hit.data.messages).toHaveLength(25);
      expect(Date.now() - t0).toBeLessThan(15_000);
      // old uids: at most one envelope FETCH for the whole run, and only the highest old uid may be re-read because
      // `UID FETCH n:*` always includes the last message (RFC 3501 semantics)
      let refetched = 0;
      for (let uid = 1; uid <= BIG; uid++) if (bigStat(uid).envelope > 0) refetched++;
      expect(refetched, "unchanged messages must not be refetched").toBeLessThanOrEqual(1);
      expect(s.fake.fetchTotal(ALICE, "Big", "envelope", [added.first, added.last])).toBeGreaterThanOrEqual(25);
      expect(s.fake.fetchTotal(ALICE, "Big", "envelope", [added.first, added.last])).toBeLessThanOrEqual(30);
    });
  });

  describe("reconciliation: flags and expunges (UIDNEXT alone is not enough)", () => {
    // NOTE: these tests run with SYNC_RECONCILE_SECS=2 (see createV1Stack). That only works if Node forwards the variable
    // to the sidecar child; with the default 30 s the same behavior is still inside the 60 s gate.
    it("an external flag change is picked up without refetching envelopes", async () => {
      await search("Big", { subject: "base-00001" });
      s.fake.resetFetchStats();
      s.fake.externalSetFlags(ALICE, "Big", 10, ["\\Flagged"]);
      s.fake.externalSetFlags(ALICE, "Big", 11, ["\\Seen"]);
      const flagged = await poll(async () => {
        const r = await search("Big", { flagged: true });
        return r.data?.messages?.some((m: any) => m.ref.uid === 10) ? r : null;
      }, 20_000);
      expect(flagged.data.messages).toHaveLength(1);
      const unseen = await search("Big", { unseen: true, subject: "base-0001", limit: 50 });
      expect(unseen.data.messages.find((m: any) => m.ref.uid === 11)).toBeUndefined();
      expect(bigStat(10).envelope).toBe(0);
      expect(bigStat(11).envelope).toBe(0);
    });

    it("clearing a flag externally is also reconciled", async () => {
      await poll(async () => (await search("Big", { flagged: true })).data?.messages?.length === 1, 20_000); // precondition: the flag was seen
      s.fake.externalSetFlags(ALICE, "Big", 10, [], ["\\Flagged"]);
      await poll(async () => (await search("Big", { flagged: true })).data?.messages?.length === 0, 20_000);
    });

    it("an external expunge disappears from search and a held reference becomes NOT_FOUND", async () => {
      const victims = [20, 21, 22]; // base-00019 .. base-00021
      const found = await search("Big", { subject: "base-00020" });
      expect(subjects(found)).toEqual(["base-00020"]);
      const ref = found.data.messages[0].ref;
      expect(ref.uid).toBe(21);
      s.fake.externalExpunge(ALICE, "Big", victims);
      await poll(async () => (await search("Big", { subject: "base-00020" })).data?.messages?.length === 0, 20_000);
      const gone = await c.mcp.call("read_message", { ref });
      expect(gone.isError).toBe(true);
      expect(gone.data.code).toBe("NOT_FOUND");
      // neighbours survive
      expect(subjects(await search("Big", { subject: "base-00023" }))).toEqual(["base-00023"]);
    });
  });

  describe("UIDVALIDITY change invalidates the folder cache before reuse", () => {
    it("old references are STALE_REFERENCE and recycled UIDs never alias new mail", async () => {
      const warm = await search("Rebirth", { subject: "old-life-4" });
      const oldRef = warm.data.messages[0].ref; // uid 5
      expect(oldRef.uid).toBe(5);
      const oldValidity = s.fake.folder(ALICE, "Rebirth").uidValidity;

      s.fake.recreateFolder(ALICE, "Rebirth");
      s.fake.addGenerated(ALICE, "Rebirth", 12, { subject: (i) => `new-life-${i}` }); // uid 5 is now "new-life-4"
      const newValidity = s.fake.folder(ALICE, "Rebirth").uidValidity;
      expect(newValidity).not.toBe(oldValidity);

      // immediately: the stale reference must never resolve to the new message that now owns uid 5
      const stale = await c.mcp.call("read_message", { ref: oldRef });
      expect(stale.isError).toBe(true);
      expect(stale.data.code).toBe("STALE_REFERENCE");
      expect(stale.text).not.toContain("new-life");

      // the cache converges: only new rows, all carrying the new UIDVALIDITY
      const fresh = await poll(async () => {
        const r = await search("Rebirth", { limit: 50 });
        return r.data?.messages?.length === 12 ? r : null;
      }, 20_000);
      expect(subjects(fresh).every((x) => x.startsWith("new-life-"))).toBe(true);
      expect(fresh.data.messages.every((m: any) => m.ref.uidValidity === newValidity)).toBe(true);
      expect((await search("Rebirth", { subject: "old-life" })).data.messages).toHaveLength(0);
      const again = await c.mcp.call("read_message", { ref: oldRef });
      expect(again.data.code).toBe("STALE_REFERENCE");
      const ok2 = await c.mcp.call("read_message", { ref: fresh.data.messages.find((m: any) => m.ref.uid === 5).ref });
      expect(ok2.data.subject).toBe("new-life-4");
    });
  });

  describe("forced sidecar kill and restart", () => {
    it("is supervised, rebuilds the cache from IMAP and serves correct data, including changes made while it was down", async () => {
      const before = await search("Big", { subject: "base-0009", limit: 50 });
      const beforeSubjects = subjects(before).sort();
      expect(beforeSubjects.length).toBeGreaterThan(0);
      const [oldPid] = sidecarPids(s.srv.proc.pid!);
      expect(oldPid).toBeGreaterThan(0);

      process.kill(oldPid, "SIGKILL");
      // changes the dead sidecar cannot have seen
      s.fake.externalExpunge(ALICE, "Big", [91, 92]); // base-00090, base-00091
      s.fake.externalDeliver(ALICE, "Big", 3, (i) => `while-down-${i}`);
      s.fake.resetFetchStats();

      const after = await poll(async () => {
        const r = await search("Big", { subject: "base-0009", limit: 50 });
        return r.isError ? null : r;
      }, 40_000, 300);
      const expected = beforeSubjects.filter((x) => x !== "base-00090" && x !== "base-00091").sort();
      expect(subjects(after).sort()).toEqual(expected);
      expect(subjects(await search("Big", { subject: "while-down-" })).length).toBe(3);

      const [newPid] = sidecarPids(s.srv.proc.pid!);
      expect(newPid).toBeGreaterThan(0);
      expect(newPid).not.toBe(oldPid);
      // the rebuild re-fetched headers from IMAP (nothing survived in a file on disk), exactly once each
      const rebuilt = s.fake.fetchTotal(ALICE, "Big", "envelope");
      expect(rebuilt).toBeGreaterThanOrEqual(BIG + 25 - 3 - 2);
      expect(rebuilt).toBeLessThanOrEqual(BIG + 25 + 5);
      // and the cache works again afterwards
      s.fake.resetFetchStats();
      await search("Big", { subject: "base-00005" });
      expect(s.fake.fetchTotal(ALICE, "Big", "envelope")).toBe(0);
      // other folders are rebuilt on demand too
      expect((await search("Rebirth", { limit: 50 })).data.messages).toHaveLength(12);
    });

    it("repeated kills do not wedge the bridge", async () => {
      for (let i = 0; i < 2; i++) {
        const pids = sidecarPids(s.srv.proc.pid!);
        for (const p of pids) process.kill(p, "SIGKILL");
        await sleep(200);
        const r = await poll(async () => {
          const x = await search("Big", { subject: "base-01499" });
          return x.isError ? null : x;
        }, 40_000, 300);
        expect(r.isError).toBe(false);
      }
    });
  });
});
