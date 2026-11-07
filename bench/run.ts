/**
 * v1 performance gate harness (docs/DESIGN_V1.md "Performance gate & harness").
 *
 *   npm run bench                      # sidecar in Docker, --cpus=2 --memory=2g (the gate configuration)
 *   npm run bench -- --no-docker       # fallback: sidecar as a plain host process (limits NOT enforced; recorded as such)
 *   npm run bench -- --messages 2000   # smaller fixture for a smoke run (results are labelled; gates are not claimed)
 *
 * What it does: starts the fake IMAP-over-TLS server (test/helpers/fakeImap.ts) with N lazily generated messages
 * (~2 KB of envelope data each) and an injected round-trip latency (default 20 ms), starts the Go sidecar, drives it
 * directly over its authenticated Unix socket, measures every gate and APPENDS a dated section (machine info +
 * numbers + PASS/FAIL per gate) to docs/BENCHMARKS.md. Nothing is tuned: a failing gate is printed and recorded as FAIL.
 *
 * Scope note (also written into the report): this measures the sidecar and the IMAP link. The Node MCP/OAuth/policy
 * layer in front of it is NOT in these numbers.
 */
import { spawn, execFileSync, type ChildProcess } from "node:child_process";
import { randomBytes } from "node:crypto";
import { appendFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, chmodSync } from "node:fs";
import net from "node:net";
import os from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { FakeImapServer } from "../test/helpers/fakeImap.js";
import { makeSelfSignedCert } from "../test/helpers/certs.js";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const arg = (n: string, d?: string) => {
  const i = process.argv.indexOf(`--${n}`);
  return i >= 0 ? (process.argv[i + 1]?.startsWith("--") || process.argv[i + 1] === undefined ? "1" : process.argv[i + 1]) : d;
};
const N = Number(arg("messages", "10000"));
const RTT = Number(arg("rtt", "20"));
const USE_DOCKER = arg("no-docker") === undefined;
const FULL_FIXTURE = N >= 10000 && RTT <= 20 && USE_DOCKER;
const BIN = resolve(arg("bin", join(ROOT, "sidecar/bin/sidecar"))!);
const IMAGE = arg("image", "alpine:latest")!;
const USER = "bench@example.test";
const MB = "bench-mailbox";
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const now = () => performance.now();
const pct = (xs: number[], p: number) => {
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.ceil((p / 100) * s.length) - 1)];
};
const fmt = (n: number, d = 0) => n.toFixed(d);

// ------------------------------------------------------------------ minimal JSON-RPC client over the UDS
class Rpc {
  private sock!: net.Socket;
  private id = 0;
  private pending = new Map<number, { res: (v: any) => void; rej: (e: Error) => void }>();
  constructor(private path: string, private secret: string) {}
  async connect() {
    this.sock = net.connect(this.path);
    await new Promise<void>((res, rej) => { this.sock.once("connect", () => res()); this.sock.once("error", rej); });
    let buf = "";
    this.sock.on("data", (d) => {
      buf += d;
      for (let i = buf.indexOf("\n"); i >= 0; i = buf.indexOf("\n")) {
        const line = buf.slice(0, i);
        buf = buf.slice(i + 1);
        const m = JSON.parse(line);
        const p = this.pending.get(m.id);
        if (!p) continue;
        this.pending.delete(m.id);
        m.error ? p.rej(Object.assign(new Error(m.error.message), { code: m.error.code })) : p.res(m.result);
      }
    });
    this.sock.on("close", () => { for (const p of this.pending.values()) p.rej(new Error("socket closed")); this.pending.clear(); });
  }
  /** Called when a request gets no answer for 120 s (a hung sidecar/fixture must fail the run, not hang it). */
  onTimeout: (method: string) => string = () => "";
  call<T = any>(method: string, params: Record<string, unknown> = {}): Promise<T> {
    const id = ++this.id;
    return new Promise<T>((res, rej) => {
      const t = setTimeout(() => { this.pending.delete(id); rej(new Error(`rpc ${method} timed out after 120 s. ${this.onTimeout(method)}`)); }, 120_000);
      this.pending.set(id, { res: (v) => { clearTimeout(t); res(v); }, rej: (e) => { clearTimeout(t); rej(e); } });
      this.sock.write(JSON.stringify({ jsonrpc: "2.0", id, method, params: { auth: this.secret, ...params } }) + "\n");
    });
  }
  close() { this.sock?.destroy(); }
}

async function timed<T>(fn: () => Promise<T>): Promise<[T, number]> {
  const t = now();
  const r = await fn();
  return [r, now() - t];
}
/** `calls` invocations with at most `conc` in flight; returns per-call latency in ms and wall time. */
async function load(calls: number, conc: number, fn: (i: number) => Promise<unknown>): Promise<{ lat: number[]; wallMs: number }> {
  const lat: number[] = [];
  let next = 0;
  const t0 = now();
  await Promise.all(Array.from({ length: conc }, async () => {
    for (;;) {
      const i = next++;
      if (i >= calls) return;
      const t = now();
      await fn(i);
      lat.push(now() - t);
    }
  }));
  return { lat, wallMs: now() - t0 };
}

// ------------------------------------------------------------------ memory sampling
let peakContainerMiB = 0;
let sampler: NodeJS.Timeout | null = null;
function startSampler(container: string | null, pid: number | null) {
  const tick = () => {
    try {
      if (container) {
        const out = execFileSync("docker", ["stats", "--no-stream", "--format", "{{.MemUsage}}", container], { encoding: "utf8", timeout: 5000 });
        const m = /^([\d.]+)\s*(KiB|MiB|GiB)/.exec(out.trim());
        if (m) peakContainerMiB = Math.max(peakContainerMiB, Number(m[1]) * ({ KiB: 1 / 1024, MiB: 1, GiB: 1024 } as any)[m[2]]);
      } else if (pid) {
        const m = /VmRSS:\s+(\d+) kB/.exec(readFileSync(`/proc/${pid}/status`, "utf8"));
        if (m) peakContainerMiB = Math.max(peakContainerMiB, Number(m[1]) / 1024);
      }
    } catch { /* sampling is best effort */ }
  };
  sampler = setInterval(tick, 2000);
}

// ------------------------------------------------------------------ main
interface Gate { id: string; name: string; limit: string; measured: string; pass: boolean | null; note?: string }
const gates: Gate[] = [];
const extra: string[] = [];
const add = (g: Gate) => { gates.push(g); console.log(`${g.pass === null ? "INFO" : g.pass ? "PASS" : "FAIL"}  ${g.name}: ${g.measured}  (gate: ${g.limit})`); };

const loadAtStart = os.loadavg().map((x) => x.toFixed(2)).join(" / ");
async function main() {
  if (!existsSync(BIN)) {
    console.error(`sidecar binary not found at ${BIN}\nbuild it:  scripts/go.sh build -o bin/sidecar ./cmd/sidecar   (npm run bench:build)`);
    process.exit(2);
  }
  const cert = makeSelfSignedCert();
  if (!cert) { console.error("openssl is required to create the fixture certificate"); process.exit(2); }

  const fake = new FakeImapServer({ key: cert.key, cert: cert.cert });
  fake.addAccount(USER, "bench-pw");
  const tGen = now();
  fake.addGenerated(USER, "INBOX", N, { subject: (i) => `msg-${String(i).padStart(6, "0")} quarterly planning notes`, headerBytes: 2048 });
  fake.addFolder(USER, "Bodies");
  fake.addGenerated(USER, "Bodies", 200, { subject: (i) => `bodymsg-${i}`, bodyBytes: 50_000 });
  await fake.start();
  fake.latencyMs = RTT;
  console.log(`fixture: ${N} messages in INBOX (${fmt(now() - tGen)} ms to describe), RTT ${RTT} ms, fake IMAP on :${fake.port}`);

  const dataDir = mkdtempSync(join(os.tmpdir(), "imap2mcp-bench-"));
  chmodSync(dataDir, 0o700);
  const sockPath = join(dataDir, "sidecar.sock");
  const secret = randomBytes(32).toString("hex");
  const container = `imap2mcp-bench-${process.pid}`;
  let child: ChildProcess;
  let dockerInfo = "n/a";
  if (USE_DOCKER) {
    const uid = os.userInfo().uid, gid = os.userInfo().gid;
    dockerInfo = execFileSync("docker", ["version", "--format", "client {{.Client.Version}} / server {{.Server.Version}}"], { encoding: "utf8" }).trim();
    child = spawn("docker", [
      "run", "-i", "--rm", "--init", "--name", container, "--cpus=2", "--memory=2g", "--memory-swap=2g", "--network", "host", "-u", `${uid}:${gid}`,
      "-v", `${dataDir}:/data`, "-v", `${BIN}:/sidecar:ro`, "-v", `${cert.dir}:/ca:ro`,
      "-e", "SIDECAR_SOCKET=/data/sidecar.sock", "-e", `SIDECAR_EXTRA_CA_FILE=/ca/${basename(cert.certPath)}`, "-e", "SYNC_RECONCILE_SECS=30",
      IMAGE, "/sidecar",
    ], { stdio: ["pipe", "pipe", "pipe"] });
  } else {
    child = spawn(BIN, [], {
      stdio: ["pipe", "pipe", "pipe"],
      env: { PATH: process.env.PATH, SIDECAR_SOCKET: sockPath, SIDECAR_EXTRA_CA_FILE: cert.certPath, SYNC_RECONCILE_SECS: "30" },
    });
  }
  let childLog = "";
  child.stdout!.on("data", (d) => (childLog += d));
  child.stderr!.on("data", (d) => (childLog += d));
  child.stdin!.write(secret + "\n");
  const cleanup = async () => {
    if (sampler) clearInterval(sampler);
    try { child.stdin?.end(); } catch { /* */ }
    if (USE_DOCKER) { try { execFileSync("docker", ["rm", "-f", container], { stdio: "ignore" }); } catch { /* */ } } else child.kill("SIGKILL");
    await fake.stop().catch(() => {});
    rmSync(dataDir, { recursive: true, force: true });
    rmSync(cert.dir, { recursive: true, force: true });
  };
  process.on("SIGINT", () => void cleanup().then(() => process.exit(130)));

  try {
    // wait for the socket
    const rpc = new Rpc(sockPath, secret);
    for (let i = 0; ; i++) {
      if (child.exitCode !== null) throw new Error(`sidecar exited early:\n${childLog}`);
      if (existsSync(sockPath)) { try { await rpc.connect(); await rpc.call("ping"); break; } catch { /* retry */ } }
      if (i > 150) throw new Error(`sidecar did not come up:\n${childLog}`);
      await sleep(100);
    }
    rpc.onTimeout = () => `last IMAP commands seen by the fixture: ${JSON.stringify(fake.commands.slice(-12).map((c) => `${c.selected ?? "-"}|${c.line}`))}\nsidecar log: ${childLog.slice(-1500)}`;
    startSampler(USE_DOCKER ? container : null, USE_DOCKER ? null : child.pid ?? null);
    await rpc.call("open", { mailboxId: MB, host: "localhost", ip: "127.0.0.1", port: fake.port, servername: "localhost", user: USER, pass: "bench-pw" });

    // ---------------------------------------------------------------- 1. cold sync
    fake.resetFetchStats();
    const [cold, coldMs] = await timed(() => rpc.call("sync", { mailboxId: MB, folder: "INBOX", mode: "full" }));
    const coldFetched = fake.fetchTotal(USER, "INBOX", "envelope");
    add({ id: "G1", name: "Cold UID/header sync", limit: "<= 30 s", measured: `${fmt(coldMs)} ms wall (sidecar reports ${cold.durationMs} ms), ${cold.count} messages, ${cold.fetched} fetched, ${coldFetched} envelope FETCHes at the server`, pass: coldMs <= 30_000 && cold.count === N });

    // average cached header size, measured from a real list response
    const sample = await rpc.call("list", { mailboxId: MB, folder: "INBOX", limit: 100 });
    const avgHdr = JSON.stringify(sample.items).length / sample.items.length;
    extra.push(`Average header as returned by \`list\` (JSON): ${fmt(avgHdr)} bytes (target fixture: about 2 KB).`);

    // ---------------------------------------------------------------- 2. warm list/search
    const warmList = await load(100, 5, () => rpc.call("list", { mailboxId: MB, folder: "INBOX", limit: 100 }));
    const warmSearchSubj = await load(100, 5, (i) => rpc.call("search", { mailboxId: MB, folder: "INBOX", criteria: { subject: `msg-00${String(i % 90).padStart(2, "0")}` }, limit: 100 }));
    const warmSearchFrom = await load(100, 5, (i) => rpc.call("search", { mailboxId: MB, folder: "INBOX", criteria: { from: `sender${i % 97}@`, seen: false }, limit: 100 }));
    for (const [nm, r] of [["list (100 newest)", warmList], ["search subject", warmSearchSubj], ["search from + unseen", warmSearchFrom]] as const) {
      const p95 = pct(r.lat, 95);
      add({ id: "G2", name: `Warm ${nm}, 100 calls, concurrency 5, <=100 results`, limit: "p95 <= 300 ms", measured: `p50 ${fmt(pct(r.lat, 50), 1)} / p95 ${fmt(p95, 1)} / p99 ${fmt(pct(r.lat, 99), 1)} / max ${fmt(Math.max(...r.lat), 1)} ms (${fmt(r.wallMs)} ms wall)`, pass: p95 <= 300 });
    }
    const memPing = await rpc.call("ping");
    const rssMiBPing = memPing.rssBytes / 1048576;

    // ---------------------------------------------------------------- 3. incremental: 100 new messages
    fake.resetFetchStats();
    const added = fake.externalDeliver(USER, "INBOX", 100, (i) => `fresh-${String(i).padStart(3, "0")} arrival`);
    const tInc = now();
    const sres = await rpc.call("sync", { mailboxId: MB, folder: "INBOX", mode: "auto" });
    let found = 0;
    for (;;) {
      const r = await rpc.call("search", { mailboxId: MB, folder: "INBOX", criteria: { subject: "fresh-" }, limit: 500 });
      found = r.items.length;
      if (found >= 100 || now() - tInc > 20_000) break;
      await sleep(100);
    }
    const incMs = now() - tInc;
    let oldRefetched = 0, maxOld = 0;
    for (let uid = 1; uid < added.first; uid++) { const e = fake.fetchStat(USER, "INBOX", uid).envelope; if (e) oldRefetched++; maxOld = Math.max(maxOld, e); }
    const newFetched = fake.fetchTotal(USER, "INBOX", "envelope", [added.first, added.last]);
    add({ id: "G3", name: "100 new messages searchable after sync start", limit: "<= 5 s", measured: `${fmt(incMs)} ms (found ${found}/100; sync reported fetched=${sres.fetched})`, pass: incMs <= 5000 && found >= 100 });
    add({ id: "G3b", name: "Unchanged messages not refetched during incremental sync", limit: "0 refetched (1 tolerated: `UID FETCH n:*` always returns the highest UID, RFC 3501)", measured: `${oldRefetched} of ${added.first - 1} old UIDs got an envelope FETCH (max ${maxOld}); new UIDs fetched ${newFetched}x`, pass: oldRefetched <= 1 && newFetched <= 105 });

    // ---------------------------------------------------------------- 4. flag + expunge reconciliation (default 30 s interval)
    const flagStep = Math.max(1, Math.floor((N * 0.35) / 500));
    const flagUids = Array.from({ length: 500 }, (_, i) => 100 + i * flagStep).filter((u) => u <= N * 0.6); // 500 messages flagged by another client
    const expUids = Array.from({ length: 200 }, (_, i) => Math.floor(N * 0.6) + 1 + i * 3).filter((u) => u <= N);
    const watch = async (done: () => Promise<boolean>) => {
      const t = now();
      while (now() - t < 90_000) {
        if (await done()) return now() - t;
        await sleep(250);
      }
      return -1;
    };
    // (a) flag changes alone: UIDNEXT and MESSAGES do not move, so only the periodic reconcile can notice
    for (const u of flagUids) fake.externalSetFlags(USER, "INBOX", u, ["\\Flagged"]);
    const sawFlags = await watch(async () => (await rpc.call("search", { mailboxId: MB, folder: "INBOX", criteria: { flagged: true }, limit: 500 })).items.length >= flagUids.length);
    add({ id: "G4a", name: `Flag reconciliation: ${flagUids.length} flag changes by another client, no other change (SYNC_RECONCILE_SECS=30)`, limit: "<= 60 s", measured: sawFlags < 0 ? "NOT OBSERVED within 90 s" : `visible after ${fmt(sawFlags)} ms`, pass: sawFlags >= 0 && sawFlags <= 60_000 });
    // (b) expunges alone
    fake.externalExpunge(USER, "INBOX", expUids);
    const expectCount = N + 100 - expUids.length;
    const sawExpunge = await watch(async () => {
      const st = (await rpc.call("stats")).mailboxes?.find((m: any) => m.mailboxId === MB);
      return st?.folders?.find((f: any) => f.folder === "INBOX")?.count === expectCount;
    });
    const gone = (await rpc.call("search", { mailboxId: MB, folder: "INBOX", criteria: { subject: "msg-" }, limit: 500 })).items.filter((m: any) => expUids.includes(m.uid)).length;
    add({ id: "G4b", name: `Expunge reconciliation: ${expUids.length} messages expunged by another client, no other change`, limit: "<= 60 s", measured: sawExpunge < 0 ? "NOT OBSERVED within 90 s" : `count correct after ${fmt(sawExpunge)} ms; expunged UIDs still returned by search: ${gone}`, pass: sawExpunge >= 0 && sawExpunge <= 60_000 && gone === 0 });
    // cost of a forced full reconcile on the same folder
    for (let i = 0; i < 100 && 1 + i * 11 <= N * 0.05; i++) fake.externalSetFlags(USER, "INBOX", 1 + i * 11, ["\\Answered"]);
    const [rec2, rec2Ms] = await timed(() => rpc.call("sync", { mailboxId: MB, folder: "INBOX", mode: "full" }));
    add({ id: "G4c", name: "Explicit full reconcile (`sync mode=full`, UID SEARCH ALL + FLAGS) on 10k folder", limit: "informational", measured: `${fmt(rec2Ms)} ms (flagChanges=${rec2.flagChanges ?? "?"}, expunged=${rec2.expunged ?? "?"})`, pass: null });

    // ---------------------------------------------------------------- 5. UIDVALIDITY reset
    const oldValidity = fake.folder(USER, "INBOX").uidValidity;
    fake.recreateFolder(USER, "INBOX");
    fake.addGenerated(USER, "INBOX", N, { subject: (i) => `reborn-${String(i).padStart(6, "0")} after uidvalidity change`, headerBytes: 2048 });
    fake.resetFetchStats();
    const [rst, rstMs] = await timed(() => rpc.call("sync", { mailboxId: MB, folder: "INBOX", mode: "auto" }));
    let stale = "no error";
    try { await rpc.call("fetchHeaders", { mailboxId: MB, folder: "INBOX", uidValidity: oldValidity, uids: [1, 2, 3] }); stale = "SERVED (BUG)"; } catch (e: any) { stale = `error ${e.code}`; }
    const l1 = await rpc.call("list", { mailboxId: MB, folder: "INBOX", limit: 100 });
    const allNew = l1.items.every((m: any) => m.subject.startsWith("reborn-") && m.uidValidity === fake.folder(USER, "INBOX").uidValidity);
    const oldLeft = (await rpc.call("search", { mailboxId: MB, folder: "INBOX", criteria: { subject: "quarterly planning" }, limit: 5 })).items.length;
    add({ id: "G5", name: "UIDVALIDITY reset rebuild", limit: "<= 30 s (cold budget), no stale mappings", measured: `${fmt(rstMs)} ms, reset=${rst.reset}, count=${rst.count}, stale-uidValidity fetchHeaders -> ${stale}, new-only list=${allNew}, old rows left=${oldLeft}`, pass: rstMs <= 30_000 && rst.reset === true && rst.count === N && stale === "error -32010" && allNew && oldLeft === 0 });

    // ---------------------------------------------------------------- 6. memory
    const memAfter = await rpc.call("ping");
    const rssMiB = Math.max(rssMiBPing, memAfter.rssBytes / 1048576);
    add({ id: "G6", name: "Sidecar RSS (ping.rssBytes, max of after-warm and after-reset with 2 x 10k headers built)", limit: "< 256 MB", measured: `${fmt(rssMiB, 1)} MiB (after warm queries ${fmt(rssMiBPing, 1)}, final ${fmt(memAfter.rssBytes / 1048576, 1)})`, pass: rssMiB < 256 });
    await sleep(2500);
    add({ id: "G6b", name: USE_DOCKER ? "Container memory peak (docker stats, 2 s sampling)" : "Process RSS peak (host, 2 s sampling)", limit: "informational (< 2 GiB cgroup limit)", measured: `${fmt(peakContainerMiB, 1)} MiB`, pass: null });

    // ---------------------------------------------------------------- 7. body transfer + remote body search, separately, not gated
    const bodyOne = await load(50, 1, (i) => rpc.call("fetchBody", { mailboxId: MB, folder: "Bodies", uidValidity: fake.folder(USER, "Bodies").uidValidity, uid: 1 + (i % 200), maxBytes: 200 * 1024 }));
    const bodyPar = await load(100, 5, (i) => rpc.call("fetchBody", { mailboxId: MB, folder: "Bodies", uidValidity: fake.folder(USER, "Bodies").uidValidity, uid: 1 + (i % 200), maxBytes: 200 * 1024 }));
    add({ id: "B1", name: "Body transfer fetchBody (~50 KB bodies), sequential x50", limit: "measured separately, no gate", measured: `p50 ${fmt(pct(bodyOne.lat, 50), 1)} / p95 ${fmt(pct(bodyOne.lat, 95), 1)} ms`, pass: null });
    add({ id: "B2", name: "Body transfer fetchBody, 100 calls concurrency 5", limit: "no gate", measured: `p50 ${fmt(pct(bodyPar.lat, 50), 1)} / p95 ${fmt(pct(bodyPar.lat, 95), 1)} ms`, pass: null });
    const txt = await load(5, 1, (i) => rpc.call("searchText", { mailboxId: MB, folder: "INBOX", text: `gen-body-${N / 2 + i * 13}`, limit: 50 }));
    add({ id: "B3", name: `Remote body search searchText over ${N} messages (IMAP UID SEARCH TEXT; time is dominated by the fake server scanning), sequential x5`, limit: "no gate", measured: `p50 ${fmt(pct(txt.lat, 50), 0)} / max ${fmt(Math.max(...txt.lat), 0)} ms`, pass: null });

    rpc.close();
    await writeReport({ dockerInfo, fakePeakNote: "" });
  } finally {
    await cleanup();
  }
}

function sh(cmd: string, args: string[]): string {
  try { return execFileSync(cmd, args, { encoding: "utf8", cwd: ROOT, timeout: 10_000 }).trim(); } catch { return "n/a"; }
}

async function writeReport(o: { dockerInfo: string; fakePeakNote: string }) {
  const cpu = readFileSync("/proc/cpuinfo", "utf8").match(/model name\s*:\s*(.+)/)?.[1] ?? "unknown";
  const failed = gates.filter((g) => g.pass === false);
  const date = new Date().toISOString();
  const lines: string[] = [];
  lines.push(`\n## Run ${date}\n`);
  lines.push(`**Result: ${failed.length === 0 ? "ALL GATES PASSED" : `${failed.length} GATE(S) FAILED`}**${FULL_FIXTURE ? "" : "  (non-gate configuration: " + [N < 10000 ? `${N} messages` : "", RTT > 20 ? `RTT ${RTT} ms` : "", USE_DOCKER ? "" : "no Docker limits"].filter(Boolean).join(", ") + "; numbers are NOT gate evidence)"}\n`);
  lines.push("| Item | Value |", "|---|---|");
  lines.push(`| Host CPU | ${cpu}, ${os.cpus().length} logical CPUs |`, `| Host load average (1/5/15 min) | at start ${loadAtStart}; at end ${os.loadavg().map((x) => x.toFixed(2)).join(" / ")} (${os.cpus().length} CPUs; high load invalidates timings) |`, `| Host RAM | ${fmt(os.totalmem() / 2 ** 30, 1)} GiB |`, `| Kernel / OS | ${os.type()} ${os.release()} |`);
  lines.push(`| Node | ${process.version} |`, `| Docker | ${USE_DOCKER ? o.dockerInfo : "NOT USED"} |`, `| Sidecar runtime | ${USE_DOCKER ? `\`docker run -i --rm --init --cpus=2 --memory=2g --memory-swap=2g --network host\` image \`${IMAGE}\` (${sh("docker", ["image", "inspect", IMAGE, "--format", "{{.Id}}"]).slice(0, 19)})` : "host process, **no CPU/memory limit enforced**"} |`);
  lines.push(`| Sidecar binary | \`${BIN.replace(ROOT + "/", "")}\`, ${sh("git", ["rev-parse", "--short", "HEAD"])}${sh("git", ["status", "--porcelain", "sidecar"]) ? "+uncommitted" : ""}; \`${sh("sha256sum", [BIN]).slice(0, 12)}\` |`);
  lines.push(`| Fixture | ${N} messages in INBOX, ~2 KB envelope each, 200 x ~50 KB-body messages in a second folder; fake IMAP-over-TLS server (Node, **on the host, not CPU-limited**, shares the machine with the driver); injected ${RTT} ms delay on every response batch |`);
  lines.push(`| Not measured | The Node MCP/OAuth/policy layer and HTTP in front of the sidecar; real providers (Gmail/Dovecot/...); network jitter. Numbers are sidecar RPC latency over the Unix socket + IMAP link to a fake. |`);
  lines.push("", "| Gate | Result | Limit | Measured |", "|---|---|---|---|");
  for (const g of gates) lines.push(`| ${g.id} ${g.name} | ${g.pass === null ? "info" : g.pass ? "PASS" : "**FAIL**"} | ${g.limit} | ${g.measured} |`);
  lines.push("", ...extra.map((e) => `- ${e}`), "");
  const text = lines.join("\n");
  const outDir = join(ROOT, "bench/results");
  mkdirSync(outDir, { recursive: true });
  writeFileSync(join(outDir, `run-${date.replace(/[:.]/g, "-")}.json`), JSON.stringify({ date, N, RTT, USE_DOCKER, FULL_FIXTURE, gates, extra }, null, 2));
  if (arg("no-write") === undefined) {
    const doc = join(ROOT, "docs/BENCHMARKS.md");
    appendFileSync(doc, text);
    console.log(`\nappended results to docs/BENCHMARKS.md`);
  }
  console.log(`\n${failed.length === 0 ? "ALL GATES PASSED" : failed.length + " GATE(S) FAILED: " + failed.map((g) => g.id).join(", ")}`);
  process.exitCode = failed.length ? 1 : 0;
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
