/**
 * Container deployment smoke test (docs/DESIGN_V2.md "Workstreams: L Ops", VERSION_PLAN v2 criterion 5).
 * Builds the real image and drives it from outside like an operator would. Skips (printed reason) if docker is unavailable.
 */
import { execFileSync, spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { chmodSync, cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import Database from "better-sqlite3";
import { drizzle } from "drizzle-orm/better-sqlite3";
import { migrate } from "drizzle-orm/better-sqlite3/migrator";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { FakeImapServer } from "../helpers/fakeImap.js";
import { Browser } from "../helpers/http.js";
import { bootstrapTokenFrom, freePort } from "../helpers/server.js";
import { addMailbox, Mcp, obtainToken, type Stack } from "../helpers/stack.js";
import { encrypt, initCrypto } from "../../server/core/imap/crypto.js";

const REPO = resolve(import.meta.dirname, "../..");
const IMAGE = process.env.SMOKE_IMAGE || "imap2mcp:smoke";
const HOST = "host.docker.internal";

function docker(args: string[], opts: { allowFail?: boolean } = {}): { code: number; out: string } {
  const r = spawnSync("docker", args, { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  const out = (r.stdout ?? "") + (r.stderr ?? "");
  if (r.status !== 0 && !opts.allowFail) throw new Error(`docker ${args.join(" ")} failed (${r.status}):\n${out}`);
  return { code: r.status ?? -1, out };
}

function dockerAvailable(): string | null {
  const v = spawnSync("docker", ["info"], { encoding: "utf8" });
  if (v.error || v.status !== 0) return "docker is not installed or its daemon is not reachable";
  if (spawnSync("openssl", ["version"]).status !== 0) return "openssl is not installed (needed for the fixture certificate)";
  return null;
}
const skipReason = dockerAvailable();
if (skipReason) console.warn(`SKIP: container smoke test not run: ${skipReason}`);

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

interface Ctr { name: string; port: number; base: string; dataDir: string }
const started: string[] = [];
const tmpDirs: string[] = [];

function mkTmp(prefix: string): string {
  const d = mkdtempSync(join(tmpdir(), prefix));
  tmpDirs.push(d);
  return d;
}

function newDataDir(): string {
  const d = mkTmp("i2m-smoke-data-");
  chmodSync(d, 0o777); // the container runs as uid 1000
  return d;
}

interface RunOpts {
  dataDir: string;
  keyFile?: string | null;
  port?: number;
  env?: Record<string, string>;
  caFile: string;
}

async function run(name: string, o: RunOpts): Promise<Ctr> {
  const port = o.port ?? (await freePort());
  const base = `http://127.0.0.1:${port}`;
  const env: Record<string, string> = {
    BASE_URL: base,
    SESSION_SECRET: SESSION_SECRET,
    ALLOW_PRIVATE_HOSTS: HOST,
    NODE_EXTRA_CA_CERTS: "/certs/ca.pem",
    SIDECAR_EXTRA_CA_FILE: "/certs/ca.pem",
    ...(o.keyFile ? { ENCRYPTION_KEY_FILE: "/run/secrets/imap2mcp_key" } : {}),
    ...o.env,
  };
  const args = ["run", "-d", "--name", name, "-p", `127.0.0.1:${port}:3000`, "--add-host", `${HOST}:host-gateway`,
    // Run as the host uid so bind-mounted files (db, backups) are mutually readable on any runner (CI uid is not 1000).
    "--user", `${process.getuid?.() ?? 1000}:${process.getgid?.() ?? 1000}`,
    "-v", `${o.dataDir}:/app/data`, "-v", `${o.caFile}:/certs/ca.pem:ro`];
  if (o.keyFile) args.push("-v", `${o.keyFile}:/run/secrets/imap2mcp_key:ro`);
  for (const [k, v] of Object.entries(env)) args.push("-e", `${k}=${v}`);
  args.push(IMAGE);
  docker(["rm", "-f", name], { allowFail: true });
  docker(args);
  started.push(name);
  return { name, port, base, dataDir: o.dataDir };
}

const logs = (c: Ctr) => docker(["logs", c.name]).out;
const state = (c: Ctr) => JSON.parse(docker(["inspect", c.name]).out)[0].State as { Running: boolean; ExitCode: number; Health?: { Status: string } };

async function waitHealthz(c: Ctr, ms = 60_000): Promise<void> {
  const end = Date.now() + ms;
  for (;;) {
    try {
      const r = await fetch(`${c.base}/healthz`);
      if (r.status === 200) return;
    } catch { /* not up */ }
    if (!state(c).Running) throw new Error(`container ${c.name} exited early (${state(c).ExitCode}):\n${logs(c)}`);
    if (Date.now() > end) throw new Error(`container ${c.name} not healthy in time:\n${logs(c)}`);
    await sleep(300);
  }
}

async function waitReady(c: Ctr, ms = 30_000): Promise<{ status: number; body: any }> {
  const end = Date.now() + ms;
  for (;;) {
    const r = await fetch(`${c.base}/readyz`);
    const body: any = await r.json();
    if (r.status === 200 || Date.now() > end) return { status: r.status, body };
    await sleep(300);
  }
}

function stopGraceful(c: Ctr): { exitCode: number; ms: number } {
  const t = Date.now();
  docker(["stop", "-t", "20", c.name]);
  return { exitCode: state(c).ExitCode, ms: Date.now() - t };
}

async function waitExit(c: Ctr, ms = 30_000): Promise<number> {
  const end = Date.now() + ms;
  while (state(c).Running) {
    if (Date.now() > end) throw new Error(`container ${c.name} did not exit:\n${logs(c)}`);
    await sleep(200);
  }
  return state(c).ExitCode;
}

function sha(p: string): string { return createHash("sha256").update(readFileSync(p)).digest("hex"); }

const SESSION_SECRET = randomBytes(32).toString("hex");

describe.skipIf(!!skipReason)("container smoke", () => {
  let fake: FakeImapServer;
  let caFile: string;
  let keyFile: string;
  let keyHex: string;
  let dataDir: string;
  let c: Ctr;
  let adminPassword: string;
  let accessToken = "";
  let mailboxId = "";
  const user = "smoke@example.test";
  const imapPw = "ImapPw-" + randomBytes(9).toString("hex");

  beforeAll(async () => {
    if (!process.env.SMOKE_IMAGE) {
      const r = spawnSync("docker", ["build", "-t", IMAGE, REPO], { encoding: "utf8", maxBuffer: 256 * 1024 * 1024 });
      if (r.status !== 0) throw new Error(`docker build failed:\n${(r.stdout ?? "") + (r.stderr ?? "")}`.slice(-4000));
    }
    const dir = mkTmp("i2m-smoke-");
    chmodSync(dir, 0o755);
    const keyPem = join(dir, "key.pem");
    caFile = join(dir, "ca.pem");
    execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", keyPem, "-out", caFile, "-days", "2", "-subj", "/CN=fixture",
      "-addext", `subjectAltName=DNS:${HOST},DNS:localhost,IP:127.0.0.1`], { stdio: "ignore" });
    chmodSync(caFile, 0o644);
    keyHex = randomBytes(32).toString("hex");
    keyFile = join(dir, "master.key");
    writeFileSync(keyFile, keyHex + "\n", { mode: 0o644 });
    fake = new FakeImapServer({ key: readFileSync(keyPem, "utf8"), cert: readFileSync(caFile, "utf8") });
    fake.addAccount(user, imapPw);
    fake.addMessage(user, "INBOX", `From: A <a@example.org>\r\nTo: s@example.test\r\nSubject: Smoke hello\r\nMessage-ID: <smoke1@example.org>\r\nDate: Fri, 02 Jan 2026 03:04:05 +0000\r\n\r\nbody\r\n`);
    await fake.start();
    dataDir = newDataDir();
    adminPassword = "Admin-" + randomBytes(9).toString("hex");
  });

  afterAll(async () => {
    for (const n of started) docker(["rm", "-f", n], { allowFail: true });
    await fake?.stop().catch(() => {});
    for (const d of tmpDirs) {
      try { rmSync(d, { recursive: true, force: true }); } catch { /* files owned by the container user */
        docker(["run", "--rm", "-v", `${d}:/d`, "--entrypoint", "sh", IMAGE, "-c", "rm -rf /d/* /d/.[!.]* 2>/dev/null; true"], { allowFail: true });
        try { rmSync(d, { recursive: true, force: true }); } catch { /* leave it */ }
      }
    }
  });

  it("docker compose file is valid", () => {
    const r = docker(["compose", "-f", join(REPO, "docker-compose.yml"), "config", "-q"], { allowFail: true });
    // compose may be absent as a plugin; only fail if it ran and rejected the file
    if (/is not a docker command|unknown shorthand|not found/.test(r.out)) return;
    const withEnv = spawnSync("docker", ["compose", "-f", join(REPO, "docker-compose.yml"), "config", "-q"],
      { encoding: "utf8", env: { ...process.env, BASE_URL: "https://mcp.example.com", SESSION_SECRET } });
    expect(withEnv.status, withEnv.stderr).toBe(0);
  });

  it("starts non-root; /healthz and /readyz are public, no-store and leak nothing", async () => {
    c = await run("i2m-smoke-main", { dataDir, keyFile, caFile });
    await waitHealthz(c);
    // The container is started with --user <host uid> for bind-mount access; the image's own default must be non-root.
    expect(docker(["image", "inspect", "--format", "{{.Config.User}}", IMAGE]).out.trim()).toBe("node");
    expect(docker(["exec", c.name, "id", "-u"]).out.trim()).not.toBe("0");

    const h = await fetch(`${c.base}/healthz`);
    expect(h.status).toBe(200);
    expect(await h.json()).toEqual({ status: "ok" });
    expect(h.headers.get("cache-control")).toBe("no-store");
    expect(h.headers.get("set-cookie")).toBeNull();

    const r = await waitReady(c);
    expect(r.status).toBe(200);
    expect(r.body).toEqual({ status: "ok", checks: { db: "ok", key: "ok", sidecar: "ok", migrations: "ok" } });
    const raw = JSON.stringify(r.body);
    for (const secret of [keyHex, SESSION_SECRET, "/app", "bridge.db", HOST]) expect(raw).not.toContain(secret);

    // the image's own HEALTHCHECK command succeeds inside the container
    const hc = JSON.parse(docker(["inspect", "--format", "{{json .Config.Healthcheck}}", c.name]).out) as { Test: string[] };
    expect(hc.Test.join(" ")).toContain("/healthz");
    docker(["exec", c.name, ...hc.Test.slice(1)]);
  });

  it("serves the SPA shell and its built assets, with the security headers", async () => {
    const root = await fetch(`${c.base}/`);
    expect(root.status).toBe(200);
    expect(root.headers.get("content-type")).toMatch(/text\/html/);
    expect(root.headers.get("content-security-policy")).toMatch(/default-src 'none'/);
    expect(root.headers.get("x-frame-options")).toBe("DENY");
    const html = await root.text();
    const assets = [...html.matchAll(/(?:src|href)="(\/_nuxt\/[^"]+)"/g)].map((m) => m[1]);
    expect(assets.length, "the SPA index references no /_nuxt assets: was the image built from `nuxt build`?").toBeGreaterThan(0);
    for (const a of assets) expect((await fetch(`${c.base}${a}`)).status, a).toBe(200);
    // deep links fall back to the SPA index; unknown API paths are JSON 404s
    expect((await fetch(`${c.base}/dashboard`)).headers.get("content-type")).toMatch(/text\/html/);
    const api = await fetch(`${c.base}/api/nope`);
    expect(api.status).toBe(404);
    expect(api.headers.get("content-type")).toMatch(/json/);
    expect((await (await fetch(`${c.base}/api/session`)).json()).setupRequired).toBe(true);
  });

  it("health endpoints are rate limited", async () => {
    // Separate throwaway container so the main one keeps a clean budget.
    const t = await run("i2m-smoke-rl", { dataDir: newDataDir(), keyFile, caFile });
    await waitHealthz(t);
    let limited = 0;
    for (let i = 0; i < 160; i++) {
      const r = await fetch(`${t.base}/healthz`);
      if (r.status === 429) limited++;
    }
    expect(limited).toBeGreaterThan(0);
    docker(["rm", "-f", t.name]);
  });

  it("bootstrap /setup, mailbox, OAuth and an MCP tool call work", async () => {
    const token = bootstrapTokenFrom(logs(c));
    expect(token, "bootstrap token missing from container log").toBeTruthy();
    const admin = new Browser(c.base);
    const setup = await admin.postWithCsrf("/api/setup", { token: token!, password: adminPassword, password2: adminPassword });
    expect(setup.status).toBe(204);
    expect((await admin.session()).setupRequired).toBe(false);
    expect((await admin.postWithCsrf("/api/setup", { token: token!, password: adminPassword, password2: adminPassword })).status).toBe(404);

    const shim = { admin, base: c.base } as unknown as Stack;
    mailboxId = await addMailbox(shim, { label: "Smoke", host: HOST, port: fake.port, user, pass: imapPw });
    const { tokens } = await obtainToken(shim, [[mailboxId, "read"]]);
    accessToken = tokens.access_token;

    const mcp = await new Mcp(c.base, accessToken).connect();
    const folders = await mcp.call("list_folders", { mailbox: mailboxId });
    expect(folders.isError, folders.text).toBe(false);
    expect(folders.text).toContain("INBOX");
    const found = await mcp.call("search_messages", { mailbox: mailboxId, folder: "INBOX", subject: "Smoke" });
    expect(found.isError, found.text).toBe(false);
    expect(found.text).toContain("Smoke hello");
    await mcp.close();

    const ready = await waitReady(c);
    expect(ready.status, JSON.stringify(ready.body)).toBe(200); // key check now decrypts a real mailbox secret

    // logs: structured, no secrets
    const log = logs(c);
    for (const secret of [keyHex, SESSION_SECRET, imapPw, accessToken, adminPassword]) expect(log).not.toContain(secret);
  });

  it("graceful stop exits 0 quickly; restart keeps admin, mailbox and token valid", async () => {
    const s = stopGraceful(c);
    expect(s.exitCode).toBe(0);
    expect(s.ms).toBeLessThan(20_000);
    docker(["rm", "-f", c.name]);
    c = await run("i2m-smoke-main", { dataDir, keyFile, caFile });
    await waitHealthz(c);
    expect((await waitReady(c)).status).toBe(200);
    expect((await (await fetch(`${c.base}/api/session`)).json()).setupRequired).toBe(false); // admin persisted; no new bootstrap
    expect(bootstrapTokenFrom(logs(c))).toBeNull();

    const admin = new Browser(c.base);
    const login = await admin.postWithCsrf("/api/login", { password: adminPassword });
    expect(login.status).toBe(204);
    // the token is bound to BASE_URL; the port is new, so a fresh token is needed. Persistence is shown by the mailbox.
    const { tokens } = await obtainToken({ admin, base: c.base } as unknown as Stack, [[mailboxId, "read"]]);
    const mcp = await new Mcp(c.base, tokens.access_token).connect();
    const folders = await mcp.call("list_folders", { mailbox: mailboxId });
    expect(folders.isError, folders.text).toBe(false);
    await mcp.close();
    // no migrations were pending: no backup is taken
    expect(existsSync(join(dataDir, "backups")) ? readdirSync(join(dataDir, "backups")) : []).toEqual([]);
  });

  it("wrong key: process serves /healthz, /readyz is 503 (key fail), tools fail, nothing leaks; re-entering the password under the new key recovers", async () => {
    stopGraceful(c);
    docker(["rm", "-f", c.name]);
    const wrong = join(mkTmp("i2m-smoke-wrongkey-"), "wrong.key");
    const wrongHex = randomBytes(32).toString("hex");
    writeFileSync(wrong, wrongHex + "\n", { mode: 0o644 });
    const w = await run("i2m-smoke-wrong", { dataDir, keyFile: wrong, caFile });
    await waitHealthz(w);
    const r = await fetch(`${w.base}/readyz`);
    expect(r.status).toBe(503);
    const body: any = await r.json();
    expect(body.status).toBe("fail");
    expect(body.checks.key).toBe("fail");
    expect(body.checks.db).toBe("ok");
    const admin = new Browser(w.base);
    expect((await admin.postWithCsrf("/api/login", { password: adminPassword })).status).toBe(204);
    const { tokens } = await obtainToken({ admin, base: w.base } as unknown as Stack, [[mailboxId, "read"]]);
    const mcp = await new Mcp(w.base, tokens.access_token).connect();
    const folders = await mcp.call("list_folders", { mailbox: mailboxId });
    expect(folders.isError).toBe(true);
    await mcp.close();
    // docs/RECOVERY.md "lost key": re-entering the mailbox password in the UI re-encrypts it under the configured key
    const edit = await admin.patchWithCsrf(`/api/mailboxes/${mailboxId}`,
      { label: "Smoke", host: HOST, port: fake.port, username: user, password: imapPw });
    expect(edit.status).toBe(200);
    expect((await waitReady(w)).status).toBe(200);
    const log = logs(w);
    for (const s of [wrongHex, keyHex, imapPw]) expect(log).not.toContain(s);
    stopGraceful(w);
    // restore the original DB-key pairing for the following tests: the stored secret is now under the "wrong" key
    keyFile = wrong;
    keyHex = wrongHex;
    docker(["rm", "-f", w.name]);

    c = await run("i2m-smoke-main", { dataDir, keyFile, caFile });
    await waitHealthz(c);
    expect((await waitReady(c)).status).toBe(200);
  });

  it("missing or malformed key refuses to start with a clear message", async () => {
    const missing = await run("i2m-smoke-nokey", { dataDir: newDataDir(), keyFile: null, caFile });
    expect(await waitExit(missing)).not.toBe(0);
    const out = logs(missing);
    expect(out).toContain("FATAL");
    expect(out).toMatch(/ENCRYPTION_KEY/);
    expect(out).not.toContain(SESSION_SECRET);

    const bad = join(mkTmp("i2m-smoke-badkey-"), "bad.key");
    writeFileSync(bad, "not-a-key\n", { mode: 0o644 });
    const b = await run("i2m-smoke-badkey", { dataDir: newDataDir(), keyFile: bad, caFile });
    expect(await waitExit(b)).not.toBe(0);
    expect(logs(b)).toContain("FATAL");
    expect(logs(b)).not.toContain("not-a-key");
  });

  describe("upgrade path", () => {
    /** Build a database as an older release would have left it: only the first `n` migrations applied. */
    function oldDb(file: string, n: number): void {
      const tmp = mkTmp("i2m-smoke-mig-");
      cpSync(join(REPO, "drizzle"), tmp, { recursive: true });
      const jp = join(tmp, "meta", "_journal.json");
      const j = JSON.parse(readFileSync(jp, "utf8"));
      j.entries = j.entries.slice(0, n);
      writeFileSync(jp, JSON.stringify(j));
      const raw = new Database(file);
      raw.pragma("journal_mode = WAL");
      migrate(drizzle(raw), { migrationsFolder: tmp });
      raw.close();
    }

    function seedMarker(file: string, id: string): void {
      initCrypto({ ENCRYPTION_KEY_FILE: keyFile } as NodeJS.ProcessEnv);
      const raw = new Database(file);
      raw.prepare("INSERT INTO mailboxes (id, label, imap_host, imap_port, imap_username, imap_password_enc) VALUES (?,?,?,?,?,?)")
        .run(id, "Marker", HOST, fake.port, user, encrypt(imapPw, `mailboxes:${id}:imap_password_enc`));
      raw.close();
    }

    it("pending migrations: backup (0600) is taken first, data survives, readyz ok", async () => {
      const dir = newDataDir();
      const dbFile = join(dir, "bridge.db");
      oldDb(dbFile, 2);
      seedMarker(dbFile, "marker-upgrade");
      const u = await run("i2m-smoke-upgrade", { dataDir: dir, keyFile, caFile });
      await waitHealthz(u);
      expect((await waitReady(u)).body).toEqual({ status: "ok", checks: { db: "ok", key: "ok", sidecar: "ok", migrations: "ok" } });

      const backups = readdirSync(join(dir, "backups"));
      expect(backups).toHaveLength(1);
      expect(backups[0]).toMatch(/^bridge-\d{4}-\d\d-\d\dT[\d-]+\.\d+Z-pre-2\.db$/);
      const bpath = join(dir, "backups", backups[0]);
      expect(statSync(bpath).mode & 0o777).toBe(0o600);

      const bk = new Database(bpath, { readonly: true });
      expect(bk.prepare("SELECT 1 FROM sqlite_master WHERE name='audit_events'").get()).toBeUndefined(); // pre-migration state
      expect((bk.prepare("SELECT COUNT(*) n FROM mailboxes").get() as { n: number }).n).toBe(1);
      bk.close();

      stopGraceful(u);
      const live = new Database(dbFile, { readonly: true });
      expect(live.prepare("SELECT 1 FROM sqlite_master WHERE name='audit_events'").get()).toBeTruthy();
      expect((live.prepare("SELECT id, status FROM mailboxes").get() as { id: string; status: string })).toEqual({ id: "marker-upgrade", status: "unknown" });
      live.close();

      // second start: nothing pending, no further backup
      const u2 = await run("i2m-smoke-upgrade", { dataDir: dir, keyFile, caFile });
      await waitHealthz(u2);
      stopGraceful(u2);
      expect(readdirSync(join(dir, "backups"))).toHaveLength(1);
    });

    it("failed migration aborts startup and leaves the original database untouched", async () => {
      const dir = newDataDir();
      const dbFile = join(dir, "bridge.db");
      oldDb(dbFile, 2);
      seedMarker(dbFile, "marker-fail");
      // sabotage: a table the next migration wants to create
      const raw = new Database(dbFile);
      raw.exec("CREATE TABLE audit_events (conflict TEXT)");
      raw.pragma("wal_checkpoint(TRUNCATE)");
      raw.close();
      const before = sha(dbFile);
      const f = await run("i2m-smoke-failmig", { dataDir: dir, keyFile, caFile });
      expect(await waitExit(f)).not.toBe(0);
      const out = logs(f);
      expect(out).toMatch(/migration failed/i);
      expect(out).not.toContain(keyHex);
      const chk = new Database(dbFile, { readonly: true });
      expect((chk.prepare("SELECT COUNT(*) n FROM mailboxes").get() as { n: number }).n).toBe(1);
      expect((chk.prepare("SELECT COUNT(*) n FROM pragma_table_info('mailboxes') WHERE name='status'").get() as { n: number }).n).toBe(0);
      chk.close();
      expect(sha(dbFile)).toBe(before);
      expect(readdirSync(join(dir, "backups"))).toHaveLength(1); // the safety copy was made before the attempt
    });
  });
});
