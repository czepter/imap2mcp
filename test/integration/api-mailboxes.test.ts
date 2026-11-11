/**
 * Black-box acceptance tests for the mailbox admin API (docs/NUXT_MIGRATION.md): create, read, update, test, retry,
 * Drafts folder, delete with label confirmation. Secrets never leave the server; credentials are encrypted at rest.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { makeSelfSignedCert } from "../helpers/certs.js";
import { errorOf, json } from "../helpers/http.js";
import { createStack, registerClient, setGrants, testMailbox, type Stack } from "../helpers/stack.js";
import type { Mailbox, MailboxDetail, MailboxTestResult, Overview } from "../../shared/types/api.js";

const haveOpenssl = !!makeSelfSignedCert();
const ALICE = "alice@example.test";
const BOB = "bob@example.test";
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;

describe.skipIf(!haveOpenssl)("mailbox admin API", () => {
  let s: Stack;
  const bodies: string[] = []; // every response text, scanned for secrets at the end
  const input = (o: Record<string, unknown> = {}) => ({ label: "Work", host: "localhost", port: s.fake.port, username: ALICE, password: s.imapPasswords[ALICE], ...o });
  async function call(method: string, path: string, body?: unknown): Promise<Response> {
    const r = await s.admin.withCsrf(method, path, body ?? {});
    bodies.push(await r.clone().text());
    return r;
  }
  const detail = async (id: string): Promise<MailboxDetail> => {
    const r = await s.admin.get(`/api/mailboxes/${id}`);
    bodies.push(await r.clone().text());
    expect(r.status).toBe(200);
    return json<MailboxDetail>(r);
  };
  const setDbStatus = (id: string, status: string, code: string | null = null) =>
    s.srv.db().prepare("UPDATE mailboxes SET status = ?, last_error_code = ? WHERE id = ?").run(status, code, id);

  beforeAll(async () => { s = await createStack({ accounts: [ALICE, BOB], skipMailboxes: true }); });
  afterAll(async () => { await s?.teardown(); });

  let id = "";

  it("POST /api/mailboxes creates a mailbox: 201, Mailbox DTO, no secret, listed in the overview as status unknown", async () => {
    const r = await call("POST", "/api/mailboxes", input({ label: "  Work  ", host: " localhost ", username: ` ${ALICE} ` }));
    expect(r.status).toBe(201);
    const m = await json<Mailbox>(r);
    id = m.id;
    expect(m).toEqual({ id: expect.stringMatching(/\S{8,}/), label: "Work", host: "localhost", port: s.fake.port, username: ALICE, draftsFolder: null, createdAt: expect.any(String) });
    expect(m.createdAt, "shared/types/api.ts: timestamps are ISO-8601 UTC").toMatch(ISO);
    const ov = await json<Overview>(await s.admin.get("/api/overview"));
    const row = ov.mailboxes.find((x) => x.id === id)!;
    expect(row).toMatchObject({ label: "Work", status: "unknown", clientCount: 0, draftsFolder: null });
    // stored encrypted, bound to the row
    const enc = (s.srv.db().prepare("SELECT imap_password_enc e FROM mailboxes WHERE id = ?").get(id) as any).e as string;
    expect(enc).toMatch(/^v1:[0-9a-f]{8}:/);
    expect(enc).not.toContain(s.imapPasswords[ALICE]);
  });

  it("creation validates its input with the old messages and creates nothing on failure", async () => {
    const before = (s.srv.db().prepare("SELECT COUNT(*) n FROM mailboxes").get() as any).n;
    const cases: Array<[Record<string, unknown>, string]> = [
      [{ label: "" }, "Label is required (max 100 characters)"],
      [{ label: "   " }, "Label is required (max 100 characters)"],
      [{ host: "" }, "A valid host name is required"],
      [{ host: "bad host" }, "A valid host name is required"],
      [{ host: "a/b" }, "A valid host name is required"],
      [{ host: "user@host" }, "A valid host name is required"],
      [{ port: 0 }, "Port must be 1-65535"],
      [{ port: 65536 }, "Port must be 1-65535"],
      [{ port: -1 }, "Port must be 1-65535"],
      [{ port: "abc" }, "Port must be 1-65535"],
      [{ username: "" }, "Username is required"],
      [{ password: "" }, "Password is required"],
    ];
    for (const [patch, message] of cases) {
      const r = await call("POST", "/api/mailboxes", input(patch));
      expect(r.status, JSON.stringify(patch).slice(0, 60)).toBe(400);
      expect((await errorOf(r)).message, JSON.stringify(patch).slice(0, 60)).toBe(message);
    }
    for (const body of [{}, [], "text"]) expect((await call("POST", "/api/mailboxes", body)).status).toBe(400);
    expect((s.srv.db().prepare("SELECT COUNT(*) n FROM mailboxes").get() as any).n).toBe(before);
  });

  it("GET /api/mailboxes/:id returns MailboxDetail; unknown ids are a JSON 404", async () => {
    const d = await detail(id);
    expect(Object.keys(d).sort()).toEqual(["mailbox", "reach", "status"]);
    expect(d.mailbox.id).toBe(id);
    expect(d.status).toEqual({ status: "unknown", lastErrorCode: null, lastOkAt: null, nextRetryAt: null });
    expect(d.reach).toEqual([]);
    const missing = await s.admin.get("/api/mailboxes/does-not-exist");
    expect(missing.status).toBe(404);
    expect((await errorOf(missing)).code).toBeTruthy();
  });

  it("POST /:id/test connects with TLS validation and lists folders; failures are ok:false with a sanitised message", async () => {
    const r = await call("POST", `/api/mailboxes/${id}/test`);
    expect(r.status).toBe(200);
    const t = await json<MailboxTestResult>(r);
    expect(t.ok).toBe(true);
    expect(t.message).toMatch(/^Connected\./);
    expect(t.folders).toEqual(expect.arrayContaining(["INBOX", "Drafts"]));

    const wrongPw = await s.admin.postWithCsrf("/api/mailboxes", input({ label: "wrong pw", password: "not-the-password" }));
    const wrongId = (await json<Mailbox>(wrongPw)).id;
    const t2 = await testMailbox(s, wrongId);
    expect(t2.ok).toBe(false);
    expect(t2.message).toMatch(/Authentication failed/);
    expect(t2.folders).toEqual([]);

    const closed = await s.admin.postWithCsrf("/api/mailboxes", input({ label: "closed port", port: 1 }));
    const t3 = await testMailbox(s, (await json<Mailbox>(closed)).id);
    expect(t3.ok).toBe(false);
    expect(t3.message).toMatch(/refused|failed/i);
    expect(JSON.stringify([t2, t3])).not.toContain(s.imapPasswords[ALICE]);

    const none = await s.admin.postWithCsrf("/api/mailboxes/does-not-exist/test");
    expect(none.status).toBe(404);
  });

  it("PUT /:id/drafts stores an existing server folder and rejects missing, empty and control-character folders", async () => {
    const ok = await call("PUT", `/api/mailboxes/${id}/drafts`, { folder: "Drafts" });
    expect(ok.status).toBe(204);
    expect((await detail(id)).mailbox.draftsFolder).toBe("Drafts");

    const bad = await call("PUT", `/api/mailboxes/${id}/drafts`, { folder: "No/Such/Folder" });
    expect(bad.status).toBe(400);
    expect((await errorOf(bad)).message).toBe("That folder does not exist on the server");
    for (const folder of ["", "   ", "Dra\u0000fts"]) {
      const r = await call("PUT", `/api/mailboxes/${id}/drafts`, { folder });
      expect(r.status, JSON.stringify(folder)).toBe(400);
    }
    expect((await call("PUT", `/api/mailboxes/${id}/drafts`, {})).status).toBe(400);
    expect((await detail(id)).mailbox.draftsFolder).toBe("Drafts"); // failures change nothing
    expect((await call("PUT", "/api/mailboxes/does-not-exist/drafts", { folder: "Drafts" })).status).toBe(404);
  });

  it("PATCH keeps the saved password when none is sent, and keeps the Drafts folder unless host/port/username change", async () => {
    const r = await call("PATCH", `/api/mailboxes/${id}`, { label: "Work renamed", host: "localhost", port: s.fake.port, username: ALICE });
    expect(r.status).toBe(200);
    expect(await json<Mailbox>(r)).toMatchObject({ id, label: "Work renamed", draftsFolder: "Drafts", username: ALICE });
    expect((await testMailbox(s, id)).ok, "stored password must survive an edit without a password").toBe(true);
    const empty = await call("PATCH", `/api/mailboxes/${id}`, { label: "Work renamed", host: "localhost", port: s.fake.port, username: ALICE, password: "" });
    expect(empty.status).toBe(200);
    expect((await testMailbox(s, id)).ok, "an empty password keeps the saved one").toBe(true);

    // the account is the same one (the fake accepts only its own credentials): switch to another user and back
    const other = await call("PATCH", `/api/mailboxes/${id}`, { label: "Work renamed", host: "localhost", port: s.fake.port, username: BOB });
    expect(other.status).toBe(200);
    expect((await json<Mailbox>(other)).draftsFolder, "target changed: Drafts folder must be re-selected").toBeNull();
    const back = await call("PATCH", `/api/mailboxes/${id}`, { label: "Work", host: "localhost", port: s.fake.port, username: ALICE, password: s.imapPasswords[ALICE] });
    expect(back.status).toBe(200);
    expect((await call("PUT", `/api/mailboxes/${id}/drafts`, { folder: "Drafts" })).status).toBe(204);
  });

  it("PATCH validates like create (password optional) and 404s on unknown ids", async () => {
    for (const [patch, message] of [[{ label: "" }, "Label is required (max 100 characters)"], [{ host: "bad host" }, "A valid host name is required"], [{ port: 0 }, "Port must be 1-65535"], [{ username: "" }, "Username is required"]] as Array<[Record<string, unknown>, string]>) {
      const { password: _omit, ...base } = input();
      const r = await call("PATCH", `/api/mailboxes/${id}`, { ...base, ...patch });
      expect(r.status, message).toBe(400);
      expect((await errorOf(r)).message).toBe(message);
    }
    const { password: _p, ...base } = input();
    expect((await call("PATCH", "/api/mailboxes/does-not-exist", base)).status).toBe(404);
    expect((await detail(id)).mailbox.label).toBe("Work");
  });

  it("a new password resets the status latches; an edit without one does not", async () => {
    setDbStatus(id, "auth_failed", "AUTH_FAILED");
    const d0 = await detail(id);
    expect(d0.status).toMatchObject({ status: "auth_failed", lastErrorCode: "AUTH_FAILED" });
    const { password: _p, ...base } = input();
    expect((await call("PATCH", `/api/mailboxes/${id}`, { ...base, label: "Work" })).status).toBe(200);
    expect((await detail(id)).status.status, "label-only edit must not clear the latch").toBe("auth_failed");
    expect((await call("PATCH", `/api/mailboxes/${id}`, input({ label: "Work" }))).status).toBe(200);
    expect((await detail(id)).status).toMatchObject({ status: "unknown", lastErrorCode: null, nextRetryAt: null });
  });

  it("POST /:id/retry answers 204, resets the status to unknown and 404s on unknown ids", async () => {
    setDbStatus(id, "degraded", "UPSTREAM_ERROR");
    expect((await detail(id)).status.status).toBe("degraded");
    const r = await call("POST", `/api/mailboxes/${id}/retry`);
    expect(r.status).toBe(204);
    expect(await r.text()).toBe("");
    expect((await detail(id)).status).toMatchObject({ status: "unknown", lastErrorCode: null });
    expect((await call("POST", "/api/mailboxes/does-not-exist/retry")).status).toBe(404);
  });

  it("the overview reflects status and the number of distinct clients holding grants", async () => {
    const c1 = await registerClient(s.base, undefined, "c1");
    const c2 = await registerClient(s.base, undefined, "c2");
    await setGrants(s, c1, [[id, "read"], [id, "draft"]]);
    await setGrants(s, c2, [[id, "read"]]);
    setDbStatus(id, "ok");
    const ov = await json<Overview>(await s.admin.get("/api/overview"));
    expect(ov.mailboxes.find((m) => m.id === id)).toMatchObject({ status: "ok", clientCount: 2 });
    const d = await detail(id);
    expect(d.reach.map((x) => x.clientName).sort()).toEqual(["c1", "c2"]);
    expect(d.reach.find((x) => x.clientName === "c1")!.capabilities.sort()).toEqual(["draft", "read"]);
    expect(d.reach.find((x) => x.clientName === "c2")!.capabilities).toEqual(["read"]);
  });

  it("DELETE needs confirmLabel to equal the label exactly; then 204, gone, and its grants are gone too", async () => {
    const label = (await detail(id)).mailbox.label;
    for (const body of [{}, { confirmLabel: "" }, { confirmLabel: "wrong" }, { confirmLabel: label.toUpperCase() }, { confirmLabel: 5 }]) {
      const r = await call("DELETE", `/api/mailboxes/${id}`, body);
      expect(r.status, JSON.stringify(body)).toBe(400);
    }
    expect((await s.admin.get(`/api/mailboxes/${id}`)).status).toBe(200);
    expect((s.srv.db().prepare("SELECT COUNT(*) n FROM policy_rules WHERE mailbox_id = ?").get(id) as any).n).toBeGreaterThan(0);

    const r = await call("DELETE", `/api/mailboxes/${id}`, { confirmLabel: label });
    expect(r.status).toBe(204);
    expect((await s.admin.get(`/api/mailboxes/${id}`)).status).toBe(404);
    expect((s.srv.db().prepare("SELECT COUNT(*) n FROM policy_rules WHERE mailbox_id = ?").get(id) as any).n).toBe(0);
    expect((await json<Overview>(await s.admin.get("/api/overview"))).mailboxes.some((m) => m.id === id)).toBe(false);
    expect((await call("DELETE", `/api/mailboxes/${id}`, { confirmLabel: label })).status).toBe(404);
    // remote mail is never touched
    expect(s.fake.commands.some((c) => /\b(DELETE|EXPUNGE|STORE)\b/i.test(c.line))).toBe(false);
  });

  it("no response of this suite ever contained an IMAP password, the master key or ciphertext", () => {
    expect(bodies.length).toBeGreaterThan(20);
    const all = bodies.join("\n");
    for (const secret of [...Object.values(s.imapPasswords), "not-the-password", s.work.keyHex, s.work.sessionSecret]) expect(all.includes(secret), secret.slice(0, 6)).toBe(false);
    expect(all).not.toMatch(/v1:[0-9a-f]{8}:/);
    expect(s.srv.output()).not.toContain(s.imapPasswords[ALICE]);
  });
});
