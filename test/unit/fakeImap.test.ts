import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { ImapFlow } from "imapflow";
import { FakeImapServer } from "../helpers/fakeImap.js";
import { makeSelfSignedCert } from "../helpers/certs.js";

const cert = makeSelfSignedCert();
const d = cert ? describe : describe.skip;

// Validates the fixture itself, against the real client library the product uses.
d("fake IMAP fixture", () => {
  let srv: FakeImapServer;
  beforeAll(async () => {
    srv = new FakeImapServer({ key: cert!.key, cert: cert!.cert });
    srv.addAccount("u", "p");
    srv.addMessage("u", "INBOX", "From: A <a@x.org>\r\nTo: b@y.org\r\nSubject: Hello\r\nMessage-ID: <1@x>\r\n\r\nbody one\r\n");
    srv.addMessage("u", "INBOX", "From: C <c@x.org>\r\nSubject: Other\r\n\r\nbody two\r\n");
    await srv.start();
  });
  afterAll(() => srv.stop());

  const mk = () => new ImapFlow({ host: "localhost", port: srv.port, secure: true, auth: { user: "u", pass: "p" }, logger: false, tls: { ca: cert!.cert } });

  it("lists, searches, peeks without setting \\Seen, appends, moves", async () => {
    const c = mk();
    await c.connect();
    const boxes = await c.list();
    expect(boxes.map((b) => b.path)).toContain("Drafts");
    const lock = await c.getMailboxLock("INBOX");
    try {
      const hits = await c.search({ subject: "Hello" }, { uid: true });
      expect(hits).toEqual([1]);
      const m = await c.fetchOne("1", { uid: true, envelope: true, source: true, flags: true }, { uid: true });
      expect(m && m.envelope?.subject).toBe("Hello");
      expect(m && m.source?.toString()).toContain("body one");
      expect(srv.folder("u", "INBOX").messages[0].flags.has("\\Seen")).toBe(false);
      await c.messageFlagsAdd("1", ["\\Flagged"], { uid: true });
      expect(srv.folder("u", "INBOX").messages[0].flags.has("\\Flagged")).toBe(true);
      await c.messageMove("2", "Archive", { uid: true });
      expect(srv.folder("u", "Archive").messages).toHaveLength(1);
      expect(srv.folder("u", "INBOX").messages).toHaveLength(1);
    } finally {
      lock.release();
    }
    const r = await c.append("Drafts", Buffer.from("Subject: d\r\n\r\nx\r\n"), ["\\Draft"]);
    expect(r && r.uid).toBe(1);
    await c.logout();
  });

  it("rejects the connection when the cert is not trusted (TLS validation matters)", async () => {
    const c = new ImapFlow({ host: "localhost", port: srv.port, secure: true, auth: { user: "u", pass: "p" }, logger: false });
    c.on("error", () => {});
    await expect(c.connect()).rejects.toBeTruthy();
  });
});
