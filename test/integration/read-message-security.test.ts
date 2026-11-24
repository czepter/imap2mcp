/**
 * read_message include: ["security"] end to end, on both read backends (direct imapflow path and the Go sidecar), against
 * the in-process IMAP fixture: shape, no \Seen, BODY.PEEK[HEADER] on the wire, the header cap, hostile headers, per-folder
 * policy, and identical output from both backends.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { makeSelfSignedCert } from "../helpers/certs.js";
import { createStack, msg, refOf, type Stack } from "../helpers/stack.js";
import { ALICE, allowAll, createV1Stack, haveSidecar, newClient, setRules, type Client, type Rule } from "../helpers/v1.js";

const haveOpenssl = !!makeSelfSignedCert();

const RICH = [
  "Received: from mx1.example.net by mx.recv.example; Fri, 02 Jan 2026 03:04:06 +0000",
  "Received: from relay.example.net by mx1.example.net; Fri, 02 Jan 2026 03:04:05 +0000",
  "Received: from sender.example.org by relay.example.net; Fri, 02 Jan 2026 03:04:04 +0000",
  "Authentication-Results: mx.recv.example;",
  "\tspf=pass smtp.mailfrom=billing@bank.example;",
  "\tdkim=pass header.d=bank.example header.s=s1;",
  "\tdmarc=fail (p=REJECT sp=REJECT dis=NONE) header.from=bank.example",
  "Authentication-Results: forged.example; spf=fail; dmarc=pass",
  "Return-Path: <bounce@evil.example>",
  'Reply-To: "Bank Support" <help@evil.example>, other@evil.example',
  "From: Bank <billing@bank.example>",
  "To: owner@example.test",
  "Subject: Your account",
  "Date: Fri, 02 Jan 2026 03:04:05 +0000",
  "Message-ID: <rich@example.org>",
  "List-Unsubscribe: <mailto:u@evil.example>, <https://evil.example/u?id=1>",
  "List-Id: Offers <offers.evil.example>",
  "X-Spam-Flag: YES",
  "X-Spam-Status: Yes, score=7.4 required=5.0 tests=FOO",
  "X-Mailer: Evil Mailer 1.0",
  "Content-Type: text/plain; charset=utf-8",
  "",
  "SECRET-BODY-LINE. Please verify your account.",
  "",
].join("\r\n");

const EXPECTED_RICH = {
  auth: {
    spf: "pass", dkim: "pass", dmarc: "fail", dkimDomains: ["bank.example"],
    raw: ["mx.recv.example; spf=pass smtp.mailfrom=billing@bank.example; dkim=pass header.d=bank.example header.s=s1; dmarc=fail (p=REJECT sp=REJECT dis=NONE) header.from=bank.example"],
  },
  replyTo: [{ name: "Bank Support", address: "help@evil.example" }, { address: "other@evil.example" }],
  returnPath: "bounce@evil.example",
  sender: null,
  listUnsubscribe: "<mailto:u@evil.example>, <https://evil.example/u?id=1>",
  listId: "Offers <offers.evil.example>",
  spam: { flag: "YES", status: "Yes, score=7.4 required=5.0 tests=FOO", score: 7.4 },
  xMailer: "Evil Mailer 1.0",
  receivedCount: 3,
};

const seen: Record<string, unknown> = {};

describe.each([
  ["direct", { SIDECAR_DISABLED: "1" }, true],
  ["sidecar", {}, haveSidecar],
] as const)("read_message security (%s backend)", (name, env, available) => {
  describe.skipIf(!haveOpenssl || !available)(name, () => {
    let s: Stack;
    let box: string;
    let c: Client;
    const log = () => s.fake.commandsFor(ALICE);
    const read = (ref: unknown, include?: string[]) => c.mcp.call("read_message", include ? { ref, include } : { ref });

    beforeAll(async () => {
      s = name === "sidecar" ? await createV1Stack() : await createStack({ env });
      box = s.mailbox[ALICE];
      c = await newClient(s, box, allowAll(), `security-${name}`);
    });
    afterAll(async () => { await c?.mcp.close(); await s?.teardown(); });

    it("include ['security'] alone returns ref and the security object, nothing else", async () => {
      const m = s.fake.addMessage(ALICE, "INBOX", RICH);
      const r = await read(refOf(s, ALICE, "INBOX", m.uid), ["security"]);
      expect(r.isError).toBe(false);
      expect(Object.keys(r.data).sort()).toEqual(["ref", "security"]);
      expect(r.data.security).toEqual(EXPECTED_RICH);
      expect(r.text).not.toContain("SECRET-BODY-LINE");
      seen[name] = r.data.security;
    });

    it("the default include is unchanged and has no security key", async () => {
      const m = s.fake.addMessage(ALICE, "INBOX", RICH);
      const r = await read(refOf(s, ALICE, "INBOX", m.uid));
      expect(r.isError).toBe(false);
      expect("security" in r.data).toBe(false);
      expect(r.data.subject).toBe("Your account");
      expect(r.data.body).toContain("SECRET-BODY-LINE");
      for (const inc of [["headers"], ["body"], ["headers", "body"]]) {
        const x = await read(refOf(s, ALICE, "INBOX", m.uid), inc);
        expect("security" in x.data).toBe(false);
      }
    });

    it("headers, body and security together", async () => {
      const m = s.fake.addMessage(ALICE, "INBOX", RICH);
      const r = await read(refOf(s, ALICE, "INBOX", m.uid), ["headers", "body", "security"]);
      expect(r.data.subject).toBe("Your account");
      expect(r.data.body).toContain("SECRET-BODY-LINE");
      expect(r.data.security).toEqual(EXPECTED_RICH);
    });

    it("fetches the header block with BODY.PEEK[HEADER] and never sets \\Seen", async () => {
      const m = s.fake.addMessage(ALICE, "INBOX", RICH);
      const ref = refOf(s, ALICE, "INBOX", m.uid);
      s.fake.clearLog();
      const r = await read(ref, ["security"]);
      expect(r.isError).toBe(false);
      expect(m.flags.has("\\Seen")).toBe(false);
      const wire = log().join("\n");
      expect(wire).toMatch(/BODY\.PEEK\[HEADER\]<0\.26214[45]>/);
      expect(wire).not.toMatch(/BODY\[/);
      expect(wire).not.toMatch(/RFC822(?!\.SIZE|\.HEADER)/);
      expect(wire).not.toMatch(/\bSTORE\b/);
    });

    it("hostile header values do not fail the call and come back sanitised", async () => {
      const raw = msg("hostile", "body").replace("\r\n\r\n", `\r\nX-Mailer: Mail${String.fromCharCode(0, 7, 27)}er${String.fromCodePoint(0x202e)}\r\nList-Id: ${"L".repeat(2000)}\r\n\r\n`);
      const m = s.fake.addMessage(ALICE, "INBOX", raw);
      const r = await read(refOf(s, ALICE, "INBOX", m.uid), ["security"]);
      expect(r.isError).toBe(false);
      expect(r.data.security.xMailer).toBe("Mailer");
      expect(r.data.security.listId).toHaveLength(512);
      expect(r.data.security.auth).toEqual({ spf: null, dkim: null, dmarc: null, dkimDomains: [], raw: [] });
    });

    it("caps the header block at 256 KiB and still parses what arrived", async () => {
      const filler = Array.from({ length: 8000 }, (_, i) => `X-Filler-${i}: ${"z".repeat(40)}`).join("\r\n");
      expect(filler.length).toBeGreaterThan(300 * 1024);
      const raw = `Authentication-Results: mx.recv.example; spf=pass; dkim=pass header.d=big.example\r\nReceived: from a by b\r\n${filler}\r\nReceived: from last by never\r\nSubject: big\r\n\r\nbody\r\n`;
      const m = s.fake.addMessage(ALICE, "INBOX", raw);
      const r = await read(refOf(s, ALICE, "INBOX", m.uid), ["security"]);
      expect(r.isError).toBe(false);
      expect(r.data.security.auth).toMatchObject({ spf: "pass", dkim: "pass", dkimDomains: ["big.example"] });
      expect(r.data.security.receivedCount).toBe(1); // the Received line past the cap never arrived
    });

    it("unknown uid answers NOT_FOUND or STALE_REFERENCE like the other read paths, and a stale uidValidity is STALE_REFERENCE", async () => {
      const missing = await read(refOf(s, ALICE, "INBOX", 987654), ["security"]);
      expect(missing.isError).toBe(true);
      expect(["NOT_FOUND", "STALE_REFERENCE"]).toContain(missing.data.code);
      const other = await read(refOf(s, ALICE, "INBOX", 987654), ["body"]);
      expect(missing.data.code).toBe(other.data.code);
      const m = s.fake.addMessage(ALICE, "Sent", RICH);
      const ref = refOf(s, ALICE, "Sent", m.uid);
      s.fake.bumpUidValidity(ALICE, "Sent");
      s.fake.dropConnections();
      const stale = await read(ref, ["security"]);
      expect(stale.isError).toBe(true);
      expect(stale.data.code).toBe("STALE_REFERENCE");
    });

    it("the input schema accepts three include values and rejects four", async () => {
      const m = s.fake.addMessage(ALICE, "INBOX", RICH);
      const ref = refOf(s, ALICE, "INBOX", m.uid);
      const ok = await read(ref, ["security", "headers", "body"]);
      expect(ok.isError).toBe(false);
      const over = await read(ref, ["security", "headers", "body", "body"]).catch((e) => ({ isError: true, text: String(e) }));
      expect(over.isError).toBe(true);
      const unknown = await read(ref, ["raw"]).catch((e) => ({ isError: true, text: String(e) }));
      expect(unknown.isError).toBe(true);
    });

    describe("policy", () => {
      it("read_body without read_headers: body and no security; security alone is denied like headers", async () => {
        const m = s.fake.addMessage(ALICE, "Archive", RICH);
        const ref = refOf(s, ALICE, "Archive", m.uid);
        const rules: Rule[] = [["Archive", "search", "allow"], ["Archive", "read_body", "allow"]];
        const bodyOnly = await newClient(s, box, rules, `body-only-${name}`);
        try {
          s.fake.clearLog();
          const both = await bodyOnly.mcp.call("read_message", { ref, include: ["security", "body"] });
          expect(both.isError).toBe(false);
          expect(both.data.body).toContain("SECRET-BODY-LINE");
          expect("security" in both.data).toBe(false);
          expect(log().join("\n")).not.toMatch(/BODY\.PEEK\[HEADER\]<0\.26214[45]>/); // the capped fetch (cap, or cap + 1 to detect truncation) is the security one
          const viaSecurity = await bodyOnly.mcp.call("read_message", { ref, include: ["security"] });
          const viaHeaders = await bodyOnly.mcp.call("read_message", { ref, include: ["headers"] });
          expect(viaSecurity.isError).toBe(true);
          expect(viaSecurity.data.code).toBe(viaHeaders.data.code);
          expect(viaSecurity.data.message).toBe(viaHeaders.data.message);
        } finally {
          await bodyOnly.mcp.close();
        }
      });

      it("read_headers only: security works and the body is withheld", async () => {
        const m = s.fake.addMessage(ALICE, "Archive", RICH);
        const ref = refOf(s, ALICE, "Archive", m.uid);
        const headersOnly = await newClient(s, box, [["Archive", "search", "allow"], ["Archive", "read_headers", "allow"]], `headers-only-${name}`);
        try {
          const r = await headersOnly.mcp.call("read_message", { ref, include: ["security"] });
          expect(r.isError).toBe(false);
          expect(r.data.security.auth.spf).toBe("pass");
          expect(Object.keys(r.data).sort()).toEqual(["ref", "security"]);
          const withBody = await headersOnly.mcp.call("read_message", { ref, include: ["security", "body"] });
          expect(withBody.data.security.auth.spf).toBe("pass");
          expect(withBody.data.body).toBeUndefined();
          expect(withBody.data.bodyDenied).toBe(true);
        } finally {
          await headersOnly.mcp.close();
        }
      });

      it("revoking read_headers takes effect on the next call", async () => {
        const m = s.fake.addMessage(ALICE, "Archive", RICH);
        const ref = refOf(s, ALICE, "Archive", m.uid);
        const r1 = await read(ref, ["security"]);
        expect(r1.isError).toBe(false);
        setRules(s, c.clientId, box, allowAll().filter(([, op]) => op !== "read_headers"));
        const r2 = await read(ref, ["security"]);
        expect(r2.isError).toBe(true);
        setRules(s, c.clientId, box, allowAll());
      });
    });
  });
});

describe.skipIf(!haveOpenssl || !haveSidecar)("read_message security: both backends agree", () => {
  it("returns the same object from the direct backend and the Go sidecar", () => {
    expect(seen.direct).toBeDefined();
    expect(seen.sidecar).toBeDefined();
    expect(seen.sidecar).toEqual(seen.direct);
  });
});
