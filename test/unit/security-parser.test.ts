import { describe, expect, it } from "vitest";
import { parseSecurity, sanitize } from "../../server/core/mcp/security.js";

const block = (...lines: string[]) => `${lines.join("\r\n")}\r\n\r\n`;
const cp = (...n: number[]) => String.fromCodePoint(...n);
const parse = (...lines: string[]) => parseSecurity(block(...lines));

describe("parseSecurity: Authentication-Results", () => {
  it("multiple results in one header", () => {
    const r = parse("Authentication-Results: mx.recv.example; spf=pass smtp.mailfrom=a@x.example; dkim=pass header.d=x.example header.s=s1; dmarc=pass header.from=x.example");
    expect(r.auth).toMatchObject({ spf: "pass", dkim: "pass", dmarc: "pass", dkimDomains: ["x.example"] });
    expect(r.auth.raw).toHaveLength(1);
    expect(r.auth.raw[0]).toContain("dmarc=pass");
  });

  it("multiple headers with the same authserv-id are merged in order", () => {
    const r = parse(
      "Authentication-Results: mx.recv.example; spf=pass smtp.mailfrom=a@x.example; dmarc=pass header.from=x.example",
      "Authentication-Results: mx.recv.example; dkim=fail header.d=bad.example; dkim=pass header.d=x.example",
    );
    expect(r.auth.spf).toBe("pass");
    expect(r.auth.dmarc).toBe("pass");
    expect(r.auth.dkim).toBe("pass");
    expect(r.auth.dkimDomains).toEqual(["x.example"]);
    expect(r.auth.raw).toHaveLength(2);
    expect(r.auth.raw[0]).toContain("spf=pass");
    expect(r.auth.raw[1]).toContain("dkim=fail");
  });

  it("missing header: everything null or empty", () => {
    const r = parse("From: a@x.example", "Subject: hi");
    expect(r.auth).toEqual({ spf: null, dkim: null, dmarc: null, dkimDomains: [], raw: [] });
  });

  it("folded lines parse like the unfolded form and raw is unfolded", () => {
    const folded = parse(
      "Authentication-Results: mx.recv.example;",
      "\tspf=pass smtp.mailfrom=a@x.example;",
      " dkim=pass header.d=",
      "  x.example header.s=s1;",
      "\tdmarc=pass header.from=x.example",
    );
    const flat = parse("Authentication-Results: mx.recv.example; spf=pass smtp.mailfrom=a@x.example; dkim=pass header.d= x.example header.s=s1; dmarc=pass header.from=x.example");
    expect(folded.auth.spf).toBe("pass");
    expect(folded.auth.dmarc).toBe("pass");
    expect(folded.auth.dkim).toBe("pass");
    expect(folded.auth.raw[0]).not.toMatch(/[\r\n\t]/);
    expect(folded.auth.raw[0]).toBe(flat.auth.raw[0]);
  });

  it("dmarc=fail (p=REJECT ...): comment stripped, raw keeps it", () => {
    const r = parse("Authentication-Results: mx.recv.example; dmarc=fail (p=REJECT sp=REJECT dis=NONE) header.from=bank.example");
    expect(r.auth.dmarc).toBe("fail");
    expect(r.auth.raw[0]).toContain("(p=REJECT sp=REJECT dis=NONE)");
  });

  it("untrusted lower header with another authserv-id is ignored", () => {
    const r = parse(
      "Authentication-Results: mx.recv.example; spf=fail; dkim=none",
      "Authentication-Results: forged.example; spf=pass; dkim=pass header.d=bank.example; dmarc=pass",
    );
    expect(r.auth).toMatchObject({ spf: "fail", dkim: "none", dmarc: null, dkimDomains: [] });
    expect(r.auth.raw).toHaveLength(1);
  });

  it("a header with another id breaks the run: only the contiguous top run counts", () => {
    const r = parse(
      "Authentication-Results: mx.recv.example; dmarc=pass header.from=x.example",
      "Authentication-Results: other.example; dkim=pass header.d=evil.example",
      "Authentication-Results: mx.recv.example; spf=pass",
    );
    expect(r.auth).toMatchObject({ dmarc: "pass", spf: null, dkim: null, dkimDomains: [] });
    expect(r.auth.raw).toHaveLength(1);
  });

  it("authserv-id is compared case-insensitively", () => {
    const r = parse("Authentication-Results: MX.Recv.Example; spf=pass", "Authentication-Results: mx.recv.example; dmarc=pass");
    expect(r.auth).toMatchObject({ spf: "pass", dmarc: "pass" });
    expect(r.auth.raw).toHaveLength(2);
  });

  it("at most 3 headers are used", () => {
    const lines = [1, 2, 3, 4, 5].map((i) => `Authentication-Results: mx.recv.example; dkim=pass header.d=d${i}.example`);
    lines[3] = "Authentication-Results: mx.recv.example; spf=pass";
    const r = parse(...lines);
    expect(r.auth.raw).toHaveLength(3);
    expect(r.auth.spf).toBeNull();
    expect(r.auth.dkimDomains).toEqual(["d1.example", "d2.example", "d3.example"]);
  });

  it("unknown verdicts map to null and never count as pass", () => {
    const r = parse("Authentication-Results: mx.recv.example; spf=hardfail; dkim=bestguesspass header.d=x.example; dmarc=weird");
    expect(r.auth).toMatchObject({ spf: null, dkim: null, dmarc: null, dkimDomains: [] });
  });

  it("verdicts are case-folded", () => {
    const r = parse("Authentication-Results: mx.recv.example; SPF=Pass; DKIM=PASS header.d=X.Example; DMARC=Fail");
    expect(r.auth).toMatchObject({ spf: "pass", dkim: "pass", dmarc: "fail", dkimDomains: ["x.example"] });
  });

  it("dkim: pass wins over fail; all fail gives the first verdict", () => {
    expect(parse("Authentication-Results: mx.recv.example; dkim=fail header.d=a.example; dkim=pass header.d=b.example").auth.dkim).toBe("pass");
    expect(parse("Authentication-Results: mx.recv.example; dkim=fail header.d=a.example; dkim=neutral header.d=b.example").auth.dkim).toBe("fail");
  });

  it("dkimDomains: header.d and header.i, lowercase, deduplicated, passing only", () => {
    const r = parse(
      "Authentication-Results: mx.recv.example;",
      " dkim=pass header.i=@x.example;",
      " dkim=pass header.i=user@Sub.X.Example header.d=\"x.example\";",
      " dkim=fail header.d=failed.example;",
      " dkim=pass header.d=\"bad domain.example\";",
      " dkim=pass header.d=<script>.example;",
      ` dkim=pass header.d=${"a".repeat(260)}.example`,
    );
    expect(r.auth.dkimDomains).toEqual(["x.example", "sub.x.example"]);
  });

  it("dkimDomains: at most 10", () => {
    const parts = Array.from({ length: 15 }, (_, i) => ` dkim=pass header.d=d${i}.example`);
    const r = parse(`Authentication-Results: mx.recv.example;${parts.join(";")}`);
    expect(r.auth.dkimDomains).toHaveLength(10);
  });

  it("authserv-id; none has no results but is kept in raw", () => {
    const r = parse("Authentication-Results: mx.recv.example; none");
    expect(r.auth).toMatchObject({ spf: null, dkim: null, dmarc: null, dkimDomains: [] });
    expect(r.auth.raw).toEqual(["mx.recv.example; none"]);
  });

  it("unparseable topmost header: no fall-through to a lower one", () => {
    const r = parse("Authentication-Results: ;spf=pass", "Authentication-Results: mx.recv.example; spf=pass; dmarc=pass");
    expect(r.auth).toEqual({ spf: null, dkim: null, dmarc: null, dkimDomains: [], raw: [] });
  });

  const M365 = "Authentication-Results: spf=pass (sender IP is 1.2.3.4) smtp.mailfrom=a@x.example; dkim=pass (signature was verified) header.d=x.example; dmarc=pass action=none header.from=x.example; compauth=pass reason=100";

  it("a header without authserv-id (Microsoft 365 style) keeps its first result", () => {
    const r = parse(M365, "Received-SPF: fail (x) client-ip=1.2.3.4");
    expect(r.auth).toMatchObject({ spf: "pass", dkim: "pass", dmarc: "pass", dkimDomains: ["x.example"] });
    expect(r.auth.raw).toHaveLength(1);
  });

  it("a lower header with a real authserv-id is still ignored below an id-less one", () => {
    const r = parse(
      "Authentication-Results: spf=fail smtp.mailfrom=a@x.example; dkim=none",
      "Authentication-Results: forged.example; spf=pass; dkim=pass header.d=bank.example; dmarc=pass",
    );
    expect(r.auth).toMatchObject({ spf: "fail", dkim: "none", dmarc: null, dkimDomains: [] });
    expect(r.auth.raw).toHaveLength(1);
  });

  it("a top header without authserv-id is used alone: a planted id-less header below it has no influence", () => {
    const r = parse(
      "Authentication-Results: spf=fail smtp.mailfrom=a@x.example; dkim=none; dmarc=fail",
      "Authentication-Results: spf=pass; dkim=pass header.d=bank.example; dmarc=pass",
    );
    expect(r.auth).toMatchObject({ spf: "fail", dkim: "none", dmarc: "fail", dkimDomains: [] });
    expect(r.auth.raw).toHaveLength(1);
    expect(r.auth.raw[0]).toContain("dkim=none");
  });

  it("an id-less header below a real one is not used", () => {
    const r = parse("Authentication-Results: mx.recv.example; dmarc=pass", "Authentication-Results: spf=pass");
    expect(r.auth).toMatchObject({ dmarc: "pass", spf: null });
    expect(r.auth.raw).toHaveLength(1);
  });

  it("other methods are ignored", () => {
    const r = parse("Authentication-Results: mx.recv.example; arc=pass; iprev=pass policy.iprev=1.2.3.4; auth=pass");
    expect(r.auth).toMatchObject({ spf: null, dkim: null, dmarc: null });
  });

  it("reason strings and quoted values containing semicolons do not split results", () => {
    const r = parse('Authentication-Results: mx.recv.example; spf=fail reason="a; dkim=pass header.d=evil.example" smtp.mailfrom=a@x.example; dmarc=pass');
    expect(r.auth).toMatchObject({ spf: "fail", dkim: null, dmarc: "pass", dkimDomains: [] });
  });
});

describe("parseSecurity: Received-SPF", () => {
  const RSPF = "Received-SPF: pass (google.com: domain of a@x.example designates 1.2.3.4 as permitted sender) client-ip=1.2.3.4;";

  it("only Received-SPF present", () => {
    const r = parse(RSPF);
    expect(r.auth).toEqual({ spf: "pass", dkim: null, dmarc: null, dkimDomains: [], raw: [] });
  });

  it("not used when the authentication results carry an spf result", () => {
    expect(parse("Authentication-Results: mx.recv.example; spf=fail", RSPF).auth.spf).toBe("fail");
  });

  it("not used when the spf result is present but unknown", () => {
    expect(parse("Authentication-Results: mx.recv.example; spf=garbage", RSPF).auth.spf).toBeNull();
  });

  it("fallback when Authentication-Results has dkim/dmarc but no spf", () => {
    const r = parse("Authentication-Results: mx.recv.example; dkim=pass header.d=x.example; dmarc=pass", RSPF);
    expect(r.auth).toMatchObject({ spf: "pass", dkim: "pass", dmarc: "pass", dkimDomains: ["x.example"] });
    expect(r.auth.raw).toHaveLength(1);
  });

  it("only the topmost header; unknown first word is null; verdict mapping", () => {
    expect(parse("Received-SPF: fail (x)", RSPF).auth.spf).toBe("fail");
    expect(parse("Received-SPF: mystery something", RSPF).auth.spf).toBeNull();
    for (const v of ["softfail", "neutral", "none", "temperror", "permerror", "pass", "fail"]) {
      expect(parse(`Received-SPF: ${v.toUpperCase()} (comment) client-ip=1.2.3.4`).auth.spf).toBe(v);
    }
  });

  it("fallback applies when an Authentication-Results header from a lower id exists but the top one is none", () => {
    const r = parse("Authentication-Results: mx.recv.example; none", RSPF);
    expect(r.auth.spf).toBe("pass");
  });
});

describe("parseSecurity: sanitising and caps", () => {
  it("strips control and bidi characters everywhere and keeps the text around them", () => {
    const bad = cp(0, 7, 0x1b) + "[31m" + cp(0x7f, 0x85, 0x202e, 0x200b, 0xfeff);
    const r = parse(
      `List-Unsubscribe: <mailto:u${bad}@x.example>`,
      `X-Mailer: Mail${bad}er`,
      `X-Spam-Status: No,${bad} score=1.5`,
      `Return-Path: <a${bad}@x.example>`,
      `Reply-To: "Help${bad}Desk" <h@x.example>`,
      `Authentication-Results: mx.recv.example; spf=pass (${bad}) smtp.mailfrom=a@x.example; x=${bad}`,
    );
    const json = JSON.stringify(r);
    for (const c of [0, 7, 0x1b, 0x7f, 0x85, 0x202e, 0x200b, 0xfeff]) expect(json.includes(cp(c))).toBe(false);
    expect(r.listUnsubscribe).toContain("mailto:u");
    expect(r.xMailer).toContain("Mail");
    expect(r.xMailer).toContain("er");
    expect(r.returnPath).toContain("@x.example");
    expect(r.replyTo[0].name).toContain("Help");
    expect(r.auth.raw[0]).toContain("spf=pass");
  });

  it("strips the Arabic letter mark and the Unicode tag block", () => {
    const bad = cp(0x061c, 0xe0001, 0xe0041, 0xe007f);
    expect(sanitize(`a${bad}b`)).toBe("ab");
    expect(JSON.stringify(parse(`X-Mailer: Mail${bad}er`))).not.toContain(cp(0xe0041));
  });

  it("tab becomes a space", () => {
    expect(sanitize("a" + cp(9) + "b")).toBe("a b");
    expect(parse("X-Mailer: one" + cp(9) + "two").xMailer).toBe("one two");
  });

  it("caps single values at 512 characters and raw entries at 1024", () => {
    const big = "x".repeat(5000);
    const r = parse(
      `X-Mailer: ${big}`, `List-Id: ${big}`, `List-Unsubscribe: ${big}`, `X-Spam-Status: ${big}`, `X-Spam-Flag: ${big}`,
      `Reply-To: "${big}" <a@x.example>`,
      `Authentication-Results: mx.recv.example; spf=pass x=${big}`,
    );
    for (const v of [r.xMailer, r.listId, r.listUnsubscribe, r.spam.status, r.spam.flag, r.replyTo[0].name]) expect(v?.length).toBe(512);
    expect(r.auth.raw[0].length).toBe(1024);
    expect(r.auth.spf).toBe("pass");
  });

  it("a value of exactly 512 characters is kept whole", () => {
    const v = "y".repeat(512);
    expect(parse(`X-Mailer: ${v}`).xMailer).toBe(v);
  });

  it("does not split a surrogate pair at the cap", () => {
    const pair = cp(0x1f600);
    const out = sanitize("a".repeat(511) + pair + "tail") as string;
    expect(out).toBe("a".repeat(511) + pair);
    expect(Array.from(out)).toHaveLength(512);
    expect(sanitize("a".repeat(510) + pair + pair, 511)).toBe("a".repeat(510) + pair);
  });

  it("at most 10 Reply-To addresses", () => {
    const list = Array.from({ length: 20 }, (_, i) => `u${i}@x.example`).join(", ");
    expect(parse(`Reply-To: ${list}`).replyTo).toHaveLength(10);
  });

  it("empty values become null", () => {
    const r = parse("X-Mailer:", "List-Id:    ", "X-Spam-Flag: " + cp(0x200b));
    expect(r.xMailer).toBeNull();
    expect(r.listId).toBeNull();
    expect(r.spam.flag).toBeNull();
  });
});

describe("parseSecurity: spam headers", () => {
  it("score from X-Spam-Score", () => {
    expect(parse("X-Spam-Score: -1.5").spam.score).toBe(-1.5);
    expect(parse("X-Spam-Score: 7").spam.score).toBe(7);
    expect(parse("X-Spam-Score:   3.2 ").spam.score).toBe(3.2);
  });

  it("score from X-Spam-Status when there is no score header", () => {
    const r = parse("X-Spam-Status: No, score=-2.1 required=5.0 tests=BAYES_00");
    expect(r.spam.score).toBe(-2.1);
    expect(r.spam.status).toBe("No, score=-2.1 required=5.0 tests=BAYES_00");
  });

  it("a non-numeric X-Spam-Score falls back to the status header", () => {
    expect(parse("X-Spam-Score: lots", "X-Spam-Status: Yes, score=9.9 required=5.0").spam.score).toBe(9.9);
    expect(parse("X-Spam-Score: 5.2 / 15.0", "X-Spam-Status: Yes, score=6 required=5.0").spam.score).toBe(6);
  });

  it("nothing numeric gives null", () => {
    expect(parse("X-Spam-Score: abc", "X-Spam-Status: Yes").spam.score).toBeNull();
    expect(parse("From: a@x.example").spam).toEqual({ flag: null, status: null, score: null });
  });

  it("flag and status are verbatim (sanitised)", () => {
    const r = parse("X-Spam-Flag: YES", "X-Spam-Status: Yes, hits=9");
    expect(r.spam).toMatchObject({ flag: "YES", status: "Yes, hits=9" });
  });

  it("topmost occurrence wins", () => {
    const r = parse("X-Spam-Flag: NO", "X-Spam-Flag: YES", "X-Spam-Score: 1", "X-Spam-Score: 99");
    expect(r.spam).toMatchObject({ flag: "NO", score: 1 });
  });
});

describe("parseSecurity: addresses", () => {
  it("Reply-To list with display names, bare addresses and quoted commas", () => {
    const r = parse('Reply-To: "Bank Support" <help@evil.example>, other@x.example, "Doe, John" <j@x.example>');
    expect(r.replyTo).toEqual([
      { name: "Bank Support", address: "help@evil.example" },
      { address: "other@x.example" },
      { name: "Doe, John", address: "j@x.example" },
    ]);
  });

  it("comments are not part of the address", () => {
    const r = parse("Reply-To: a@x.example (Alice (the boss)), Bob (note) <b@x.example>");
    expect(r.replyTo.map((a) => a.address)).toEqual(["a@x.example", "b@x.example"]);
    expect(r.replyTo[1].name).toBe("Bob");
  });

  it("group syntax is flattened", () => {
    const r = parse("Reply-To: Team: a@x.example, b@x.example;, c@x.example");
    expect(r.replyTo.map((a) => a.address)).toEqual(["a@x.example", "b@x.example", "c@x.example"]);
  });

  it("RFC 2047 names are decoded (B and Q)", () => {
    const b64 = Buffer.from("Bank Sparkasse ü", "utf8").toString("base64");
    const r = parse(`Reply-To: =?UTF-8?B?${b64}?= <a@x.example>, =?ISO-8859-1?Q?M=FCller_GmbH?= <m@x.example>`);
    expect(r.replyTo[0].name).toBe("Bank Sparkasse " + cp(0xfc));
    expect(r.replyTo[1].name).toBe("M" + cp(0xfc) + "ller GmbH");
  });

  it("an undecodable encoded word is kept as text", () => {
    const r = parse("Reply-To: =?NOPE-CHARSET?B?AAAA?= <a@x.example>");
    expect(r.replyTo[0].name).toBe("=?NOPE-CHARSET?B?AAAA?=");
  });

  it("entries without exactly one @ are dropped", () => {
    const r = parse("Reply-To: nobody, a@b@c, <>, ok@x.example, @x.example");
    expect(r.replyTo).toEqual([{ address: "ok@x.example" }]);
  });

  it("Sender is the first valid address; absent gives []/null", () => {
    expect(parse('Sender: "Boss" <boss@x.example>').sender).toEqual({ name: "Boss", address: "boss@x.example" });
    const none = parse("From: a@x.example");
    expect(none.sender).toBeNull();
    expect(none.replyTo).toEqual([]);
  });

  it("only the topmost Reply-To is used", () => {
    expect(parse("Reply-To: a@x.example", "Reply-To: b@x.example").replyTo).toEqual([{ address: "a@x.example" }]);
  });

  it("Return-Path", () => {
    expect(parse("Return-Path: <a@x.example>").returnPath).toBe("a@x.example");
    expect(parse("Return-Path: <>").returnPath).toBeNull();
    expect(parse("Return-Path: bare@x.example").returnPath).toBe("bare@x.example");
    expect(parse("From: a@x.example").returnPath).toBeNull();
  });
});

describe("parseSecurity: list headers, received count, block handling", () => {
  it("list headers are kept verbatim as one string", () => {
    const r = parse("List-Unsubscribe: <mailto:u@x.example>, <https://x.example/u?id=1&a=%20b>", "List-Id: Newsletter <news.x.example>", "X-Mailer: Foo Mailer 1.2");
    expect(r.listUnsubscribe).toBe("<mailto:u@x.example>, <https://x.example/u?id=1&a=%20b>");
    expect(r.listId).toBe("Newsletter <news.x.example>");
    expect(r.xMailer).toBe("Foo Mailer 1.2");
  });

  it("receivedCount counts Received headers only, folded ones once", () => {
    expect(parse("From: a@x.example").receivedCount).toBe(0);
    const r = parse("Received: from a by b;", " Mon, 1 Jan 2026 00:00:00 +0000", "Received: from c by d", "Received-SPF: pass", "X-Received: nope");
    expect(r.receivedCount).toBe(2);
  });

  it("ignores everything after the blank line", () => {
    const r = parseSecurity("From: a@x.example\r\n\r\nAuthentication-Results: mx.recv.example; spf=pass\r\nX-Mailer: evil\r\n");
    expect(r.auth.spf).toBeNull();
    expect(r.xMailer).toBeNull();
  });

  it("accepts bare LF line endings", () => {
    const r = parseSecurity("Authentication-Results: mx.recv.example;\n spf=pass\nX-Mailer: m\n\nbody");
    expect(r.auth.spf).toBe("pass");
    expect(r.xMailer).toBe("m");
  });

  it("empty input gives the all-empty object with the issue shape", () => {
    const r = parseSecurity("");
    expect(r).toEqual({
      auth: { spf: null, dkim: null, dmarc: null, dkimDomains: [], raw: [] },
      replyTo: [], returnPath: null, sender: null, listUnsubscribe: null, listId: null,
      spam: { flag: null, status: null, score: null }, xMailer: null, receivedCount: 0,
    });
    expect(Object.keys(r)).toEqual(["auth", "replyTo", "returnPath", "sender", "listUnsubscribe", "listId", "spam", "xMailer", "receivedCount"]);
    expect(Object.keys(r.auth)).toEqual(["spf", "dkim", "dmarc", "dkimDomains", "raw"]);
    expect(Object.keys(r.spam)).toEqual(["flag", "status", "score"]);
  });
});

describe("parseSecurity: hostile input", () => {
  const shapeOk = (r: ReturnType<typeof parseSecurity>) => {
    expect(Object.keys(r)).toEqual(["auth", "replyTo", "returnPath", "sender", "listUnsubscribe", "listId", "spam", "xMailer", "receivedCount"]);
  };

  it("never throws and stays fast", () => {
    const inputs = [
      "", "\n", "no colon here\r\nstill none\r\n\r\n", `X-Mailer: ${"x".repeat(256 * 1024)}`, ":".repeat(256 * 1024),
      `Authentication-Results: mx; ${"(".repeat(100000)}`, `Reply-To: ${"(".repeat(100000)}`, `Reply-To: ${'"'.repeat(100000)}`,
      `Reply-To: ${"<".repeat(100000)}`, `Reply-To: ${"a@b,".repeat(50000)}`,
      `Authentication-Results: mx; spf=pass reason="${"\\".repeat(100000)}`, `Authentication-Results: ${";".repeat(100000)}`,
      `Authentication-Results: mx;${" spf=pass".repeat(20000)}`, `Authentication-Results: mx; ${"a=".repeat(50000)}`,
      `Reply-To: =?UTF-8?B?${"A".repeat(100000)}`, `Received: x\r\n${" a\r\n".repeat(60000)}`,
      "From: a@x.example\r\nAuthentication-Results: mx.recv.example; spf=pa", Array.from({ length: 5000 }, (_, i) => String.fromCharCode(i % 256)).join(""),
      `${"Received: a\r\n".repeat(20000)}Authentication-Results: mx; spf=pass`,
    ];
    const t0 = Date.now();
    for (const raw of inputs) shapeOk(parseSecurity(raw));
    expect(Date.now() - t0).toBeLessThan(1000);
  });

  it("a block cut in the middle of a header parses as far as it arrived", () => {
    const r = parseSecurity("Authentication-Results: mx.recv.example; spf=pass; dkim=pass header.d=x.exa");
    expect(r.auth.spf).toBe("pass");
    expect(r.auth.dkimDomains).toEqual(["x.exa"]);
  });

  it("a very large block with Authentication-Results first still parses the top", () => {
    const filler = Array.from({ length: 8000 }, (_, i) => `X-Filler-${i}: ${"z".repeat(30)}`).join("\r\n");
    const r = parseSecurity(`Authentication-Results: mx.recv.example; spf=pass\r\n${filler}\r\n\r\n`);
    expect(r.auth.spf).toBe("pass");
  });
});
