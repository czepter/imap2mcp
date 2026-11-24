import { beforeEach, describe, expect, it, vi } from "vitest";

// Policy: client may search/read INBOX fully, "Work" headers only, never "Secret".
const rules: Record<string, string[]> = {
  INBOX: ["search", "read_headers", "read_body"],
  Work: ["search", "read_headers"],
  BodyOnly: ["search", "read_body"],
  Secret: [],
};
vi.mock("../../server/core/policy/policy.js", () => ({
  isOpAllowed: (_c: unknown, _m: string, f: string, op: string) => (rules[f] ?? []).includes(op),
  assertOp: (_c: unknown, _m: string, f: string, op: string) => {
    if (!(rules[f] ?? []).includes(op)) throw new (class extends Error { code = "FORBIDDEN"; name = "PolicyError" })();
  },
  filterAllowedFolders: (_c: unknown, _m: string, ops: string[], fs: string[]) => fs.filter((f) => ops.some((o) => (rules[f] ?? []).includes(o))),
  anyAllowedMailboxes: () => ["mb"],
  mailboxHasAllow: () => true,
  allowedMailboxes: () => ["mb"],
}));

const calls: string[] = [];
const RAW = [
  "Authentication-Results: mx.recv.example; spf=pass smtp.mailfrom=a@x.example; dkim=pass header.d=x.example; dmarc=fail (p=REJECT) header.from=bank.example",
  'Reply-To: "Support" <help@evil.example>', "Return-Path: <a@x.example>", "Received: from a by b", "Received: from c by d", "X-Mailer: Foo", "", "",
].join("\r\n");
const hdr = (uid: number, date: string, uv = 7) => ({ uid, uidValidity: uv, flags: [], subject: `s${uid}`, from: [], to: [], cc: [], date, messageId: null, size: 1 });
const backend = {
  listFolders: vi.fn(async () => ["INBOX", "Work", "Secret"].map((path) => ({ path, delimiter: "/", flags: [] }))),
  search: vi.fn(async (_m: string, folder: string, _c: unknown, _l: number, before?: number) => {
    calls.push(`search:${folder}`);
    const all = folder === "INBOX" ? [hdr(3, "2026-01-03"), hdr(1, "2026-01-01")] : [hdr(2, "2026-01-02")];
    return { uidValidity: 7, items: all.filter((h) => before === undefined || h.uid < before) };
  }),
  searchText: vi.fn(async () => ({ uidValidity: 7, uids: [] })),
  fetchHeaders: vi.fn(async (_m: string, folder: string, uv: number, uids: number[]) => {
    calls.push(`fetchHeaders:${folder}`);
    if (uv !== 7) { const { ToolError } = await import("../../server/core/mcp/errors.js"); throw new ToolError("STALE_REFERENCE", "stale"); }
    return uids.map((u) => hdr(u, "2026-01-01"));
  }),
  fetchBody: vi.fn(async () => { calls.push("fetchBody"); return { text: "hello", truncated: false }; }),
  fetchRawHeader: vi.fn(async (..._a: unknown[]): Promise<{ raw: string; truncated: boolean }> => { calls.push("fetchRawHeader"); return { raw: RAW, truncated: false }; }),
};
vi.mock("../../server/core/mcp/backend.js", () => ({ getBackend: () => backend }));
vi.mock("../../server/core/sidecar/index.js", () => ({ sidecarEnabled: () => false, getSidecar: () => { throw new Error("no"); } }));

const ctx = { tokenId: "t", clientId: "c", scopes: ["read"] } as never;
const { searchMessagesTool, readMessageTool, listFoldersTool } = await import("../../server/core/mcp/tools.js");
const { ToolError } = await import("../../server/core/mcp/errors.js");
const { parseSecurity, MAX_RAW_HEADER_BYTES } = await import("../../server/core/mcp/security.js");

const defaultRawHeader = backend.fetchRawHeader.getMockImplementation()!;
beforeEach(() => {
  calls.length = 0;
  backend.fetchRawHeader.mockReset();
  backend.fetchRawHeader.mockImplementation(defaultRawHeader);
  backend.fetchHeaders.mockClear();
  backend.fetchBody.mockClear();
});

describe("MCP read paths: policy before and after the backend", () => {
  it("list_folders returns only readable folders and never names denied ones", async () => {
    const r = await listFoldersTool(ctx, { mailbox: "mb" });
    expect(r.folders.map((f) => f.path)).toEqual(["INBOX", "Work"]);
  });

  it("search without folder queries only allowed folders, merges newest first, never touches Secret", async () => {
    const r = await searchMessagesTool(ctx, { mailbox: "mb" }) as any;
    expect(calls).not.toContain("search:Secret");
    expect(r.messages.map((m: any) => m.ref.folder + ":" + m.ref.uid)).toEqual(["INBOX:3", "Work:2", "INBOX:1"]);
    expect(r.nextCursor).toBeNull();
  });

  it("multi-folder pagination uses an opaque cursor and loses nothing", async () => {
    const p1 = await searchMessagesTool(ctx, { mailbox: "mb", limit: 2 }) as any;
    expect(p1.messages.map((m: any) => m.ref.uid)).toEqual([3, 2]);
    expect(typeof p1.nextCursor).toBe("string");
    const p2 = await searchMessagesTool(ctx, { mailbox: "mb", limit: 2, cursor: p1.nextCursor }) as any;
    expect(p2.messages.map((m: any) => m.ref.uid)).toEqual([1]);
  });

  it("explicit denied folder: answers like a missing folder (NOT_FOUND), before any backend call", async () => {
    await expect(searchMessagesTool(ctx, { mailbox: "mb", folder: "Secret" })).rejects.toMatchObject({ code: "NOT_FOUND", message: "Folder not found" });
    expect(backend.search).not.toHaveBeenCalled();
    expect(calls).toEqual([]);
  });

  it("read_message: body denied => headers only; fully denied => NOT_FOUND (like a missing folder) without backend calls", async () => {
    const ref = (folder: string) => ({ mailbox: "mb", folder, uidValidity: 7, uid: 5 });
    const w = await readMessageTool(ctx, { ref: ref("Work") }) as any;
    expect(w.subject).toBe("s5");
    expect(w.body).toBeUndefined();
    expect(calls).not.toContain("fetchBody");
    calls.length = 0;
    await expect(readMessageTool(ctx, { ref: ref("Secret") })).rejects.toMatchObject({ code: "NOT_FOUND", message: "Folder not found" });
    expect(calls).toEqual([]);
    const i = await readMessageTool(ctx, { ref: ref("INBOX"), include: ["body"] }) as any;
    expect(i.body).toBe("hello");
    expect(i.subject).toBeUndefined();
  });

  it("stale uidValidity surfaces as STALE_REFERENCE", async () => {
    await expect(readMessageTool(ctx, { ref: { mailbox: "mb", folder: "INBOX", uidValidity: 99, uid: 1 } })).rejects.toMatchObject({ code: "STALE_REFERENCE" });
  });

  describe("include: security", () => {
    const ref = (folder: string) => ({ mailbox: "mb", folder, uidValidity: 7, uid: 5 });

    it("security alone returns ref and security only, with one header-block fetch", async () => {
      const r = await readMessageTool(ctx, { ref: ref("INBOX"), include: ["security"] }) as any;
      expect(Object.keys(r).sort()).toEqual(["ref", "security"]);
      expect(r.security.auth).toMatchObject({ spf: "pass", dkim: "pass", dmarc: "fail", dkimDomains: ["x.example"] });
      expect(r.security.replyTo).toEqual([{ name: "Support", address: "help@evil.example" }]);
      expect(r.security.returnPath).toBe("a@x.example");
      expect(r.security.receivedCount).toBe(2);
      expect(calls).toEqual(["fetchRawHeader"]);
      expect(backend.fetchRawHeader).toHaveBeenCalledWith("mb", "INBOX", 7, 5, MAX_RAW_HEADER_BYTES);
    });

    it("the default include is unchanged: no security key, no header-block fetch", async () => {
      const r = await readMessageTool(ctx, { ref: ref("INBOX") }) as any;
      expect(Object.keys(r).sort()).toEqual(["attachments", "body", "bodyType", "cc", "date", "flags", "from", "inReplyTo", "messageId", "ref", "subject", "to", "truncated"]);
      expect(r.security).toBeUndefined();
      expect(backend.fetchRawHeader).not.toHaveBeenCalled();
      const h = await readMessageTool(ctx, { ref: ref("INBOX"), include: ["headers"] }) as any;
      expect("security" in h).toBe(false);
      expect(backend.fetchRawHeader).not.toHaveBeenCalled();
    });

    it("headers, body and security together", async () => {
      const r = await readMessageTool(ctx, { ref: ref("INBOX"), include: ["headers", "body", "security"] }) as any;
      expect(r.subject).toBe("s5");
      expect(r.body).toBe("hello");
      expect(r.security.auth.spf).toBe("pass");
      expect(calls.sort()).toEqual(["fetchBody", "fetchHeaders:INBOX", "fetchRawHeader"]);
    });

    it("duplicates in include are harmless", async () => {
      await readMessageTool(ctx, { ref: ref("INBOX"), include: ["security", "security"] });
      expect(backend.fetchRawHeader).toHaveBeenCalledTimes(1);
    });

    it("without read_headers: same answer as include headers; with body also allowed, body comes back and security is absent", async () => {
      const viaHeaders = await readMessageTool(ctx, { ref: ref("BodyOnly"), include: ["headers"] }).catch((e) => e);
      const viaSecurity = await readMessageTool(ctx, { ref: ref("BodyOnly"), include: ["security"] }).catch((e) => e);
      expect(viaHeaders).toMatchObject({ code: "NOT_FOUND" });
      expect(viaSecurity).toMatchObject({ code: viaHeaders.code, message: viaHeaders.message });
      expect(backend.fetchRawHeader).not.toHaveBeenCalled();
      const r = await readMessageTool(ctx, { ref: ref("BodyOnly"), include: ["security", "body"] }) as any;
      expect(r.body).toBe("hello");
      expect(r.security).toBeUndefined();
      expect(backend.fetchRawHeader).not.toHaveBeenCalled();
    });

    it("security is omitted when the header fetch fails; alone it surfaces the error", async () => {
      backend.fetchRawHeader.mockRejectedValue(new ToolError("UPSTREAM_ERROR", "boom"));
      const r = await readMessageTool(ctx, { ref: ref("INBOX"), include: ["headers", "body", "security"] }) as any;
      expect(r.subject).toBe("s5");
      expect(r.body).toBe("hello");
      expect("security" in r).toBe(false);
      await expect(readMessageTool(ctx, { ref: ref("INBOX"), include: ["security"] })).rejects.toMatchObject({ code: "UPSTREAM_ERROR" });
    });

    it("an empty header block counts as a failed fetch", async () => {
      backend.fetchRawHeader.mockResolvedValue({ raw: "", truncated: false });
      const r = await readMessageTool(ctx, { ref: ref("INBOX"), include: ["body", "security"] }) as any;
      expect(r.body).toBe("hello");
      expect("security" in r).toBe(false);
      await expect(readMessageTool(ctx, { ref: ref("INBOX"), include: ["security"] })).rejects.toMatchObject({ code: "UPSTREAM_ERROR", message: "Could not read message headers" });
    });

    it("STALE_REFERENCE and NOT_FOUND still surface when other parts succeeded", async () => {
      for (const code of ["STALE_REFERENCE", "NOT_FOUND"] as const) {
        backend.fetchRawHeader.mockRejectedValue(new ToolError(code, "gone"));
        await expect(readMessageTool(ctx, { ref: ref("INBOX"), include: ["headers", "body", "security"] })).rejects.toMatchObject({ code });
      }
    });

    it("security is withheld when read_headers is revoked mid-flight", async () => {
      const saved = rules.INBOX;
      const revoke = async () => { rules.INBOX = ["search", "read_body"]; return { raw: RAW, truncated: false }; };
      try {
        backend.fetchRawHeader.mockImplementation(revoke);
        const r = await readMessageTool(ctx, { ref: ref("INBOX"), include: ["security", "body"] }) as any;
        expect(r.body).toBe("hello");
        expect("security" in r).toBe(false);
        rules.INBOX = saved;
        await expect(readMessageTool(ctx, { ref: ref("INBOX"), include: ["security"] })).rejects.toMatchObject({ code: "NOT_FOUND", message: "Folder not found" });
      } finally {
        rules.INBOX = saved;
      }
    });

    it("the parser output is passed through unchanged", async () => {
      const r = await readMessageTool(ctx, { ref: ref("INBOX"), include: ["security"] }) as any;
      expect(r.security).toEqual(parseSecurity(RAW));
    });
  });
});
