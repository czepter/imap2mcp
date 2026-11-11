import { beforeEach, describe, expect, it, vi } from "vitest";

// Policy: client may search/read INBOX fully, "Work" headers only, never "Secret".
const rules: Record<string, string[]> = {
  INBOX: ["search", "read_headers", "read_body"],
  Work: ["search", "read_headers"],
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
};
vi.mock("../../server/core/mcp/backend.js", () => ({ getBackend: () => backend }));
vi.mock("../../server/core/sidecar/index.js", () => ({ sidecarEnabled: () => false, getSidecar: () => { throw new Error("no"); } }));

const ctx = { tokenId: "t", clientId: "c", scopes: ["read"] } as never;
const { searchMessagesTool, readMessageTool, listFoldersTool } = await import("../../server/core/mcp/tools.js");

beforeEach(() => { calls.length = 0; });

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
});
