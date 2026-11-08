import { beforeEach, describe, expect, it, vi } from "vitest";

let revoked = false;
let revokeAfter = Infinity; // number of assertOp calls allowed before policy flips to denied
let assertCalls = 0;
vi.mock("../../src/policy/policy.js", () => ({
  isOpAllowed: () => !revoked,
  assertOp: () => {
    assertCalls++;
    if (revoked || assertCalls > revokeAfter) throw new (class extends Error { code = "FORBIDDEN"; name = "PolicyError" })();
  },
  filterAllowedFolders: (_c: unknown, _m: string, _o: string[], f: string[]) => f,
  anyAllowedMailboxes: () => ["mb"],
  mailboxHasAllow: () => true,
  allowedMailboxes: () => ["mb"],
}));
vi.mock("../../src/db/database.js", () => ({
  getDb: () => ({ prepare: () => ({ get: () => ({ drafts_folder: "Drafts" }), run: () => ({}) }) }),
}));
vi.mock("../../src/imap/mailboxes.js", () => ({ getMailboxCredentials: () => ({ host: "h", port: 993, user: "me@example.test", password: "p" }) }));
vi.mock("../../src/sidecar/index.js", () => ({ sidecarEnabled: () => false, getSidecar: () => { throw new Error("no"); } }));
vi.mock("../../src/mcp/backend.js", () => ({ getBackend: () => ({}) }));

interface Fake {
  mailbox: { uidValidity: bigint };
  capabilities: Set<string>;
  append: ReturnType<typeof vi.fn>;
  search: ReturnType<typeof vi.fn>;
  list: ReturnType<typeof vi.fn>;
  fetchOne: ReturnType<typeof vi.fn>;
  fetch: ReturnType<typeof vi.fn>;
  messageMove: ReturnType<typeof vi.fn>;
  messageFlagsAdd: ReturnType<typeof vi.fn>;
  messageFlagsRemove: ReturnType<typeof vi.fn>;
  getMailboxLock: ReturnType<typeof vi.fn>;
}
let fake: Fake;
let withImapCalls = 0;
const failConnections: number[] = []; // 1-based withImap call numbers that fail to (re)connect
vi.mock("../../src/imap/client.js", async (orig) => {
  const real = await orig<typeof import("../../src/imap/client.js")>();
  return {
    ...real,
    withImap: async (_id: string, fn: (c: unknown) => unknown) => {
      withImapCalls++;
      if (failConnections.includes(withImapCalls)) throw new real.ImapConnectError("down");
      return fn(fake);
    },
  };
});

const { createDraftTool, moveMessageTool, setFlagsTool } = await import("../../src/mcp/tools.js");
const { ImapTimeoutError } = await import("../../src/imap/client.js");
const ctx = { tokenId: "t", clientId: "c", scopes: [] } as never;
const ref = { mailbox: "mb", folder: "INBOX", uidValidity: 5, uid: 10 };
const dropped = () => Object.assign(new Error("Connection not available"), { code: "NoConnection" });

beforeEach(() => {
  revoked = false; revokeAfter = Infinity; assertCalls = 0; withImapCalls = 0; failConnections.length = 0;
  fake = {
    mailbox: { uidValidity: 5n },
    capabilities: new Set(["MOVE", "UIDPLUS"]),
    append: vi.fn(async () => { throw dropped(); }),
    search: vi.fn(async () => []),
    list: vi.fn(async () => [{ path: "INBOX", flags: new Set() }, { path: "Archive", flags: new Set() }]),
    fetchOne: vi.fn(async () => ({ uid: 10, envelope: { messageId: "<orig@x>" } })),
    fetch: vi.fn(() => (async function* () { yield { uid: 10, flags: new Set<string>() }; yield { uid: 11, flags: new Set<string>() }; })()),
    messageMove: vi.fn(async () => { throw dropped(); }),
    messageFlagsAdd: vi.fn(async () => { throw dropped(); }),
    messageFlagsRemove: vi.fn(async () => true),
    getMailboxLock: vi.fn(async () => ({ release() {} })),
  };
});

const draftArgs = { mailbox: "mb", to: ["a@example.test"], subject: "s", body: "b" };

describe("create_draft reconciliation", () => {
  it("connection drops after APPEND was sent; Message-ID found in Drafts => success reconciled:true, APPEND not replayed", async () => {
    fake.search.mockResolvedValue([41, 42]);
    const r = await createDraftTool(ctx, draftArgs) as any;
    expect(r.reconciled).toBe(true);
    expect(r.ref).toEqual({ mailbox: "mb", folder: "Drafts", uidValidity: 5, uid: 42 });
    expect(fake.append).toHaveBeenCalledTimes(1);
    const q = fake.search.mock.calls[0][0];
    expect(q.header["message-id"]).toBe(r.messageId);
  });

  it("timeout + not found => UNKNOWN_OUTCOME (with messageId), never re-appended, not retryable", async () => {
    fake.append.mockRejectedValue(new ImapTimeoutError());
    const e = await createDraftTool(ctx, draftArgs).catch((x) => x);
    expect(e.code).toBe("UNKNOWN_OUTCOME");
    expect(e.retryable).toBe(false);
    expect(e.extra.messageId).toMatch(/^<.+@imap2mcp\.invalid>$/);
    expect(fake.append).toHaveBeenCalledTimes(1);
  });

  it("cannot reconnect to verify => UNKNOWN_OUTCOME", async () => {
    failConnections.push(2);
    const e = await createDraftTool(ctx, draftArgs).catch((x) => x);
    expect(e.code).toBe("UNKNOWN_OUTCOME");
    expect(fake.search).not.toHaveBeenCalled();
    expect(fake.append).toHaveBeenCalledTimes(1);
  });

  it("policy revoked mid-failure: no reconcile read is issued", async () => {
    revokeAfter = 2; // pre-check + in-write recheck pass, the reconcile recheck is denied
    const e = await createDraftTool(ctx, draftArgs).catch((x) => x);
    expect(e.code).toBe("UNKNOWN_OUTCOME");
    expect(fake.search).not.toHaveBeenCalled();
    expect(withImapCalls).toBe(1);
  });

  it("explicit server rejection NO [OVERQUOTA] => QUOTA_EXCEEDED, no reconcile, no replay", async () => {
    fake.append.mockRejectedValue(Object.assign(new Error("Command failed"), { serverResponseCode: "OVERQUOTA", responseStatus: "NO" }));
    const e = await createDraftTool(ctx, draftArgs).catch((x) => x);
    expect(e.code).toBe("QUOTA_EXCEEDED");
    expect(e.retryable).toBe(false);
    expect(fake.search).not.toHaveBeenCalled();
  });

  it("server accepted but returned no UID (no UIDPLUS): resolved by Message-ID search", async () => {
    fake.append.mockResolvedValue({ destination: "Drafts" });
    fake.search.mockResolvedValue([7]);
    const r = await createDraftTool(ctx, draftArgs) as any;
    expect(r.ref.uid).toBe(7);
    expect(r.reconciled).toBe(true);
  });

  it("plain success is unchanged and does not claim reconciliation", async () => {
    fake.append.mockResolvedValue({ destination: "Drafts", uid: 9, uidValidity: 5n });
    const r = await createDraftTool(ctx, draftArgs) as any;
    expect(r.reconciled).toBeUndefined();
    expect(r.ref.uid).toBe(9);
    expect(fake.search).not.toHaveBeenCalled();
  });
});

describe("move_message reconciliation", () => {
  const args = { ref, destination: "Archive" };
  /** fetchOne calls 1-2 are the pre-write existence check and the Message-ID lookup; later calls are the reconcile source check. */
  const sourceAfter = (present: boolean) => {
    let n = 0;
    fake.fetchOne.mockImplementation(async () => (++n <= 2 || present ? { uid: 10, envelope: { messageId: "<orig@x>" } } : null));
  };

  it("destination has the Message-ID and source UID is gone => success reconciled", async () => {
    sourceAfter(false);
    fake.search.mockResolvedValue([3]);
    const r = await moveMessageTool(ctx, args) as any;
    expect(r).toMatchObject({ moved: true, reconciled: true, newRef: { folder: "Archive", uid: 3, uidValidity: 5 } });
    expect(fake.messageMove).toHaveBeenCalledTimes(1);
    expect(fake.search.mock.calls[0][0].header["message-id"]).toBe("<orig@x>");
  });

  it("source still present and destination lacks it => UNKNOWN_OUTCOME likelyNotApplied (not replayed)", async () => {
    sourceAfter(true);
    fake.search.mockResolvedValue([]);
    const e = await moveMessageTool(ctx, args).catch((x) => x);
    expect(e.code).toBe("UNKNOWN_OUTCOME");
    expect(e.extra).toEqual({ likelyNotApplied: true });
    expect(fake.messageMove).toHaveBeenCalledTimes(1);
  });

  it("anything else (both present, or both gone) => plain UNKNOWN_OUTCOME", async () => {
    sourceAfter(true);
    fake.search.mockResolvedValue([3]);
    let e = await moveMessageTool(ctx, args).catch((x) => x);
    expect(e.code).toBe("UNKNOWN_OUTCOME");
    expect(e.extra).toBeUndefined();
    sourceAfter(false);
    fake.search.mockResolvedValue([]);
    e = await moveMessageTool(ctx, args).catch((x) => x);
    expect(e.code).toBe("UNKNOWN_OUTCOME");
    expect(e.extra).toBeUndefined();
  });

  it("policy revoked mid-failure => no reconcile read", async () => {
    revokeAfter = 4; // two pre-checks + two rechecks before MOVE; reconcile recheck denied
    const e = await moveMessageTool(ctx, args).catch((x) => x);
    expect(e.code).toBe("UNKNOWN_OUTCOME");
    expect(withImapCalls).toBe(1);
    expect(fake.search).not.toHaveBeenCalled();
  });

  it("definite server rejection (NO [OVERQUOTA]) => QUOTA_EXCEEDED without reconcile", async () => {
    fake.messageMove.mockRejectedValue(Object.assign(new Error("x"), { serverResponseCode: "OVERQUOTA", responseStatus: "NO" }));
    const e = await moveMessageTool(ctx, args).catch((x) => x);
    expect(e.code).toBe("QUOTA_EXCEEDED");
    expect(withImapCalls).toBe(1);
  });
});

describe("set_flags reconciliation", () => {
  const args = { refs: [ref, { ...ref, uid: 11 }], add: ["\\Seen"] };
  const flagsAfter = (m: Record<number, string[]>) => {
    let n = 0;
    fake.fetch.mockImplementation(() => (async function* () {
      n++;
      if (n === 1) { yield { uid: 10 }; yield { uid: 11 }; return; } // presence check before STORE
      for (const [u, f] of Object.entries(m)) yield { uid: Number(u), flags: new Set(f) };
    })());
  };

  it("re-FETCH shows the desired flags => ok with reconciled:true; mismatching message => UNKNOWN_OUTCOME; STORE not replayed", async () => {
    flagsAfter({ 10: ["\\Seen"], 11: [] });
    const r = await setFlagsTool(ctx, args) as any;
    expect(r.results[0]).toMatchObject({ status: "ok", reconciled: true });
    expect(r.results[1]).toMatchObject({ status: "error", code: "UNKNOWN_OUTCOME" });
    expect(r.succeeded).toBe(1);
    expect(r.failed).toBe(1);
    expect(fake.messageFlagsAdd).toHaveBeenCalledTimes(1);
  });

  it("flags to remove must be absent too (case-insensitive)", async () => {
    fake.messageFlagsAdd.mockResolvedValue(true);
    fake.messageFlagsRemove.mockRejectedValue(dropped());
    flagsAfter({ 10: ["\\seen", "Todo"], 11: ["\\SEEN"] });
    const r = await setFlagsTool(ctx, { ...args, remove: ["Todo"] }) as any;
    expect(r.results[0].code).toBe("UNKNOWN_OUTCOME");
    expect(r.results[1]).toMatchObject({ status: "ok", reconciled: true });
  });

  it("policy revoked mid-failure => no reconcile read, all UNKNOWN_OUTCOME", async () => {
    revokeAfter = 3; // upfront, group pre-check, final recheck pass; reconcile recheck denied
    const r = await setFlagsTool(ctx, args) as any;
    expect(r.results.map((x: any) => x.code)).toEqual(["UNKNOWN_OUTCOME", "UNKNOWN_OUTCOME"]);
    expect(withImapCalls).toBe(1);
  });

  it("definite rejection (NO [OVERQUOTA]) => per-message QUOTA_EXCEEDED, no reconcile", async () => {
    fake.messageFlagsAdd.mockRejectedValue(Object.assign(new Error("x"), { serverResponseCode: "OVERQUOTA", responseStatus: "NO" }));
    const r = await setFlagsTool(ctx, args) as any;
    expect(r.results.map((x: any) => x.code)).toEqual(["QUOTA_EXCEEDED", "QUOTA_EXCEEDED"]);
    expect(withImapCalls).toBe(1);
  });
});
