/**
 * MCP tool metadata over the real HTTP transport (the unit test checks the in-memory server): tools/list through
 * /mcp must return a title and explicit behavioural annotations for all 7 tools, because MCP clients categorise
 * tools (and decide which need confirmation) from these hints.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { makeSelfSignedCert } from "../helpers/certs.js";
import { createStack, Mcp, obtainToken, type Stack } from "../helpers/stack.js";

const haveOpenssl = !!makeSelfSignedCert();
const TOOLS = ["create_draft", "list_folders", "list_mailboxes", "move_message", "read_message", "search_messages", "set_flags"];
const READ_ONLY = new Set(["list_mailboxes", "list_folders", "search_messages", "read_message"]);

describe.skipIf(!haveOpenssl)("tools/list over HTTP", () => {
  let s: Stack;
  let mcp: Mcp;
  beforeAll(async () => {
    s = await createStack({ accounts: ["alice@example.test"] });
    const box = s.mailbox["alice@example.test"];
    const { tokens } = await obtainToken(s, [[box, "read"], [box, "draft"], [box, "organize"]]);
    mcp = await new Mcp(s.base, tokens.access_token).connect();
  });
  afterAll(async () => { await mcp?.close(); await s?.teardown(); });

  it("lists exactly the seven tools, each with a title and explicit annotations", async () => {
    const tools = await mcp.toolDefs();
    expect(tools.map((t) => t.name).sort()).toEqual(TOOLS);
    for (const t of tools) {
      expect(typeof t.title === "string" && t.title.length > 0, `${t.name} title`).toBe(true);
      expect(t.description && t.description.length > 10, `${t.name} description`).toBeTruthy();
      expect(t.inputSchema?.type, `${t.name} schema`).toBe("object");
      const an = t.annotations;
      expect(an, `${t.name} annotations`).toBeDefined();
      expect(an!.readOnlyHint, `${t.name} readOnlyHint`).toBe(READ_ONLY.has(t.name));
      expect(typeof an!.idempotentHint, `${t.name} idempotentHint`).toBe("boolean");
      expect(typeof an!.openWorldHint, `${t.name} openWorldHint`).toBe("boolean");
      if (!READ_ONLY.has(t.name)) expect(an!.destructiveHint, `${t.name} destructiveHint`).toBe(false); // nothing deletes mail
    }
  });

  it("read-only tools are idempotent; tools that reach the mail server are open-world", async () => {
    const tools = await mcp.toolDefs();
    for (const t of tools) {
      if (READ_ONLY.has(t.name)) expect(t.annotations!.idempotentHint, t.name).toBe(true);
      if (t.name !== "list_mailboxes") expect(t.annotations!.openWorldHint, t.name).toBe(true); // list_mailboxes only reads local configuration
    }
  });

  it("titles are distinct and human readable (not just the snake_case name)", async () => {
    const titles = (await mcp.toolDefs()).map((t) => t.title!);
    expect(new Set(titles).size).toBe(7);
    for (const t of titles) expect(t).not.toMatch(/_/);
  });
});
