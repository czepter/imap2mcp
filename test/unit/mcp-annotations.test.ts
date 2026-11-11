import { describe, it, expect } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createMcpServer } from "../../server/core/mcp/server.js";

describe("MCP tool annotations (clients categorize tools by these hints)", () => {
  it("every tool has a title and explicit read-only / destructive / idempotent / open-world hints", async () => {
    const server = createMcpServer({ tokenId: "t", clientId: "c", scopes: ["read", "draft", "organize"] });
    const [a, b] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: "test", version: "0" });
    await Promise.all([server.connect(a), client.connect(b)]);
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual(
      ["create_draft", "list_folders", "list_mailboxes", "move_message", "read_message", "search_messages", "set_flags"]);
    const readOnly = new Set(["list_mailboxes", "list_folders", "search_messages", "read_message"]);
    for (const t of tools) {
      expect(t.title, t.name).toBeTruthy();
      const an = t.annotations!;
      expect(an, t.name).toBeDefined();
      expect(an.readOnlyHint, t.name).toBe(readOnly.has(t.name));
      expect(typeof an.idempotentHint, t.name).toBe("boolean");
      expect(typeof an.openWorldHint, t.name).toBe("boolean");
      if (!readOnly.has(t.name)) expect(an.destructiveHint, t.name).toBe(false);
    }
    await client.close(); await server.close();
  });
});
