import { getHeader, getResponseHeader, setResponseHeader, setResponseStatus } from "h3";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { resolveRequestId } from "~~/server/core/security/requestId";
import { createMcpServer } from "~~/server/core/mcp/server";
import { bearerAuth } from "../utils/bearer";
import { isJsonContentType, ProtocolBodyError, readProtocolBody } from "../utils/oauthProtocol";

const rpcError = (code: number, message: string) => ({ jsonrpc: "2.0", error: { code, message }, id: null });

/**
 * Stateless Streamable HTTP endpoint (all methods). bearerAuth first (every method, as before), then POST only.
 * A fresh server + transport is created per request; the SDK writes the response on the raw Node response.
 */
export default defineEventHandler(async (event) => {
  const auth = bearerAuth(event);
  if (!auth.ok) return auth.body;

  if (event.method !== "POST") {
    setResponseStatus(event, 405);
    setResponseHeader(event, "Allow", "POST");
    return rpcError(-32000, "Method not allowed (stateless server)");
  }

  const ctxId = (event.context as { requestId?: unknown }).requestId;
  const rid = typeof ctxId === "string" && ctxId ? ctxId : resolveRequestId(getHeader(event, "x-request-id"));
  (event.context as Record<string, unknown>).requestId = rid;
  if (!getResponseHeader(event, "X-Request-Id")) setResponseHeader(event, "X-Request-Id", rid);

  // Pre-parse the body (1 MB cap) so the SDK transport does not have to read the stream.
  let body: unknown = {};
  if (isJsonContentType(event)) {
    try {
      body = await readProtocolBody(event);
    } catch (e) {
      if (e instanceof ProtocolBodyError && e.status === 413) {
        setResponseStatus(event, 413);
        return rpcError(-32000, "Request body too large");
      }
      setResponseStatus(event, 400);
      return rpcError(-32700, "Parse error: Invalid JSON");
    }
  }

  const { req, res } = event.node;
  const server = createMcpServer(auth.ctx, { requestId: rid });
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  res.on("close", () => { void transport.close(); void server.close(); });
  try {
    await server.connect(transport);
    await transport.handleRequest(req, res, body);
  } catch {
    if (!res.headersSent) {
      setResponseStatus(event, 500);
      return rpcError(-32603, "Internal server error");
    }
  }
  if (!res.headersSent && !res.writableEnded) {
    setResponseStatus(event, 500);
    return rpcError(-32603, "Internal server error");
  }
  // The transport owns the response (it may still be streaming): tell h3 not to write anything more.
  event._handled = true;
});
