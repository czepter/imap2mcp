import express from "express";
import cors from "cors";
import session from "express-session";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

import { validateStartup } from "./config.js";

// Fail closed before anything else touches the DB or keys.
let config: ReturnType<typeof validateStartup>;
try {
  config = validateStartup();
} catch (e) {
  console.error(`FATAL: ${(e as Error).message}`);
  process.exit(1);
}

const { getDb } = await import("./db/database.js");
const { authRouter, initBootstrap } = await import("./auth/index.js");
const { securityHeaders, csrfExcept, createRateLimiter } = await import("./security/index.js");

import metadataRouter from "./oauth/metadata.js";
import registerRouter from "./oauth/register.js";
import authorizeRouter from "./oauth/authorize.js";
import tokenRouter from "./oauth/token.js";
import { bearerAuth } from "./oauth/middleware.js";
import webRouter from "./web/routes.js";
import * as mcpModule from "./mcp/server.js";

const app = express();
app.disable("x-powered-by");
if (config.isHttps) app.set("trust proxy", 1);

app.use(securityHeaders({ https: config.isHttps }));

// CORS only for the machine-facing endpoints; never with credentials.
const apiCors = cors({ origin: config.corsOrigin || true, credentials: false });
app.use(["/mcp", "/oauth/token", "/oauth/register", "/oauth/revoke", "/.well-known"], apiCors);

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: false, limit: "1mb" }));

app.use(
  session({
    name: "imap2mcp.sid",
    secret: config.sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: config.isHttps, httpOnly: true, sameSite: "lax", maxAge: 24 * 60 * 60 * 1000 },
  })
);

getDb();
initBootstrap();

// CSRF on every browser form POST; bearer/API endpoints are exempt.
app.use(csrfExcept(["/oauth/token", "/oauth/register", "/oauth/revoke", "/mcp"]));

app.use("/oauth/token", createRateLimiter({ windowMs: 60_000, max: 60, message: "Too many token requests" }));

app.use(authRouter);
app.use(metadataRouter);
app.use(registerRouter);
app.use(authorizeRouter);
app.use(tokenRouter);
app.use(webRouter);

// MCP: stateless streamable HTTP; a fresh server per request carries the validated token context.
const mcp: any = mcpModule;
if (typeof mcp.mcpHandler === "function") {
  app.all("/mcp", bearerAuth as any, mcp.mcpHandler);
} else {
  app.post("/mcp", bearerAuth as any, async (req: any, res: any) => {
    const server = mcp.createMcpServer(req.tokenContext);
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    res.on("close", () => {
      void transport.close();
      void server.close?.();
    });
    try {
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (e) {
      console.error("MCP error:", (e as Error).message);
      if (!res.headersSent) res.status(500).json({ jsonrpc: "2.0", error: { code: -32603, message: "Internal error" }, id: null });
    }
  });
  const notAllowed = (_req: any, res: any) =>
    res.status(405).json({ jsonrpc: "2.0", error: { code: -32000, message: "Method not allowed" }, id: null });
  app.get("/mcp", bearerAuth as any, notAllowed);
  app.delete("/mcp", bearerAuth as any, notAllowed);
}

app.listen(config.port, () => {
  console.log(`IMAP Bridge running at ${config.baseUrl}`);
  console.log(`MCP endpoint: ${config.baseUrl}/mcp`);
  console.log(`OAuth metadata: ${config.baseUrl}/.well-known/oauth-authorization-server`);
});
