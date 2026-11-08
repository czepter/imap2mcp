import express from "express";
import cors from "cors";
import session from "express-session";

import { validateStartup } from "./config.js";

// Fail closed before anything else touches the DB or keys.
let config: ReturnType<typeof validateStartup>;
try {
  config = validateStartup();
} catch (e) {
  // log.ts redacts; the message names the variable at fault but never prints a value.
  process.stderr.write(`FATAL: ${(e as Error).message}\n`);
  process.exit(1);
}

const { log } = await import("./log.js");
const { getDb, closeDb } = await import("./db/database.js");
const { authRouter, initBootstrap } = await import("./auth/index.js");
const { securityHeaders, csrfExcept, createRateLimiter } = await import("./security/index.js");

import metadataRouter from "./oauth/metadata.js";
import registerRouter from "./oauth/register.js";
import authorizeRouter from "./oauth/authorize.js";
import tokenRouter from "./oauth/token.js";
import { bearerAuth } from "./oauth/middleware.js";
import webRouter from "./web/routes.js";
import { handleMcpRequest } from "./mcp/server.js";
import { startSidecar, stopSidecar } from "./sidecar/index.js";
import { closeAllImap } from "./imap/client.js";
import { healthRouter } from "./health.js";
import { auditRouter } from "./audit/routes.js";
import { startAuditPruner, stopAuditPruner } from "./audit/index.js";
import { installProcessHandlers } from "./process.js";

const app = express();
app.disable("x-powered-by");
if (config.isHttps) app.set("trust proxy", 1);

app.use(securityHeaders({ https: config.isHttps }));

// Liveness/readiness first: unauthenticated, rate limited, no session cookie, no CSRF.
app.use(healthRouter());

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

// Opens the DB; pending migrations are preceded by a VACUUM INTO backup and a failed migration aborts startup.
try {
  getDb();
} catch (e) {
  log.error("FATAL: database could not be opened or migrated; the original file was left untouched", { error: e });
  process.exit(1);
}
initBootstrap();

// CSRF on every browser form POST; bearer/API endpoints are exempt.
app.use(csrfExcept(["/oauth/token", "/oauth/register", "/oauth/revoke", "/mcp"]));

app.use("/oauth/token", createRateLimiter({ windowMs: 60_000, max: 60, message: "Too many token requests" }));

app.use(authRouter);
app.use(metadataRouter);
app.use(registerRouter);
app.use(authorizeRouter);
app.use(tokenRouter);
app.use(auditRouter);
app.use(webRouter);

// MCP: stateless streamable HTTP; a fresh server per request carries the validated token context.
app.all("/mcp", bearerAuth as any, handleMcpRequest as any);

const server = app.listen(config.port, () => {
  log.info("IMAP Bridge listening", { baseUrl: config.baseUrl, mcp: `${config.baseUrl}/mcp`, port: config.port });
});

// Read-only IMAP work runs in the supervised sidecar (v1); start it without blocking the listener.
void startSidecar();
startAuditPruner();

/**
 * Graceful shutdown, in dependency order:
 *  1. stop accepting connections and drop idle keep-alives (health/readiness now unreachable),
 *  2. stop the audit pruner (no new DB work),
 *  3. stop the sidecar and the Node IMAP pool (in-flight tool calls get the grace period),
 *  4. close SQLite (WAL checkpoint) and exit.
 * A hard deadline guarantees exit even if a step hangs; Docker's stop_grace_period must be longer.
 */
let shuttingDown = false;
const SHUTDOWN_DEADLINE_MS = 15_000;
async function shutdown(code = 0): Promise<void> {
  if (shuttingDown) return;
  shuttingDown = true;
  const hard = setTimeout(() => {
    log.error("shutdown deadline exceeded; forcing exit");
    process.exit(code || 1);
  }, SHUTDOWN_DEADLINE_MS);
  hard.unref();
  log.info("shutting down");
  const closed = new Promise<void>((r) => server.close(() => r()));
  server.closeIdleConnections();
  stopAuditPruner();
  await Promise.allSettled([stopSidecar(), closeAllImap()]);
  server.closeAllConnections(); // remaining (streaming) connections: tool calls have had their chance
  await Promise.race([closed, new Promise((r) => setTimeout(r, 2000))]);
  try { closeDb(); } catch (e) { log.warn("closing the database failed", { error: e }); }
  process.exit(code);
}

installProcessHandlers({ shutdown: (code: number) => shutdown(code) });
process.on("SIGTERM", () => void shutdown(0));
process.on("SIGINT", () => void shutdown(0));
