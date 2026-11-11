import net from "node:net";
import { isMainThread } from "node:worker_threads";
import { validateStartup } from "~~/server/core/config";
import { log } from "~~/server/core/log";
import { getDb, closeDb } from "~~/server/core/db/database";
import { startSidecar, stopSidecar } from "~~/server/core/sidecar/index";
import { closeAllImap } from "~~/server/core/imap/client";
import { startAuditPruner, stopAuditPruner } from "~~/server/core/audit/retention";
import { installProcessHandlers } from "~~/server/core/process";
import { initBootstrap } from "~~/server/utils/bootstrap";

const SHUTDOWN_DEADLINE_MS = 15_000;

/**
 * Startup and shutdown, in the order and with the fail-closed behaviour of the old src/index.ts.
 * Nitro runs plugins synchronously before it creates and starts the HTTP server, so a FATAL exit here happens
 * before anything listens. Everything that must complete before the first request is synchronous.
 */
export default defineNitroPlugin((nitroApp) => {
  // `nuxt build` prerenders in-process without a runtime environment: never boot the app there.
  if (import.meta.prerender) return;

  // 1. Fail closed on invalid configuration / encryption key (the message names the variable, never a value).
  let config: ReturnType<typeof validateStartup>;
  try {
    config = validateStartup();
  } catch (e) {
    process.stderr.write(`FATAL: ${(e as Error).message}\n`);
    process.exit(1);
  }

  // 2. Open the database; pending migrations are preceded by a VACUUM INTO backup and a failed migration aborts startup.
  try {
    getDb();
  } catch (e) {
    log.error("FATAL: database could not be opened or migrated; the original file was left untouched", { error: e });
    process.exit(1);
  }
  initBootstrap();

  // 3. Learn about the real listener: Nitro's node-server entry calls `server.listen()` right after the plugins ran.
  //    One-shot hook on net.Server.prototype.listen so the "listening" log is truthful and shutdown can close it.
  let httpServer: net.Server | undefined;
  const origListen = net.Server.prototype.listen;
  (net.Server.prototype as any).listen = function (this: net.Server, ...args: unknown[]) {
    (net.Server.prototype as any).listen = origListen;
    httpServer = this;
    this.once("listening", () => {
      const a = this.address();
      const port = a && typeof a === "object" ? a.port : config.port;
      log.info("IMAP Bridge listening", { baseUrl: config.baseUrl, mcp: `${config.baseUrl}/mcp`, port });
    });
    return (origListen as any).apply(this, args);
  };

  // 4. Read-only IMAP work runs in the supervised sidecar; start it without blocking, then the audit pruner.
  void startSidecar();
  startAuditPruner();

  /** Dependency-ordered teardown of everything the plugin started (idempotent). */
  const teardown = async () => {
    stopAuditPruner();
    await Promise.allSettled([stopSidecar(), closeAllImap()]);
  };
  // Nitro `close` hook (dev reloads, programmatic shutdown): release resources but never exit the process.
  nitroApp.hooks.hook("close", async () => {
    await teardown();
    try { closeDb(); } catch (e) { log.warn("closing the database failed", { error: e }); }
  });

  // Only the main thread of a production server owns signals and the process lifetime (not `nuxt dev` workers).
  if (!isMainThread) return;

  /**
   * Graceful shutdown, in dependency order:
   *  1. stop accepting connections and drop idle keep-alives (health/readiness now unreachable),
   *  2. stop the audit pruner (no new DB work),
   *  3. stop the sidecar and the Node IMAP pool (in-flight tool calls get the grace period),
   *  4. close SQLite (WAL checkpoint) and exit.
   * A hard deadline guarantees exit even if a step hangs; Docker's stop_grace_period must be longer.
   * This is the ONLY signal path: Nitro's own graceful shutdown (30 s, no ordering) is switched off below.
   */
  process.env.NITRO_SHUTDOWN_DISABLED = "1";
  let shuttingDown = false;
  const shutdown = async (code = 0): Promise<void> => {
    if (shuttingDown) return;
    shuttingDown = true;
    const hard = setTimeout(() => {
      log.error("shutdown deadline exceeded; forcing exit");
      process.exit(code || 1);
    }, SHUTDOWN_DEADLINE_MS);
    hard.unref();
    log.info("shutting down");
    const server = httpServer;
    const closed = new Promise<void>((r) => (server?.listening ? server.close(() => r()) : r()));
    (server as any)?.closeIdleConnections?.();
    await teardown();
    (server as any)?.closeAllConnections?.(); // remaining (streaming) connections: tool calls have had their chance
    await Promise.race([closed, new Promise((r) => setTimeout(r, 2000))]);
    try { closeDb(); } catch (e) { log.warn("closing the database failed", { error: e }); }
    process.exit(code);
  };

  installProcessHandlers({ shutdown: (code: number) => shutdown(code) });
  process.on("SIGTERM", () => void shutdown(0));
  process.on("SIGINT", () => void shutdown(0));
});
