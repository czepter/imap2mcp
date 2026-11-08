import { log } from "./log.js";

export interface ProcessHandlerOptions {
  /** Graceful shutdown hook (close server, sidecar, IMAP pool, DB). Bounded by `graceMs`. */
  shutdown?: (exitCode: number) => Promise<void> | void;
  /** Grace period for `shutdown` before exiting anyway. Default 5000. */
  graceMs?: number;
  /** Test seam; defaults to process.exit. */
  exit?: (code: number) => void;
  /** Test seam; defaults to the real process. */
  target?: Pick<NodeJS.Process, "on" | "off">;
}

let uninstall: (() => void) | null = null;

/**
 * Process safety (docs/DESIGN_V2.md): an unhandled rejection is logged (redacted) and the process keeps serving;
 * an uncaught exception is logged, the process closes gracefully and exits non-zero so the supervisor restarts it.
 * A failed tool call never terminates the process. Idempotent; returns an uninstall function (tests).
 */
export function installProcessHandlers(opts: ProcessHandlerOptions = {}): () => void {
  if (uninstall) uninstall();
  const target = opts.target ?? process;
  const exit = opts.exit ?? ((c: number) => process.exit(c));
  const graceMs = opts.graceMs ?? 5_000;
  let dying = false;

  const onRejection = (reason: unknown) => {
    log.error("unhandled promise rejection (continuing)", { err: reason instanceof Error ? reason : { reason: String(reason) } });
  };
  const onUncaught = (err: unknown) => {
    log.error("uncaught exception; shutting down", { err: err instanceof Error ? err : { reason: String(err) } });
    if (dying) { exit(1); return; }
    dying = true;
    const timer = setTimeout(() => exit(1), graceMs);
    timer.unref?.();
    Promise.resolve()
      .then(() => opts.shutdown?.(1))
      .catch((e) => log.error("shutdown after uncaught exception failed", { err: e instanceof Error ? e : { reason: String(e) } }))
      .finally(() => { clearTimeout(timer); exit(1); });
  };

  target.on("unhandledRejection", onRejection);
  target.on("uncaughtException", onUncaught);
  uninstall = () => {
    target.off("unhandledRejection", onRejection);
    target.off("uncaughtException", onUncaught);
    uninstall = null;
  };
  return uninstall;
}
