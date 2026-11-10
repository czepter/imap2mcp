import { ImapAuthError, isMailboxAuthFailed, markMailboxAuthFailed } from "../imap/client.js";
import { remainingMs } from "../imap/budget.js";
import { auditNote, currentRequestId } from "../audit/context.js";
import { log } from "../log.js";
import type { ReadBackend } from "./backend.js";
import { ToolError, describeCause, normalizeError } from "./errors.js";

/** Read retries: at most 2 (3 attempts), jittered, and only while the 30 s tool budget allows (docs/DESIGN_V2.md "Retries"). */
export const MAX_READ_RETRIES = 2;

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/** Jittered retry delay for retry number `n` (0-based): random in [150, 400] ms doubled per retry. */
export function retryDelayMs(n: number, rand: () => number = Math.random): number {
  return Math.floor((150 + rand() * 250) * 2 ** n);
}

/** Throws AUTH_FAILED without contacting the server when the mailbox is latched. */
export function assertMailboxUsable(mailbox: string): void {
  if (isMailboxAuthFailed(mailbox)) throw normalizeError(new ImapAuthError("latched", true));
}

async function raceBudget<T>(fn: () => Promise<T>): Promise<T> {
  const rem = remainingMs();
  if (rem === undefined) return fn();
  if (rem <= 0) throw new ToolError("TIMEOUT", "Mailbox operation timed out");
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, rej) => {
    timer = setTimeout(() => rej(new ToolError("TIMEOUT", "Mailbox operation timed out")), rem);
    timer.unref?.();
  });
  try { return await Promise.race([fn(), timeout]); } finally { clearTimeout(timer); }
}

/**
 * Run a READ-ONLY upstream operation: latch check, per-call budget, bounded jittered retries on retryable
 * failures. Never used for writes (writes are never replayed automatically).
 */
export async function readOp<T>(mailbox: string, fn: () => Promise<T>, rand: () => number = Math.random): Promise<T> {
  for (let attempt = 0; ; attempt++) {
    assertMailboxUsable(mailbox);
    try {
      return await raceBudget(fn);
    } catch (e) {
      const te = normalizeError(e, false);
      log.warn("read failed", { requestId: currentRequestId(), mailboxId: mailbox, attempt: attempt + 1, errorCode: te.code, cause: describeCause(e) });
      if (te.code === "AUTH_FAILED") markMailboxAuthFailed(mailbox);
      const delay = retryDelayMs(attempt, rand);
      const rem = remainingMs();
      const canRetry = te.retryable && attempt < MAX_READ_RETRIES && (rem === undefined || rem > delay + 1_000);
      if (!canRetry) throw te;
      log.info("retrying read", { mailboxId: mailbox, attempt: attempt + 1, errorCode: te.code, delayMs: delay });
      await sleep(delay);
    }
  }
}

/** Sidecar serves these from its header cache; the rest hit the server on every call. */
const CACHED_METHODS = new Set(["search", "fetchHeaders"]);

/** Wrap a backend with the read policy (budget, retry, latch) and audit notes. */
export function reliableBackend(inner: ReadBackend, cachedMethods: Set<string> = CACHED_METHODS, rand?: () => number): ReadBackend {
  const wrap = <K extends keyof ReadBackend>(name: K): ReadBackend[K] =>
    (async (mailbox: string, ...args: unknown[]) => {
      const r = await readOp(mailbox, () => (inner[name] as (...a: unknown[]) => Promise<unknown>)(mailbox, ...args), rand);
      auditNote({ mailboxId: mailbox, cached: cachedMethods.has(name as string) });
      return r;
    }) as ReadBackend[K];
  return {
    listFolders: wrap("listFolders"), search: wrap("search"), searchText: wrap("searchText"),
    fetchHeaders: wrap("fetchHeaders"), fetchBody: wrap("fetchBody"),
  };
}
