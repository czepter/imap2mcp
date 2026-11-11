import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { config } from "../core/config";
import { banner, log, registerSecret } from "../core/log";
import { adminExists } from "./requireAdmin";
import { createRateLimiter } from "./rateLimit";

export const MIN_PASSWORD = 12;

let bootstrapToken: string | undefined;

/** Called at startup (after the DB is open). Prints the one-time bootstrap token if no admin exists yet. */
export function initBootstrap(): void {
  if (adminExists()) return;
  bootstrapToken = config.adminBootstrapToken || randomBytes(24).toString("base64url");
  registerSecret(bootstrapToken);
  log.info("first run: no admin configured; setup code printed to stdout");
  banner([ // intentionally plain text and unredacted: the operator must copy the one-time code
    "========================================",
    "  First run: no admin configured.",
    `  Open ${config.baseUrl}/setup and enter this one-time bootstrap token:`,
    `  ${bootstrapToken}`,
    "========================================",
  ]);
}

/** True while first-run setup is possible: a token was issued at startup and no admin exists yet. */
export function setupAvailable(): boolean {
  return !!bootstrapToken && !adminExists();
}

/** Constant-time comparison against the issued token. */
export function bootstrapTokenMatches(candidate: unknown): boolean {
  if (typeof candidate !== "string" || !bootstrapToken) return false;
  const a = createHash("sha256").update(candidate).digest();
  const b = createHash("sha256").update(bootstrapToken).digest();
  return timingSafeEqual(a, b);
}

/** Forget the token (after the admin was created). */
export function clearBootstrapToken(): void {
  bootstrapToken = undefined;
}

export const loginLimiter = createRateLimiter({ windowMs: 15 * 60_000, max: 10 });
export const setupLimiter = createRateLimiter({ windowMs: 15 * 60_000, max: 10 });
export const TOO_MANY_ATTEMPTS = "Too many attempts, try again later";
