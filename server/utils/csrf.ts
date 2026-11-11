import { createHash, timingSafeEqual } from "node:crypto";
import { getRequestHeader, type H3Event } from "h3";
import { apiError } from "./apiError";
import { getAdminSession } from "./session";

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

/** Timing-safe string comparison (digests first, so neither content nor length leaks through timing). */
export function csrfEqual(a: string, b: string): boolean {
  const x = createHash("sha256").update(a).digest();
  const y = createHash("sha256").update(b).digest();
  return timingSafeEqual(x, y);
}

export function isApiPath(pathname: string): boolean {
  return pathname === "/api" || pathname.startsWith("/api/");
}

export function pathnameOf(event: H3Event): string {
  const p = event.node.req.originalUrl || event.path || "/";
  const q = p.indexOf("?");
  return q === -1 ? p : p.slice(0, q);
}

/**
 * CSRF check for every non-GET/HEAD/OPTIONS request under /api: `Content-Type: application/json` (a cross-site form
 * cannot send it without a CORS preflight, which /api never answers) and `X-CSRF-Token` equal to the session token.
 * The token comes from GET /api/session, which also works for visitors without a session yet.
 */
export async function enforceCsrf(event: H3Event): Promise<void> {
  if (!isApiPath(pathnameOf(event)) || SAFE_METHODS.has(event.method.toUpperCase())) return;
  const media = (getRequestHeader(event, "content-type") ?? "").split(";")[0]!.trim().toLowerCase();
  const supplied = getRequestHeader(event, "x-csrf-token");
  const expected = (await getAdminSession(event)).csrf;
  if (media !== "application/json" || !expected || typeof supplied !== "string" || !csrfEqual(expected, supplied)) {
    apiError(403, "csrf", "Invalid or missing CSRF token");
  }
}
