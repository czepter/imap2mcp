import { randomBytes, timingSafeEqual } from "crypto";
import type { Request, Response, NextFunction } from "express";

declare module "express-session" {
  interface SessionData {
    csrf?: string;
  }
}

/** Per-session CSRF token (created on first use). Put it in every POST form as <input name="_csrf">. */
export function csrfToken(req: Request): string {
  if (!req.session) throw new Error("csrfToken requires express-session");
  if (!req.session.csrf) req.session.csrf = randomBytes(32).toString("base64url");
  return req.session.csrf;
}

export function csrfField(req: Request): string {
  return `<input type="hidden" name="_csrf" value="${csrfToken(req)}">`;
}

const SAFE = new Set(["GET", "HEAD", "OPTIONS"]);

function safeEqual(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

/** Verifies body._csrf (or X-CSRF-Token header) against the session token on state-changing methods. */
export function csrfProtection(req: Request, res: Response, next: NextFunction) {
  if (SAFE.has(req.method)) return next();
  const expected = req.session?.csrf;
  const supplied = (req.body && typeof req.body._csrf === "string" ? req.body._csrf : undefined) ?? req.get("x-csrf-token");
  if (!expected || typeof supplied !== "string" || !safeEqual(expected, supplied)) {
    res.status(403).type("text/plain").send("Invalid or missing CSRF token");
    return;
  }
  next();
}

/** Wrap csrfProtection so bearer/API paths (e.g. /token, /register, /mcp) are skipped. */
export function csrfExcept(prefixes: string[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (prefixes.some((p) => req.path === p || req.path.startsWith(p + "/"))) return next();
    return csrfProtection(req, res, next);
  };
}
