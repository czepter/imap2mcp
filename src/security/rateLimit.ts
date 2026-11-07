import type { Request, Response, NextFunction } from "express";

export interface RateLimitOptions {
  windowMs: number;
  max: number;
  /** Key function; default is the client IP. */
  key?: (req: Request) => string;
  /** Count only failed attempts: call req.rateLimit?.reset() on success. Default false (count all). */
  message?: string;
  now?: () => number;
}

declare module "express-serve-static-core" {
  interface Request {
    rateLimit?: { reset(): void };
  }
}

/** In-memory fixed-window limiter. Reusable middleware factory. */
export function createRateLimiter(opts: RateLimitOptions) {
  const hits = new Map<string, { count: number; resetAt: number }>();
  const now = opts.now ?? Date.now;
  let lastSweep = now();

  return function rateLimit(req: Request, res: Response, next: NextFunction) {
    const t = now();
    if (t - lastSweep > opts.windowMs) {
      for (const [k, v] of hits) if (v.resetAt <= t) hits.delete(k);
      lastSweep = t;
    }
    const key = opts.key ? opts.key(req) : req.ip || "unknown";
    let e = hits.get(key);
    if (!e || e.resetAt <= t) {
      e = { count: 0, resetAt: t + opts.windowMs };
      hits.set(key, e);
    }
    e.count++;
    req.rateLimit = { reset: () => hits.delete(key) };
    if (e.count > opts.max) {
      const retry = Math.max(1, Math.ceil((e.resetAt - t) / 1000));
      res.setHeader("Retry-After", String(retry));
      res.status(429).json({ error: "too_many_requests", error_description: opts.message ?? "Too many requests, try again later" });
      return;
    }
    next();
  };
}
