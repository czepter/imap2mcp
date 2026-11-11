import type { H3Event } from "h3";
import { getRequestHeader, setResponseHeader } from "h3";
import { config } from "../core/config";
import { apiError } from "./apiError";

export interface RateLimiter {
  /** Counts one hit for the caller; returns whether the caller is now over the limit and the Retry-After seconds. */
  hit(event: H3Event): { limited: boolean; retryAfter: number };
  /** Forget the caller (call after a successful login so only failures count). */
  reset(event: H3Event): void;
}
export interface RateLimitOptions { windowMs: number; max: number; key?: (event: H3Event) => string; now?: () => number }

/** In-memory fixed window, same semantics as src/security/rateLimit.ts. */
export function createRateLimiter(opts: RateLimitOptions): RateLimiter {
  const hits = new Map<string, { count: number; resetAt: number }>();
  const now = opts.now ?? Date.now;
  let lastSweep = now();
  const keyOf = (event: H3Event) => (opts.key ? opts.key(event) : clientIp(event)) || "unknown";

  return {
    hit(event) {
      const t = now();
      if (t - lastSweep > opts.windowMs) {
        for (const [k, v] of hits) if (v.resetAt <= t) hits.delete(k);
        lastSweep = t;
      }
      const key = keyOf(event);
      let e = hits.get(key);
      if (!e || e.resetAt <= t) {
        e = { count: 0, resetAt: t + opts.windowMs };
        hits.set(key, e);
      }
      e.count++;
      if (e.count > opts.max) return { limited: true, retryAfter: Math.max(1, Math.ceil((e.resetAt - t) / 1000)) };
      return { limited: false, retryAfter: 0 };
    },
    reset(event) { hits.delete(keyOf(event)); },
  };
}

/** Client IP; with an https BASE_URL trust exactly one proxy hop (last X-Forwarded-For entry), like `trust proxy 1`. */
export function clientIp(event: H3Event): string {
  const socket = event.node.req.socket?.remoteAddress || "unknown";
  let https = false;
  try { https = config.isHttps; } catch { /* invalid config: do not trust forwarded headers */ }
  if (!https) return socket;
  const xff = getRequestHeader(event, "x-forwarded-for");
  const last = xff?.split(",").map((s) => s.trim()).filter(Boolean).pop();
  return last || socket;
}

/** Count a hit; over the limit => 429 `too_many_requests` with Retry-After (the old limiter's behaviour). */
export function enforceRateLimit(event: H3Event, limiter: RateLimiter, message = "Too many requests, try again later"): void {
  const r = limiter.hit(event);
  if (r.limited) {
    setResponseHeader(event, "Retry-After", r.retryAfter);
    apiError(429, "too_many_requests", message);
  }
}
