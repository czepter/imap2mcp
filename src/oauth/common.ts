import { createHash, randomBytes } from "crypto";
import { config } from "../config.js";

import type { Capability } from "../types.js";
export type { Capability };
export const CAPABILITIES: Capability[] = ["read", "draft", "organize"];
export const ALL_SCOPES = ["mail:read", "mail:draft", "mail:organize"] as const;

export const ACCESS_TTL_MS = 60 * 60 * 1000;
export const REFRESH_TTL_MS = 30 * 24 * 60 * 60 * 1000;
export const CODE_TTL_MS = 10 * 60 * 1000;

export function sha256hex(s: string): string {
  return createHash("sha256").update(s).digest("hex");
}

export function newSecret(): string {
  return randomBytes(32).toString("base64url");
}

export function baseUrl(): string {
  return String(config.baseUrl).replace(/\/+$/, "");
}

/** Canonical resource / audience identifier of the MCP endpoint. */
export function resourceUrl(): string {
  return `${baseUrl()}/mcp`;
}

export function scopesToCaps(scopes: string): Capability[] {
  const out: Capability[] = [];
  for (const s of scopes.split(/\s+/)) {
    if (s.startsWith("mail:")) {
      const c = s.slice(5) as Capability;
      if (CAPABILITIES.includes(c) && !out.includes(c)) out.push(c);
    }
  }
  return out;
}

export function capsToScopes(caps: Capability[]): string {
  return caps.map((c) => `mail:${c}`).join(" ");
}

/** Redirect URIs: https, or http on loopback only; no fragments. */
export function validRedirectUri(uri: unknown): uri is string {
  if (typeof uri !== "string" || uri.length > 2000) return false;
  let u: URL;
  try {
    u = new URL(uri);
  } catch {
    return false;
  }
  if (u.hash) return false;
  if (u.protocol === "https:") return true;
  if (u.protocol === "http:") {
    return u.hostname === "localhost" || u.hostname === "127.0.0.1" || u.hostname === "[::1]";
  }
  return false;
}

/** Minimal in-memory fixed-window limiter keyed by IP. */
export function rateLimiter(max: number, windowMs: number) {
  const hits = new Map<string, { n: number; reset: number }>();
  return (req: any, res: any, next: any) => {
    const now = Date.now();
    const key = String(req.ip || "unknown");
    let h = hits.get(key);
    if (!h || h.reset <= now) {
      h = { n: 0, reset: now + windowMs };
      hits.set(key, h);
      if (hits.size > 10000) for (const [k, v] of hits) if (v.reset <= now) hits.delete(k);
    }
    h.n++;
    if (h.n > max) {
      res.setHeader("Retry-After", String(Math.ceil((h.reset - now) / 1000)));
      return res.status(429).json({ error: "rate_limited" });
    }
    next();
  };
}
