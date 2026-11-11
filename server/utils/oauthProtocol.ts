import type { H3Event } from "h3";
import { getHeader, setResponseHeader, setResponseStatus } from "h3";
import { parse as parseQuery } from "node:querystring";
import { createRateLimiter, clientIp, type RateLimiter } from "./rateLimit";

/** Body cap for every protocol endpoint (the old express.json / express.urlencoded limit). */
export const PROTOCOL_BODY_LIMIT = 1024 * 1024;

export class ProtocolBodyError extends Error {
  constructor(readonly status: 400 | 413, message: string) { super(message); }
}

const JSON_CT = /^application\/json\s*(;|$)/i;
const FORM_CT = /^application\/x-www-form-urlencoded\s*(;|$)/i;

export function isJsonContentType(event: H3Event): boolean { return JSON_CT.test(getHeader(event, "content-type") ?? ""); }

/** Reads the request body with a hard size cap (counted while streaming). */
async function readCapped(event: H3Event): Promise<Buffer> {
  const req = event.node.req;
  const declared = Number(req.headers["content-length"]);
  if (Number.isFinite(declared) && declared > PROTOCOL_BODY_LIMIT) {
    req.resume();
    throw new ProtocolBodyError(413, "Request body too large");
  }
  const chunks: Buffer[] = [];
  let size = 0;
  let over = false;
  await new Promise<void>((resolve, reject) => {
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size > PROTOCOL_BODY_LIMIT) { over = true; chunks.length = 0; return; } // keep draining so the response can still be written
      if (!over) chunks.push(c);
    });
    req.on("end", () => resolve());
    req.on("error", reject);
    req.on("aborted", () => reject(new ProtocolBodyError(400, "Request aborted")));
  });
  if (over) throw new ProtocolBodyError(413, "Request body too large");
  return Buffer.concat(chunks);
}

/**
 * Same acceptance as the old `express.json({limit:"1mb"})` + `express.urlencoded({extended:false, limit:"1mb"})`:
 * application/json (objects/arrays only) and application/x-www-form-urlencoded; any other content type yields `{}`;
 * an empty body yields `{}`. Throws ProtocolBodyError (400 malformed, 413 too large).
 */
export async function readProtocolBody(event: H3Event): Promise<Record<string, unknown>> {
  const json = isJsonContentType(event);
  const form = !json && FORM_CT.test(getHeader(event, "content-type") ?? "");
  if (!json && !form) return {};
  const text = (await readCapped(event)).toString("utf8");
  if (!text.trim()) return {};
  if (form) return { ...parseQuery(text) };
  const first = text.trimStart()[0];
  if (first !== "{" && first !== "[") throw new ProtocolBodyError(400, "Malformed JSON body");
  try {
    return JSON.parse(text) as Record<string, unknown>;
  } catch {
    throw new ProtocolBodyError(400, "Malformed JSON body");
  }
}

/** OAuth error response (RFC 6749 section 5.2) with the no-store headers the token endpoint always sent. */
export function oauthError(event: H3Event, code: string, desc?: string, status = 400): { error: string; error_description?: string } {
  setResponseHeader(event, "Cache-Control", "no-store");
  setResponseHeader(event, "Pragma", "no-cache");
  setResponseStatus(event, status);
  return { error: code, error_description: desc };
}

/** Maps a body-reading failure to the OAuth error shape. */
export function oauthBodyError(event: H3Event, e: unknown): { error: string; error_description?: string } {
  if (e instanceof ProtocolBodyError) return oauthError(event, "invalid_request", e.message, e.status);
  return oauthError(event, "invalid_request", "Malformed request body", 400);
}

// ---- rate limiters (created lazily so importing this module never touches A's implementation at boot) ----

const WINDOW_15_MIN = 15 * 60 * 1000;
interface Limiters { tokenPerMinute: RateLimiter; tokenAndRevoke: RateLimiter; register: RateLimiter; health: RateLimiter }
let limiters: Limiters | undefined;

export function protocolLimiters(): Limiters {
  if (!limiters) {
    const key = (e: H3Event) => clientIp(e) || "unknown";
    limiters = {
      // app.use("/oauth/token", createRateLimiter({60/min})) in the old index.ts
      tokenPerMinute: createRateLimiter({ windowMs: 60_000, max: 60, key }),
      // rateLimiter(60, 15 min) from oauth/token.ts: ONE counter shared by /oauth/token and /oauth/revoke
      tokenAndRevoke: createRateLimiter({ windowMs: WINDOW_15_MIN, max: 60, key }),
      // rateLimiter(20, 15 min) from oauth/register.ts
      register: createRateLimiter({ windowMs: WINDOW_15_MIN, max: 20, key }),
      // healthRouter: 120/min
      health: createRateLimiter({ windowMs: 60_000, max: 120, key }),
    };
  }
  return limiters;
}

/** Counts a hit; when over the limit sets 429 + Retry-After and returns true (the caller then returns `body`). */
export function overLimit(event: H3Event, limiter: RateLimiter): boolean {
  const r = limiter.hit(event);
  if (!r.limited) return false;
  setResponseHeader(event, "Retry-After", r.retryAfter);
  setResponseStatus(event, 429);
  return true;
}

/** JSON 404 for protocol/API paths that do not exist. */
export function notFoundBody(event: H3Event): { error: string; error_description: string } {
  setResponseStatus(event, 404);
  return { error: "not_found", error_description: "Not found" };
}

/** GET and HEAD are served (Express answered HEAD from GET routes); every other method on a read-only endpoint is a 404. */
export function isReadMethod(event: H3Event): boolean {
  return event.method === "GET" || event.method === "HEAD";
}
