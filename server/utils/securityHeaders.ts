import { createHash } from "node:crypto";
import { brotliDecompressSync, gunzipSync, inflateSync } from "node:zlib";
import { getRequestHeader, getResponseHeader, setResponseHeader, type H3Event } from "h3";
import { config } from "../core/config";
import { resolveRequestId } from "../core/security/requestId";

/** CSP of protocol / JSON / everything that is not the SPA document (unchanged from the Express version). */
export const DEFAULT_CSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'";
/** Long-lived caching is for the content-hashed Nuxt build assets only. */
export const ASSET_CACHE_CONTROL = "public, max-age=31536000, immutable";

/**
 * CSP of the SPA document. `script-src` is 'self' plus the sha256 of each inline script in the document served
 * (Nuxt's `window.__NUXT__` bootstrap and the importmap): never 'unsafe-inline'. No form-action (it would break
 * the OAuth redirect after approval).
 */
export function buildSpaCsp(scriptHashes: readonly string[] = []): string {
  const script = ["'self'", ...scriptHashes.map((h) => `'${h}'`)].join(" ");
  return [
    "default-src 'none'",
    `script-src ${script}`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    "base-uri 'none'",
    "frame-ancestors 'none'",
  ].join("; ");
}

const NON_EXECUTABLE_TYPE = /^(?!$)(?!module$|importmap$|speculationrules$|(?:text|application)\/(?:javascript|ecmascript|x-javascript|x-ecmascript|jscript|livescript)$)/i;

/** CSP hash sources ("sha256-...") of every inline, script-executed `<script>` in an HTML document. Data blocks (type=application/json) need none. */
export function inlineScriptHashes(html: string): string[] {
  const out = new Set<string>();
  for (const m of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi)) {
    const attrs = m[1] ?? "";
    const body = m[2] ?? "";
    if (/\ssrc\s*=/i.test(" " + attrs) || body === "") continue;
    const type = /\stype\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))/i.exec(" " + attrs);
    const t = (type?.[1] ?? type?.[2] ?? type?.[3] ?? "").trim();
    if (t && NON_EXECUTABLE_TYPE.test(t)) continue;
    out.add("sha256-" + createHash("sha256").update(body, "utf8").digest("base64"));
  }
  return [...out];
}

function bodyToHtml(body: unknown, encoding: string | undefined): string | undefined {
  try {
    if (typeof body === "string") return body;
    if (body instanceof Uint8Array) {
      let buf = Buffer.from(body.buffer, body.byteOffset, body.byteLength);
      const enc = (encoding ?? "").trim().toLowerCase();
      if (enc === "gzip" || enc === "x-gzip") buf = gunzipSync(buf);
      else if (enc === "br") buf = brotliDecompressSync(buf);
      else if (enc === "deflate") buf = inflateSync(buf);
      else if (enc && enc !== "identity") return undefined;
      return buf.toString("utf8");
    }
  } catch { /* undecodable: no hashes (the page then fails closed under the CSP) */ }
  return undefined;
}

const cache = new Map<string, string>();

/** The CSP for an HTML document body (hash list computed from the bytes about to be sent, memoised). */
export function spaCspFor(html: string | undefined): string {
  if (html === undefined) return buildSpaCsp();
  let csp = cache.get(html);
  if (!csp) {
    csp = buildSpaCsp(inlineScriptHashes(html));
    if (cache.size >= 8) cache.clear();
    cache.set(html, csp);
  }
  return csp;
}

function isHttps(): boolean {
  try { return config.isHttps; } catch { return false; } // invalid config: startup validation already failed closed
}

function pathnameOf(event: H3Event): string {
  const p = event.node.req.originalUrl || event.node.req.url || "/";
  const q = p.indexOf("?");
  return q === -1 ? p : p.slice(0, q);
}

/** Request id: honour a well-formed X-Request-Id, else mint one; exposed as event.context.requestId and echoed. Idempotent. */
export function applyRequestId(event: H3Event): string {
  const ctx = event.context as { requestId?: string };
  if (!ctx.requestId) ctx.requestId = resolveRequestId(getRequestHeader(event, "x-request-id"));
  setResponseHeader(event, "X-Request-Id", ctx.requestId);
  return ctx.requestId;
}

/**
 * Headers for every response (including those served straight from Nitro's static handler, so this also runs from a
 * `request` hook). Idempotent. The SPA document's CSP replaces DEFAULT_CSP in applySpaCsp once the body is known.
 */
export function applyBaseHeaders(event: H3Event): void {
  const ctx = event.context as { securityHeaders?: boolean };
  if (ctx.securityHeaders) return;
  ctx.securityHeaders = true;
  setResponseHeader(event, "X-Content-Type-Options", "nosniff");
  setResponseHeader(event, "X-Frame-Options", "DENY");
  setResponseHeader(event, "Referrer-Policy", "no-referrer");
  setResponseHeader(event, "Content-Security-Policy", DEFAULT_CSP);
  if (isHttps()) setResponseHeader(event, "Strict-Transport-Security", "max-age=31536000");
  const m = event.method.toUpperCase();
  const dev = !!(import.meta as { dev?: boolean }).dev;
  const hashedAsset = !dev && (m === "GET" || m === "HEAD") && pathnameOf(event).startsWith("/_nuxt/");
  setResponseHeader(event, "Cache-Control", hashedAsset ? ASSET_CACHE_CONTROL : "no-store");
  // HTML/API/protocol responses are never cacheable, so conditional requests never help; and a 304 for the SPA
  // document would carry no body to derive the CSP hashes from.
  if (!hashedAsset) {
    delete event.node.req.headers["if-none-match"];
    delete event.node.req.headers["if-modified-since"];
  }
}

/** Called with the handler's response body just before it is sent: an HTML document gets the SPA CSP. */
export function applySpaCsp(event: H3Event, body: unknown): void {
  const type = String(getResponseHeader(event, "content-type") ?? "");
  if (!/^text\/html\b/i.test(type)) return;
  const enc = getResponseHeader(event, "content-encoding");
  setResponseHeader(event, "Content-Security-Policy", spaCspFor(bodyToHtml(body, Array.isArray(enc) ? enc[0] : (enc as string | undefined))));
}
