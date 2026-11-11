import { getRequestHeader, type H3Event } from "h3";
import { config } from "../core/config";

const PREFIXES = ["/mcp", "/oauth/token", "/oauth/register", "/oauth/revoke", "/.well-known"];

/** The machine-facing endpoints that get CORS (never anything under /api). Prefix semantics of Express' `app.use(path)`. */
export function isCorsPath(pathname: string): boolean {
  return PREFIXES.some((p) => pathname === p || pathname.startsWith(p + "/"));
}

function addVary(event: H3Event, value: string): void {
  const res = event.node.res;
  const cur = res.getHeader("vary");
  const have = (Array.isArray(cur) ? cur.join(",") : String(cur ?? "")).split(",").map((s) => s.trim().toLowerCase());
  if (have.includes("*") || have.includes(value.toLowerCase())) return;
  res.setHeader("vary", cur ? `${Array.isArray(cur) ? cur.join(", ") : cur}, ${value}` : value);
}

/**
 * Same behaviour as `cors({ origin: config.corsOrigin || true, credentials: false })`: the configured origin, or the
 * request's Origin reflected; no Allow-Credentials, ever. Returns true when it answered an OPTIONS preflight itself.
 */
export function applyCors(event: H3Event): boolean {
  const res = event.node.res;
  const configured = config.corsOrigin;
  const origin = configured || getRequestHeader(event, "origin");
  if (origin) res.setHeader("Access-Control-Allow-Origin", origin);
  addVary(event, "Origin");
  if (event.method.toUpperCase() !== "OPTIONS") return false;
  res.setHeader("Access-Control-Allow-Methods", "GET,HEAD,PUT,PATCH,POST,DELETE");
  const reqHeaders = getRequestHeader(event, "access-control-request-headers");
  addVary(event, "Access-Control-Request-Headers");
  if (reqHeaders) res.setHeader("Access-Control-Allow-Headers", reqHeaders);
  res.statusCode = 204;
  res.setHeader("Content-Length", "0");
  res.end();
  return true;
}
