import type { NitroErrorHandler } from "nitropack";
import { removeResponseHeader, send, setResponseHeader, setResponseStatus, type H3Error, type H3Event } from "h3";
import { log } from "./core/log";
import { isCorsPath } from "./utils/cors";
import { isApiPath, pathnameOf } from "./utils/csrf";
import { applyBaseHeaders } from "./utils/securityHeaders";

const CODES: Record<number, { code: string; message: string }> = {
  400: { code: "bad_request", message: "Bad request" },
  401: { code: "unauthorized", message: "Authentication required" },
  403: { code: "forbidden", message: "Forbidden" },
  404: { code: "not_found", message: "Not found" },
  405: { code: "method_not_allowed", message: "Method not allowed" },
  409: { code: "conflict", message: "Conflict" },
  413: { code: "payload_too_large", message: "Payload too large" },
  415: { code: "unsupported_media_type", message: "Unsupported media type" },
  422: { code: "unprocessable", message: "Unprocessable request" },
  429: { code: "too_many_requests", message: "Too many requests, try again later" },
};
const INTERNAL = { code: "internal", message: "Internal server error" };

export interface ErrorView { status: number; type: string; body: string }

function statusOf(error: Partial<H3Error>): number {
  const s = Number(error.statusCode);
  return Number.isInteger(s) && s >= 400 && s <= 599 ? s : 500;
}

function isProtocolPath(pathname: string): boolean {
  return isCorsPath(pathname) || pathname === "/oauth" || pathname.startsWith("/oauth/") || pathname === "/healthz" || pathname === "/readyz";
}

/** Pure mapping error -> response. Never includes stack traces, causes or internal messages of 5xx errors. */
export function renderError(error: Partial<H3Error>, pathname: string): ErrorView {
  const status = statusOf(error);
  const data = (error.data && typeof error.data === "object" ? error.data : {}) as Record<string, unknown>;
  const generic = CODES[status] ?? (status >= 500 ? INTERNAL : { code: "error", message: "Request failed" });

  if (isApiPath(pathname)) {
    if (status >= 500) return json(status, { error: INTERNAL });
    // apiError() puts its code in data.code and its human message in `message`; anything else gets the generic text.
    const code = typeof data.code === "string" ? data.code : generic.code;
    const message = typeof data.code === "string" && error.message ? error.message : generic.message;
    return json(status, { error: { code, message } });
  }

  if (isProtocolPath(pathname)) {
    // OAuth-style JSON where the route already produced `error` / `error_description`.
    if (status >= 500) return json(status, { error: "server_error", error_description: "Internal server error" });
    if (typeof data.error === "string") {
      return json(status, typeof data.error_description === "string" ? { error: data.error, error_description: data.error_description } : { error: data.error });
    }
    return json(status, { error: generic.code, error_description: generic.message });
  }

  const text = status >= 500 ? INTERNAL.message : generic.message;
  return { status, type: "text/plain; charset=utf-8", body: text };
}

function json(status: number, body: unknown): ErrorView {
  return { status, type: "application/json; charset=utf-8", body: JSON.stringify(body) };
}

function report(error: Partial<H3Error>, event: H3Event, pathname: string): void {
  try {
    log.error("request failed", {
      requestId: (event.context as { requestId?: string }).requestId,
      method: event.method,
      path: pathname, // no query string: it may carry OAuth codes
      status: statusOf(error),
      error: error.cause ?? error,
    });
  } catch { /* logging must never break error handling */ }
}

/** Nitro error handler: `{ error: { code, message } }` for /api, OAuth-style JSON for protocol routes, plain text otherwise. */
const handler: NitroErrorHandler = (error, event) => {
  const res = event.node.res;
  if (res.headersSent || res.writableEnded) return;
  applyBaseHeaders(event);
  const pathname = pathnameOf(event);
  const view = renderError(error, pathname);
  if (view.status >= 500) report(error, event, pathname);
  removeResponseHeader(event, "Content-Length");
  removeResponseHeader(event, "Content-Encoding");
  removeResponseHeader(event, "ETag");
  setResponseStatus(event, view.status);
  setResponseHeader(event, "Content-Type", view.type);
  setResponseHeader(event, "Cache-Control", "no-store");
  return send(event, view.body);
};
export default handler;
