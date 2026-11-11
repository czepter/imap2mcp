import { randomUUID } from "crypto";

export const REQUEST_ID_RE = /^[A-Za-z0-9_-]{8,64}$/;

/** Accept a client-supplied X-Request-Id only if it matches the safe pattern; otherwise mint a UUID. */
export function resolveRequestId(header: unknown): string {
  const h = Array.isArray(header) ? header[0] : header;
  return typeof h === "string" && REQUEST_ID_RE.test(h) ? h : randomUUID();
}
