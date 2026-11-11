import type { H3Event } from "h3";
import { getRequestHeader, readRawBody } from "h3";
import { apiError } from "./apiError";

export const MAX_JSON_BYTES = 1024 * 1024;

async function readCapped(event: H3Event): Promise<Buffer> {
  const declared = getRequestHeader(event, "content-length");
  if (declared !== undefined) {
    if (Number(declared) > MAX_JSON_BYTES) apiError(400, "bad_request", "Request body is too large");
    return (await readRawBody(event, false)) ?? Buffer.alloc(0); // node enforces Content-Length: no more bytes arrive
  }
  // chunked / unknown length: count while reading and stop at the cap
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of event.node.req) {
    const b = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += b.length;
    if (total > MAX_JSON_BYTES) apiError(400, "bad_request", "Request body is too large");
    chunks.push(b);
  }
  return Buffer.concat(chunks);
}

/** Parse a JSON object body; 400 apiError("bad_request", ...) if absent, not an object, or too large (1 MB). */
export async function readJsonBody<T extends Record<string, unknown> = Record<string, unknown>>(event: H3Event): Promise<T> {
  const raw = await readCapped(event);
  if (raw.length === 0) apiError(400, "bad_request", "A JSON request body is required");
  let parsed: unknown;
  try { parsed = JSON.parse(raw.toString("utf8")); } catch { apiError(400, "bad_request", "Request body is not valid JSON"); }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    apiError(400, "bad_request", "Request body must be a JSON object");
  }
  return parsed as T;
}
