import { randomUUID } from "crypto";
import type { Request, Response, NextFunction } from "express";

export const REQUEST_ID_RE = /^[A-Za-z0-9_-]{8,64}$/;

declare module "express-serve-static-core" {
  interface Request {
    requestId?: string;
  }
}

/** Accept a client-supplied X-Request-Id only if it matches the safe pattern; otherwise mint a UUID. */
export function resolveRequestId(header: unknown): string {
  const h = Array.isArray(header) ? header[0] : header;
  return typeof h === "string" && REQUEST_ID_RE.test(h) ? h : randomUUID();
}

/** Sets req.requestId and the X-Request-Id response header. Mount early (before auth/logging). */
export function requestId(req: Request, res: Response, next: NextFunction): void {
  const id = resolveRequestId(req.get("x-request-id"));
  req.requestId = id;
  res.setHeader("X-Request-Id", id);
  next();
}
