// Single seam to workstream A's modules (admin guard, CSRF). Adjust imports here only.
import type { Request, RequestHandler } from "express";

export { requireAdmin } from "../auth/middleware.js";
export { csrfProtection, csrfToken } from "../security/csrf.js";
export type { Request, RequestHandler };
export const CSRF_FIELD = "_csrf";
