import { createError } from "h3";

/** Throw an admin-API error. Rendered as `{ error: { code, message } }` by server/error.ts. */
export function apiError(status: number, code: string, message: string): never {
  throw createError({ statusCode: status, statusMessage: code, message, data: { code } });
}
