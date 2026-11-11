import { defineEventHandler, sendNoContent, setResponseHeader } from "h3";
import { getDb } from "../core/db/database";
import { hashPassword } from "../core/auth/password";
import { apiError } from "../utils/apiError";
import { bootstrapTokenMatches, clearBootstrapToken, MIN_PASSWORD, setupAvailable, setupLimiter, TOO_MANY_ATTEMPTS } from "../utils/bootstrap";
import { readJsonBody } from "../utils/readJson";
import { enforceRateLimit } from "../utils/rateLimit";
import { newCsrfToken, regenerateAdminSession } from "../utils/session";

export default defineEventHandler(async (event) => {
  if (!setupAvailable()) apiError(404, "not_found", "Not found");
  enforceRateLimit(event, setupLimiter, TOO_MANY_ATTEMPTS);
  const { token, password, password2 } = await readJsonBody(event);
  if (!bootstrapTokenMatches(token)) apiError(403, "invalid_token", "Invalid bootstrap token");
  if (typeof password !== "string" || password.length < MIN_PASSWORD) {
    apiError(400, "password_too_short", `Password must be at least ${MIN_PASSWORD} characters`);
  }
  if (password !== password2) apiError(400, "password_mismatch", "Passwords do not match");
  const hash = await hashPassword(password);
  try {
    getDb().prepare("INSERT INTO admin (id, password_hash) VALUES (1, ?)").run(hash);
  } catch {
    apiError(404, "not_found", "Not found"); // lost a race: an admin exists now
  }
  clearBootstrapToken();
  const csrf = newCsrfToken();
  await regenerateAdminSession(event, { admin: true, csrf });
  setResponseHeader(event, "X-CSRF-Token", csrf); // the old token died with the old session
  return sendNoContent(event);
});
