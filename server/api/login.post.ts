import { defineEventHandler, sendNoContent, setResponseHeader } from "h3";
import { getDb } from "../core/db/database";
import { verifyPassword } from "../core/auth/password";
import { apiError } from "../utils/apiError";
import { loginLimiter, TOO_MANY_ATTEMPTS } from "../utils/bootstrap";
import { readJsonBody } from "../utils/readJson";
import { enforceRateLimit } from "../utils/rateLimit";
import { newCsrfToken, regenerateAdminSession } from "../utils/session";

export default defineEventHandler(async (event) => {
  enforceRateLimit(event, loginLimiter, TOO_MANY_ATTEMPTS);
  const { password } = await readJsonBody(event);
  const row = getDb().prepare("SELECT password_hash FROM admin WHERE id = 1").get() as { password_hash: string } | undefined;
  const ok = row && typeof password === "string" && password.length <= 1024 && (await verifyPassword(password, row.password_hash));
  if (!ok) apiError(401, "invalid_credentials", "Wrong password. Try again.");
  loginLimiter.reset(event);
  const csrf = newCsrfToken();
  await regenerateAdminSession(event, { admin: true, csrf });
  setResponseHeader(event, "X-CSRF-Token", csrf); // the old token died with the old session
  return sendNoContent(event);
});
