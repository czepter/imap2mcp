import { defineEventHandler, sendNoContent } from "h3";
import { clearAdminSession } from "../utils/session";

// Idempotent: signing out without a session is not an error. CSRF is enforced by server/middleware/03.csrf.ts.
export default defineEventHandler(async (event) => {
  await clearAdminSession(event);
  return sendNoContent(event);
});
