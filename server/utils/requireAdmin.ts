import type { H3Event } from "h3";
import { getDb } from "../core/db/database";
import { apiError } from "./apiError";
import { getAdminSession } from "./session";

export function adminExists(): boolean {
  return !!getDb().prepare("SELECT 1 FROM admin WHERE id = 1").get();
}

/** 401 apiError unless the session is a signed-in admin AND an admin row still exists. */
export async function requireAdmin(event: H3Event): Promise<void> {
  const s = await getAdminSession(event);
  if (s.admin === true && adminExists()) return;
  apiError(401, "unauthorized", "Authentication required");
}
