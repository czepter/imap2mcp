import { defineEventHandler } from "h3";
import { config } from "../core/config";
import { adminExists } from "../utils/requireAdmin";
import { csrfToken, getAdminSession } from "../utils/session";
import type { SessionInfo } from "../../shared/types/api";

export default defineEventHandler(async (event): Promise<SessionInfo> => {
  const exists = adminExists();
  const token = await csrfToken(event);
  const s = await getAdminSession(event);
  return {
    setupRequired: !exists,
    authenticated: exists && s.admin === true,
    csrfToken: token,
    registrationMode: config.registrationMode,
    baseUrl: config.baseUrl,
  };
});
