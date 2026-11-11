import { defineEventHandler, getRouterParam, setResponseStatus } from "h3";
import { requireAdmin } from "../../../utils/requireAdmin";
import { apiError } from "../../../utils/apiError";
import { getDb } from "../../../core/db/database.js";

export default defineEventHandler(async (event) => {
  await requireAdmin(event);
  const id = getRouterParam(event, "id") ?? "";
  const r = getDb().prepare("UPDATE oauth_tokens SET revoked = 1 WHERE id = ?").run(id);
  if (r.changes === 0) apiError(404, "not_found", "Token not found");
  setResponseStatus(event, 204);
  return null;
});
