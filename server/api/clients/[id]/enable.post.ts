import { defineEventHandler, getRouterParam, setResponseStatus } from "h3";
import { requireAdmin } from "../../../utils/requireAdmin";
import { apiError } from "../../../utils/apiError";
import { getClientRow } from "../../../utils/dto-common";
import { getDb } from "../../../core/db/database.js";

export default defineEventHandler(async (event) => {
  await requireAdmin(event);
  const id = getRouterParam(event, "id") ?? "";
  if (!getClientRow(id)) apiError(404, "not_found", "Client not found");
  getDb().prepare("UPDATE oauth_clients SET disabled = 0 WHERE client_id = ?").run(id);
  setResponseStatus(event, 204);
  return null;
});
