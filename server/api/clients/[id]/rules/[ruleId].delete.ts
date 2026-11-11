import { defineEventHandler, getRouterParam, setResponseStatus } from "h3";
import { requireAdmin } from "../../../../utils/requireAdmin";
import { apiError } from "../../../../utils/apiError";
import { getClientRow } from "../../../../utils/dto-common";
import { getDb } from "../../../../core/db/database.js";

export default defineEventHandler(async (event) => {
  await requireAdmin(event);
  const id = getRouterParam(event, "id") ?? "";
  if (!getClientRow(id)) apiError(404, "not_found", "Client not found");
  // idempotent, like the old handler: a rule that is already gone is not an error
  getDb().prepare("DELETE FROM policy_rules WHERE id = ? AND client_id = ?").run(getRouterParam(event, "ruleId") ?? "", id);
  setResponseStatus(event, 204);
  return null;
});
