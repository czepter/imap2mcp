import { defineEventHandler, getRouterParam } from "h3";
import type { ClientDetail } from "../../../../shared/types/api";
import { requireAdmin } from "../../../utils/requireAdmin";
import { apiError } from "../../../utils/apiError";
import { getClientRow } from "../../../utils/dto-common";
import { buildClientDetail } from "../../../utils/dto-client";

export default defineEventHandler(async (event): Promise<ClientDetail> => {
  await requireAdmin(event);
  const c = getClientRow(getRouterParam(event, "id") ?? "");
  if (!c) apiError(404, "not_found", "Client not found");
  return buildClientDetail(c);
});
