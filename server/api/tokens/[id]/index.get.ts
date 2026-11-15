import { defineEventHandler, getRouterParam } from "h3";
import type { TokenDetail } from "../../../../shared/types/api";
import { requireAdmin } from "../../../utils/requireAdmin";
import { apiError } from "../../../utils/apiError";
import { buildTokenDetail, getLiveToken } from "../../../utils/dto-client";

export default defineEventHandler(async (event): Promise<TokenDetail> => {
  await requireAdmin(event);
  const t = getLiveToken(getRouterParam(event, "id") ?? "");
  if (!t) apiError(404, "not_found", "Token not found");
  return buildTokenDetail(t);
});
