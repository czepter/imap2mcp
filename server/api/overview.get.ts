import { defineEventHandler } from "h3";
import type { Overview } from "../../shared/types/api";
import { requireAdmin } from "../utils/requireAdmin";
import { buildOverview } from "../utils/dto-client";

export default defineEventHandler(async (event): Promise<Overview> => {
  await requireAdmin(event);
  return buildOverview();
});
