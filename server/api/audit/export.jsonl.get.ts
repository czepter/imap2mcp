import { defineEventHandler } from "h3";
import { requireAdmin } from "../../utils/requireAdmin";
import { sendAuditExport } from "../../utils/dto-audit-stream";

export default defineEventHandler(async (event) => {
  await requireAdmin(event);
  return sendAuditExport(event, "jsonl");
});
