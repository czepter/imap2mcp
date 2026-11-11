import { defineEventHandler, getRouterParam } from "h3";
import type { MailboxTestResult } from "../../../../shared/types/api";
import { requireAdmin } from "../../../utils/requireAdmin";
import { apiError } from "../../../utils/apiError";
import { getMailbox, testMailbox } from "../../../core/imap/mailboxes.js";

export default defineEventHandler(async (event): Promise<MailboxTestResult> => {
  await requireAdmin(event);
  const id = getRouterParam(event, "id") ?? "";
  if (!getMailbox(id)) apiError(404, "not_found", "Mailbox not found");
  return await testMailbox(id);
});
