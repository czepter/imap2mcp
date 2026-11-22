import { defineEventHandler, getRouterParam } from "h3";
import type { MailboxTestResult } from "../../../../shared/types/api";
import { requireAdmin } from "../../../utils/requireAdmin";
import { apiError } from "../../../utils/apiError";
import { getMailbox, testMailbox } from "../../../core/imap/mailboxes.js";
import { isMailboxAuthFailed } from "../../../core/imap/client.js";
import { resetMailboxStatus } from "../../../utils/dto-mailbox";

export default defineEventHandler(async (event): Promise<MailboxTestResult> => {
  await requireAdmin(event);
  const id = getRouterParam(event, "id") ?? "";
  if (!getMailbox(id)) apiError(404, "not_found", "Mailbox not found");
  const result = await testMailbox(id);
  // The stored credentials just logged in: a latched auth failure was a false alarm (or has been fixed server-side).
  if (result.ok && isMailboxAuthFailed(id)) await resetMailboxStatus(id);
  return result;
});
