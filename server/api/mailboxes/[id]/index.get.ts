import { defineEventHandler, getRouterParam } from "h3";
import type { MailboxDetail } from "../../../../shared/types/api";
import { requireAdmin } from "../../../utils/requireAdmin";
import { apiError } from "../../../utils/apiError";
import { mailboxReach, mailboxStatusOf, toMailboxDto } from "../../../utils/dto-mailbox";
import { getMailbox } from "../../../core/imap/mailboxes.js";

export default defineEventHandler(async (event): Promise<MailboxDetail> => {
  await requireAdmin(event);
  const m = getMailbox(getRouterParam(event, "id") ?? "");
  if (!m) apiError(404, "not_found", "Mailbox not found");
  return { mailbox: toMailboxDto(m), status: mailboxStatusOf(m.id), reach: mailboxReach(m.id) };
});
