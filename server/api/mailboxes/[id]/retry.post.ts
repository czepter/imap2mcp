import { defineEventHandler, getRouterParam, setResponseStatus } from "h3";
import { requireAdmin } from "../../../utils/requireAdmin";
import { apiError } from "../../../utils/apiError";
import { resetMailboxStatus } from "../../../utils/dto-mailbox";
import { getMailbox } from "../../../core/imap/mailboxes.js";

export default defineEventHandler(async (event) => {
  await requireAdmin(event);
  const id = getRouterParam(event, "id") ?? "";
  if (!getMailbox(id)) apiError(404, "not_found", "Mailbox not found");
  await resetMailboxStatus(id);
  setResponseStatus(event, 204);
  return null;
});
