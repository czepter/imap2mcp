import { defineEventHandler, getRouterParam, setResponseStatus } from "h3";
import { requireAdmin } from "../../../utils/requireAdmin";
import { readJsonBody } from "../../../utils/readJson";
import { apiError } from "../../../utils/apiError";
import { deleteMailbox, getMailbox } from "../../../core/imap/mailboxes.js";

export default defineEventHandler(async (event) => {
  await requireAdmin(event);
  const id = getRouterParam(event, "id") ?? "";
  const body = await readJsonBody(event);
  const m = getMailbox(id);
  if (!m) apiError(404, "not_found", "Mailbox not found");
  if (typeof body.confirmLabel !== "string" || body.confirmLabel !== m.label) {
    apiError(400, "confirm_mismatch", "Type the mailbox label exactly to confirm");
  }
  deleteMailbox(id);
  setResponseStatus(event, 204);
  return null;
});
