import { defineEventHandler, getRouterParam } from "h3";
import type { Mailbox } from "../../../../shared/types/api";
import { requireAdmin } from "../../../utils/requireAdmin";
import { readJsonBody } from "../../../utils/readJson";
import { apiError } from "../../../utils/apiError";
import { parseMailboxBody, resetMailboxStatus, toMailboxDto } from "../../../utils/dto-mailbox";
import { getMailbox, updateMailbox, validateMailboxInput } from "../../../core/imap/mailboxes.js";

export default defineEventHandler(async (event): Promise<Mailbox> => {
  await requireAdmin(event);
  const id = getRouterParam(event, "id") ?? "";
  const i = parseMailboxBody(await readJsonBody(event));
  const bad = validateMailboxInput(i, false);
  if (bad) apiError(400, "validation", bad);
  if (!updateMailbox(id, i)) apiError(404, "not_found", "Mailbox not found");
  if (i.password) await resetMailboxStatus(id); // new credentials: resume automatic attempts (both latches)
  return toMailboxDto(getMailbox(id)!);
});
