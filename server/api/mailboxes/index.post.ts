import { defineEventHandler, setResponseStatus } from "h3";
import type { Mailbox } from "../../../shared/types/api";
import { requireAdmin } from "../../utils/requireAdmin";
import { readJsonBody } from "../../utils/readJson";
import { apiError } from "../../utils/apiError";
import { parseMailboxBody, toMailboxDto } from "../../utils/dto-mailbox";
import { createMailbox, validateMailboxInput } from "../../core/imap/mailboxes.js";

export default defineEventHandler(async (event): Promise<Mailbox> => {
  await requireAdmin(event);
  const i = parseMailboxBody(await readJsonBody(event));
  const bad = validateMailboxInput(i, true);
  if (bad) apiError(400, "validation", bad);
  const m = createMailbox(i);
  setResponseStatus(event, 201);
  return toMailboxDto(m);
});
