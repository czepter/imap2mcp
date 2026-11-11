import { defineEventHandler, getRouterParam, setResponseStatus } from "h3";
import { requireAdmin } from "../../../utils/requireAdmin";
import { readJsonBody } from "../../../utils/readJson";
import { apiError } from "../../../utils/apiError";
import { trimmedString } from "../../../utils/dto-common";
import { getMailbox, setDraftsFolder, testMailbox } from "../../../core/imap/mailboxes.js";

export default defineEventHandler(async (event) => {
  await requireAdmin(event);
  const id = getRouterParam(event, "id") ?? "";
  const body = await readJsonBody(event);
  const folder = trimmedString(body.folder, 255);
  if (!getMailbox(id)) apiError(404, "not_found", "Mailbox not found");
  if (!folder || /[\x00-\x1f]/.test(folder)) apiError(400, "validation", "Choose a folder");
  // must be a folder that really exists on the server
  const t = await testMailbox(id);
  if (!t.ok) apiError(400, "mailbox_test_failed", t.message);
  if (!t.folders.includes(folder)) apiError(400, "validation", "That folder does not exist on the server");
  setDraftsFolder(id, folder);
  setResponseStatus(event, 204);
  return null;
});
