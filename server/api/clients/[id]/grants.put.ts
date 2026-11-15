import { defineEventHandler, getRouterParam, setResponseStatus } from "h3";
import { requireAdmin } from "../../../utils/requireAdmin";
import { readJsonBody } from "../../../utils/readJson";
import { apiError } from "../../../utils/apiError";
import { getClientRow, parseGrantList } from "../../../utils/dto-common";
import { getDb } from "../../../core/db/database.js";
import { listMailboxes } from "../../../core/imap/mailboxes.js";
import { applyGrantSet } from "../../../core/policy/rules.js";

export default defineEventHandler(async (event) => {
  await requireAdmin(event);
  const id = getRouterParam(event, "id") ?? "";
  const body = await readJsonBody(event);
  if (!Array.isArray(body.grants)) apiError(400, "validation", "grants must be a list");
  if (!getClientRow(id)) apiError(404, "not_found", "Client not found");
  // The complete desired preset set. Unknown mailboxes and capabilities never match the loops below, so they are ignored.
  const desired = new Set(parseGrantList(body.grants).map((g) => `${g.mailboxId}|${g.capability}`));
  const db = getDb();
  const ids = listMailboxes().map((m) => m.id);
  db.transaction(() => applyGrantSet(db, id, ids, desired))();
  setResponseStatus(event, 204);
  return null;
});
