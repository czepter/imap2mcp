import { defineEventHandler, getRouterParam, setResponseStatus } from "h3";
import { requireAdmin } from "../../../utils/requireAdmin";
import { readJsonBody } from "../../../utils/readJson";
import { apiError } from "../../../utils/apiError";
import { getClientRow, parseGrantList } from "../../../utils/dto-common";
import { getDb } from "../../../core/db/database.js";
import { listMailboxes } from "../../../core/imap/mailboxes.js";
import { CAPABILITIES } from "../../../core/oauth/common.js";
import { grantPreset, presetActive, revokePreset } from "../../../core/policy/rules.js";

export default defineEventHandler(async (event) => {
  await requireAdmin(event);
  const id = getRouterParam(event, "id") ?? "";
  const body = await readJsonBody(event);
  if (!Array.isArray(body.grants)) apiError(400, "validation", "grants must be a list");
  if (!getClientRow(id)) apiError(404, "not_found", "Client not found");
  // The complete desired preset set. Unknown mailboxes and capabilities never match the loops below, so they are ignored.
  const desired = new Set(parseGrantList(body.grants).map((g) => `${g.mailboxId}|${g.capability}`));
  const db = getDb();
  const mailboxes = listMailboxes();
  db.transaction(() => {
    for (const m of mailboxes) for (const cap of CAPABILITIES) {
      const want = desired.has(`${m.id}|${cap}`);
      const have = presetActive(db, id, m.id, cap);
      if (want && !have) grantPreset(db, id, m.id, cap);
      else if (!want && have) revokePreset(db, id, m.id, cap);
    }
  })();
  setResponseStatus(event, 204);
  return null;
});
