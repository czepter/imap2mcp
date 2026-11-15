import { defineEventHandler, getRouterParam } from "h3";
import type { TokenDetail } from "../../../../shared/types/api";
import { requireAdmin } from "../../../utils/requireAdmin";
import { readJsonBody } from "../../../utils/readJson";
import { apiError } from "../../../utils/apiError";
import { isCapability, parseGrantList } from "../../../utils/dto-common";
import { buildTokenDetail, getLiveToken } from "../../../utils/dto-client";
import { getDb } from "../../../core/db/database.js";
import { listMailboxes } from "../../../core/imap/mailboxes.js";
import { CAPABILITIES, capsToScopes } from "../../../core/oauth/common.js";
import { applyGrantSet } from "../../../core/policy/rules.js";

export default defineEventHandler(async (event): Promise<TokenDetail> => {
  await requireAdmin(event);
  const id = getRouterParam(event, "id") ?? "";
  const body = await readJsonBody(event);
  if (!Array.isArray(body.capabilities) || !body.capabilities.every(isCapability)) apiError(400, "validation", "capabilities must be a list of read, draft or organize");
  if (!body.capabilities.length) apiError(400, "validation", "A token needs at least one capability. Revoke it to remove all access.");
  if (!Array.isArray(body.grants)) apiError(400, "validation", "grants must be a list");
  const t = getLiveToken(id);
  if (!t) apiError(404, "not_found", "Token not found");
  const wanted = new Set<string>(body.capabilities);
  const scopes = capsToScopes(CAPABILITIES.filter((c) => wanted.has(c)));
  const desired = new Set(parseGrantList(body.grants).map((g) => `${g.mailboxId}|${g.capability}`));
  const ids = listMailboxes().map((m) => m.id);
  const db = getDb();
  db.transaction(() => {
    applyGrantSet(db, t.client_id, ids, desired);
    // Revoked siblings of the same lineage follow, so the refresh-reuse check (client, scopes, resource) still matches.
    db.prepare("UPDATE oauth_tokens SET scopes = ? WHERE client_id = ? AND resource = ? AND scopes = ? AND (id = ? OR revoked = 1)")
      .run(scopes, t.client_id, t.resource, t.scopes, t.id);
  })();
  return buildTokenDetail(getLiveToken(id)!);
});
