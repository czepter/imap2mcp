import { defineEventHandler, getQuery } from "h3";
import type { AuthorizeRedirect, AuthorizeRequest } from "../../../shared/types/api";
import { requireAdmin } from "../../utils/requireAdmin";
import { requestedColumns, toAuthorizeParams, validateAuthorize } from "../../utils/dto-oauth";
import { clientDisplayNameOrId, isoTs } from "../../utils/dto-common";
import { listMailboxes } from "../../core/imap/mailboxes.js";

export default defineEventHandler(async (event): Promise<AuthorizeRequest | AuthorizeRedirect> => {
  await requireAdmin(event);
  const r = validateAuthorize(getQuery(event) as Record<string, unknown>);
  if (!r.ok) return { redirectTo: r.redirectTo };
  const p = r.value;
  return {
    client: { id: p.client.client_id, name: clientDisplayNameOrId(p.client), createdAt: isoTs(p.client.created_at) },
    redirectUri: p.redirect_uri,
    capabilities: requestedColumns(p.caps),
    mailboxes: listMailboxes().map((m) => ({ id: m.id, label: m.label, draftsFolder: m.drafts_folder })),
    params: toAuthorizeParams(p),
  };
});
