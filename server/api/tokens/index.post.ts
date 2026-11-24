import { randomUUID } from "node:crypto";
import { defineEventHandler, setResponseStatus } from "h3";
import { API_TOKEN_EXPIRY_DAYS, type ApiTokenCreated } from "../../../shared/types/api";
import { requireAdmin } from "../../utils/requireAdmin";
import { readJsonBody } from "../../utils/readJson";
import { apiError } from "../../utils/apiError";
import { parseGrantList, trimmedString } from "../../utils/dto-common";
import { buildTokenDetail, getLiveToken } from "../../utils/dto-client";
import { getDb } from "../../core/db/database.js";
import { listMailboxes } from "../../core/imap/mailboxes.js";
import { CAPABILITIES, capsToScopes, newSecret, resourceUrl, sha256hex } from "../../core/oauth/common.js";
import { grantPreset } from "../../core/policy/rules.js";

/** Lets people and secret scanners recognise the string; it is part of the hashed secret. */
const API_TOKEN_PREFIX = "i2m_";

/**
 * Create an API token: a bearer token the owner hands to a client that cannot run the OAuth flow. It gets its own
 * client record, so grants, folder rules, revocation and the audit log work as for any other client. It has no
 * refresh token and cannot be extended. The secret is returned once and only its hash is stored.
 */
export default defineEventHandler(async (event): Promise<ApiTokenCreated> => {
  await requireAdmin(event);
  const body = await readJsonBody(event);
  const name = trimmedString(body.name, 100);
  if (!name) apiError(400, "validation", "A name is required");
  const days = API_TOKEN_EXPIRY_DAYS.find((d) => d === body.expiresInDays);
  if (!days) apiError(400, "validation", `expiresInDays must be one of ${API_TOKEN_EXPIRY_DAYS.join(", ")}`);

  const wanted = new Set(parseGrantList(body.grants).map((g) => `${g.mailboxId}|${g.capability}`));
  const grants = listMailboxes().flatMap((m) =>
    CAPABILITIES.filter((c) => wanted.has(`${m.id}|${c}`)).map((capability) => ({ mailboxId: m.id, capability })));
  if (!grants.length) apiError(400, "validation", "Choose at least one mailbox permission");
  const scopes = capsToScopes(CAPABILITIES.filter((c) => grants.some((g) => g.capability === c)));

  const clientId = randomUUID();
  const tokenId = randomUUID();
  const secret = API_TOKEN_PREFIX + newSecret();
  const db = getDb();
  db.transaction(() => {
    db.prepare("INSERT INTO oauth_clients (client_id, client_name, redirect_uris) VALUES (?, ?, '[]')").run(clientId, name);
    for (const g of grants) grantPreset(db, clientId, g.mailboxId, g.capability);
    db.prepare("INSERT INTO oauth_tokens (id, token_hash, client_id, scopes, resource, expires_at) VALUES (?, ?, ?, ?, ?, ?)")
      .run(tokenId, sha256hex(secret), clientId, scopes, resourceUrl(), new Date(Date.now() + days * 86_400_000).toISOString());
  })();

  setResponseStatus(event, 201);
  return { secret, token: buildTokenDetail(getLiveToken(tokenId)!).token };
});
