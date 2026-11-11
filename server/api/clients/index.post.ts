import { randomUUID } from "node:crypto";
import { defineEventHandler, setResponseStatus } from "h3";
import type { ClientSummary } from "../../../shared/types/api";
import { requireAdmin } from "../../utils/requireAdmin";
import { readJsonBody } from "../../utils/readJson";
import { apiError } from "../../utils/apiError";
import { getClientRow, toClientSummary, trimmedString } from "../../utils/dto-common";
import { getDb } from "../../core/db/database.js";
import { config } from "../../core/config.js";
import { validRedirectUri } from "../../core/oauth/common.js";

export default defineEventHandler(async (event): Promise<ClientSummary> => {
  await requireAdmin(event);
  if (config.registrationMode !== "admin") apiError(403, "forbidden", "Clients are registered dynamically");
  const body = await readJsonBody(event);
  const name = trimmedString(body.name, 100);
  const uris = Array.isArray(body.redirectUris)
    ? body.redirectUris.map((u) => (typeof u === "string" ? u.trim() : u)).filter((u) => u !== "")
    : [];
  if (!name || uris.length === 0 || uris.length > 10 || !uris.every(validRedirectUri)) {
    apiError(400, "validation", "Name and 1-10 valid redirect URIs required (https, or http on localhost)");
  }
  const id = randomUUID();
  getDb().prepare("INSERT INTO oauth_clients (client_id, client_name, redirect_uris) VALUES (?, ?, ?)").run(id, name, JSON.stringify(uris));
  setResponseStatus(event, 201);
  return toClientSummary(getClientRow(id)!);
});
