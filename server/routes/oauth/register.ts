import { randomUUID } from "node:crypto";
import { setResponseStatus } from "h3";
import { getDb } from "~~/server/core/db/database";
import { config } from "~~/server/core/config";
import { validRedirectUri } from "~~/server/core/oauth/common";
import { notFoundBody, oauthBodyError, overLimit, protocolLimiters, readProtocolBody } from "../../utils/oauthProtocol";

// RFC 7591 dynamic client registration. Public clients only; registration grants no mail access.
export default defineEventHandler(async (event) => {
  if (event.method !== "POST") return notFoundBody(event);
  if (overLimit(event, protocolLimiters().register)) return { error: "rate_limited" };

  let body: Record<string, unknown>;
  try { body = await readProtocolBody(event); } catch (e) { return oauthBodyError(event, e); }

  if (config.registrationMode !== "dynamic") {
    setResponseStatus(event, 403);
    return {
      error: "access_denied",
      error_description: "Dynamic client registration is disabled; clients are provisioned by the administrator",
    };
  }
  const uris = body.redirect_uris;
  if (!Array.isArray(uris) || uris.length === 0 || uris.length > 10 || !uris.every(validRedirectUri)) {
    setResponseStatus(event, 400);
    return {
      error: "invalid_redirect_uri",
      error_description: "redirect_uris must be 1-10 https URIs (http only for localhost loopback), no fragments",
    };
  }
  const method = body.token_endpoint_auth_method;
  if (method !== undefined && method !== "none") {
    setResponseStatus(event, 400);
    return { error: "invalid_client_metadata", error_description: "Only token_endpoint_auth_method=none is supported" };
  }
  const name = typeof body.client_name === "string" ? body.client_name.slice(0, 100) : null;
  const clientId = randomUUID();
  getDb()
    .prepare("INSERT INTO oauth_clients (client_id, client_name, redirect_uris) VALUES (?, ?, ?)")
    .run(clientId, name, JSON.stringify(uris));
  setResponseStatus(event, 201);
  return {
    client_id: clientId,
    client_name: name ?? undefined,
    redirect_uris: uris,
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    token_endpoint_auth_method: "none",
    client_id_issued_at: Math.floor(Date.now() / 1000),
  };
});
