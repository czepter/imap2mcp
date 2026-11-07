import { Router } from "express";
import { randomUUID } from "crypto";
import { getDb } from "../db/database.js";
import { config } from "../config.js";
import { validRedirectUri, rateLimiter } from "./common.js";

const router = Router();
const limit = rateLimiter(20, 15 * 60 * 1000);


// RFC 7591 dynamic client registration. Public clients only; registration grants no mail access.
router.post("/oauth/register", limit, (req, res) => {
  if (config.registrationMode !== "dynamic") {
    return res.status(403).json({
      error: "access_denied",
      error_description: "Dynamic client registration is disabled; clients are provisioned by the administrator",
    });
  }
  const body = req.body ?? {};
  const uris = body.redirect_uris;
  if (!Array.isArray(uris) || uris.length === 0 || uris.length > 10 || !uris.every(validRedirectUri)) {
    return res.status(400).json({
      error: "invalid_redirect_uri",
      error_description: "redirect_uris must be 1-10 https URIs (http only for localhost loopback), no fragments",
    });
  }
  const method = body.token_endpoint_auth_method;
  if (method !== undefined && method !== "none") {
    return res.status(400).json({ error: "invalid_client_metadata", error_description: "Only token_endpoint_auth_method=none is supported" });
  }
  const name = typeof body.client_name === "string" ? body.client_name.slice(0, 100) : null;
  const clientId = randomUUID();
  getDb()
    .prepare("INSERT INTO oauth_clients (client_id, client_name, redirect_uris) VALUES (?, ?, ?)")
    .run(clientId, name, JSON.stringify(uris));
  res.status(201).json({
    client_id: clientId,
    client_name: name ?? undefined,
    redirect_uris: uris,
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    token_endpoint_auth_method: "none",
    client_id_issued_at: Math.floor(Date.now() / 1000),
  });
});

export default router;
