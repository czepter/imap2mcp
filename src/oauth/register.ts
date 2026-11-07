import { Router } from "express";
import { v4 as uuid } from "uuid";
import { getDb } from "../db/database.js";

const router = Router();

function handleRegister(req: any, res: any) {
  const { client_name, redirect_uris, grant_types, response_types, scope } = req.body;

  if (!redirect_uris || !Array.isArray(redirect_uris) || redirect_uris.length === 0) {
    return res.status(400).json({ error: "invalid_client_metadata", error_description: "redirect_uris required" });
  }

  for (const uri of redirect_uris) {
    try {
      const parsed = new URL(uri);
      if (!["http:", "https:"].includes(parsed.protocol)) {
        return res.status(400).json({ error: "invalid_client_metadata", error_description: "redirect_uris must use http or https" });
      }
    } catch {
      return res.status(400).json({ error: "invalid_client_metadata", error_description: "redirect_uris must be valid URLs" });
    }
  }

  const clientId = uuid();
  const db = getDb();

  db.prepare(`
    INSERT INTO oauth_clients (client_id, client_name, redirect_uris, grant_types, response_types)
    VALUES (?, ?, ?, ?, ?)
  `).run(
    clientId,
    client_name || null,
    JSON.stringify(redirect_uris),
    JSON.stringify(grant_types || ["authorization_code"]),
    JSON.stringify(response_types || ["code"])
  );

  res.status(201).json({
    client_id: clientId,
    client_name: client_name || null,
    redirect_uris,
    grant_types: grant_types || ["authorization_code"],
    response_types: response_types || ["code"],
    token_endpoint_auth_method: "none",
  });
}

// Mount at both paths (Claude.ai may ignore the metadata registration_endpoint)
router.post("/oauth/register", handleRegister);
router.post("/register", handleRegister);

export default router;
