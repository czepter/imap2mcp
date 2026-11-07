import { Router } from "express";
import { config } from "../config.js";
import { SCOPES } from "../types.js";

const router = Router();

router.get("/.well-known/oauth-authorization-server", (_req, res) => {
  res.json({
    issuer: config.baseUrl,
    authorization_endpoint: `${config.baseUrl}/oauth/authorize`,
    token_endpoint: `${config.baseUrl}/oauth/token`,
    registration_endpoint: `${config.baseUrl}/oauth/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    scopes_supported: Object.keys(SCOPES),
    token_endpoint_auth_methods_supported: ["none"],
  });
});

export default router;
