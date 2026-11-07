import { Router } from "express";
import { baseUrl, resourceUrl, ALL_SCOPES } from "./common.js";

const router = Router();

function authServerMetadata() {
  const b = baseUrl();
  return {
    issuer: b,
    authorization_endpoint: `${b}/oauth/authorize`,
    token_endpoint: `${b}/oauth/token`,
    registration_endpoint: `${b}/oauth/register`,
    revocation_endpoint: `${b}/oauth/revoke`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    scopes_supported: [...ALL_SCOPES],
    token_endpoint_auth_methods_supported: ["none"],
    revocation_endpoint_auth_methods_supported: ["none"],
    authorization_response_iss_parameter_supported: true,
  };
}

function protectedResourceMetadata() {
  return {
    resource: resourceUrl(),
    authorization_servers: [baseUrl()],
    scopes_supported: [...ALL_SCOPES],
    bearer_methods_supported: ["header"],
  };
}

router.get("/.well-known/oauth-authorization-server", (_req, res) => {
  res.json(authServerMetadata());
});
// RFC 9728: root and path-suffixed (resource is <base>/mcp) forms
router.get(["/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"], (_req, res) => {
  res.json(protectedResourceMetadata());
});

export default router;
