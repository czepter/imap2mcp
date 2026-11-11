import { baseUrl, ALL_SCOPES } from "~~/server/core/oauth/common";
import { isReadMethod, notFoundBody } from "../../utils/oauthProtocol";

// RFC 8414 authorization server metadata.
export default defineEventHandler((event) => {
  if (!isReadMethod(event)) return notFoundBody(event);
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
});
