import { baseUrl, resourceUrl, ALL_SCOPES } from "~~/server/core/oauth/common";

/** RFC 9728 protected resource metadata (served at the root and the path-suffixed /mcp form). */
export function protectedResourceMetadata() {
  return {
    resource: resourceUrl(),
    authorization_servers: [baseUrl()],
    scopes_supported: [...ALL_SCOPES],
    bearer_methods_supported: ["header"],
  };
}
