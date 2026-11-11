import { protectedResourceMetadata } from "../../../utils/oauthMetadata";
import { isReadMethod, notFoundBody } from "../../../utils/oauthProtocol";

// RFC 9728, path-suffixed form (the resource is <base>/mcp).
export default defineEventHandler((event) => (isReadMethod(event) ? protectedResourceMetadata() : notFoundBody(event)));
