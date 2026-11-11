import { protectedResourceMetadata } from "../../utils/oauthMetadata";
import { isReadMethod, notFoundBody } from "../../utils/oauthProtocol";

// RFC 9728, root form.
export default defineEventHandler((event) => (isReadMethod(event) ? protectedResourceMetadata() : notFoundBody(event)));
