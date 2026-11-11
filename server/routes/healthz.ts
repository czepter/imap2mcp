import { setResponseHeader, setResponseStatus } from "h3";
import { isReadMethod, notFoundBody, overLimit, protocolLimiters } from "../utils/oauthProtocol";

// Liveness: unauthenticated, rate limited (120/min), never cached, never touches the session.
export default defineEventHandler((event) => {
  if (!isReadMethod(event)) return notFoundBody(event);
  setResponseHeader(event, "Cache-Control", "no-store");
  if (overLimit(event, protocolLimiters().health)) {
    return { error: "too_many_requests", error_description: "Too many health requests" };
  }
  setResponseStatus(event, 200);
  return { status: "ok" };
});
