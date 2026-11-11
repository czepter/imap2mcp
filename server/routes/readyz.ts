import { setResponseHeader, setResponseStatus } from "h3";
import { readiness } from "../utils/health";
import { isReadMethod, notFoundBody, overLimit, protocolLimiters } from "../utils/oauthProtocol";

// Readiness: same rules as /healthz; 200 when ready, 503 otherwise.
export default defineEventHandler(async (event) => {
  if (!isReadMethod(event)) return notFoundBody(event);
  setResponseHeader(event, "Cache-Control", "no-store");
  if (overLimit(event, protocolLimiters().health)) {
    return { error: "too_many_requests", error_description: "Too many health requests" };
  }
  const r = await readiness();
  setResponseStatus(event, r.status === "ok" ? 200 : 503);
  return r;
});
