import { setResponseHeader, setResponseStatus } from "h3";
import { revokeToken } from "../../utils/oauthTokens";
import { notFoundBody, oauthBodyError, oauthError, overLimit, protocolLimiters, readProtocolBody } from "../../utils/oauthProtocol";

// POST /oauth/revoke (RFC 7009). Shares its 60 per 15 min counter with /oauth/token, as before.
export default defineEventHandler(async (event) => {
  if (event.method !== "POST") return notFoundBody(event);
  if (overLimit(event, protocolLimiters().tokenAndRevoke)) return { error: "rate_limited" };

  let b: Record<string, unknown>;
  try { b = await readProtocolBody(event); } catch (e) { return oauthBodyError(event, e); }

  const f = revokeToken(b);
  if (f) return oauthError(event, f.code, f.desc);
  setResponseHeader(event, "Cache-Control", "no-store");
  setResponseStatus(event, 200);
  return {};
});
