import { getHeader, setResponseHeader } from "h3";
import { exchangeToken } from "../../utils/oauthTokens";
import { notFoundBody, oauthBodyError, oauthError, overLimit, protocolLimiters, readProtocolBody } from "../../utils/oauthProtocol";

// POST /oauth/token (RFC 6749 section 3.2). Any other method is a 404, as before.
export default defineEventHandler(async (event) => {
  if (event.method !== "POST") return notFoundBody(event);
  const l = protocolLimiters();
  if (overLimit(event, l.tokenPerMinute)) return { error: "too_many_requests", error_description: "Too many token requests" };
  if (overLimit(event, l.tokenAndRevoke)) return { error: "rate_limited" };

  let b: Record<string, unknown>;
  try { b = await readProtocolBody(event); } catch (e) { return oauthBodyError(event, e); }

  const r = exchangeToken(b, !!getHeader(event, "authorization"));
  if (!r.ok) return oauthError(event, r.fail.code, r.fail.desc, r.fail.status);
  setResponseHeader(event, "Cache-Control", "no-store");
  setResponseHeader(event, "Pragma", "no-cache");
  return r.body;
});
