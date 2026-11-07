import { createHash, timingSafeEqual } from "crypto";

/** PKCE S256 only. */
export function verifyPKCE(codeVerifier: string, codeChallenge: string): boolean {
  if (!/^[A-Za-z0-9\-._~]{43,128}$/.test(codeVerifier)) return false;
  const a = Buffer.from(createHash("sha256").update(codeVerifier).digest("base64url"));
  const b = Buffer.from(codeChallenge);
  return a.length === b.length && timingSafeEqual(a, b);
}
