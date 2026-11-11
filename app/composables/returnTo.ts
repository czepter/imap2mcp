/**
 * Accept a `returnTo` only when it is a same-site absolute path: starts with a single "/",
 * no backslash tricks, no control characters, and not an auth page (would loop).
 */
export function safeReturnTo(value: unknown): string | null {
  const v = Array.isArray(value) ? value[0] : value;
  if (typeof v !== "string" || v.length === 0 || v.length > 2000) return null;
  if (!v.startsWith("/") || v.startsWith("//") || v.includes("\\")) return null;
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(v)) return null;
  const path = v.split(/[?#]/)[0] ?? "";
  if (path === "/login" || path === "/setup") return null;
  return v;
}
