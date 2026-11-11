import type { SessionInfo } from "~~/shared/types/api";

/**
 * Session snapshot from `GET /api/session` (useState-backed, shared by every component).
 * `info` is null until the first refresh and after a 401. The CSRF token lives here only,
 * never in storage.
 */
export function useSessionState() {
  const info = useState<SessionInfo | null>("imap2mcp:session", () => null);

  async function refresh(): Promise<SessionInfo> {
    const next = await $fetch<SessionInfo>("/api/session", {
      credentials: "same-origin",
      headers: { Accept: "application/json" },
      cache: "no-store",
    });
    info.value = next;
    return next;
  }

  return { info, refresh };
}
