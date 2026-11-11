import type { ApiErrorBody } from "~~/shared/types/api";

/** An error answered by the admin API (`{ error: { code, message } }`) or a transport failure (status 0). */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

export interface ApiOptions {
  query?: Record<string, string | number | boolean | undefined | null>;
}

type Method = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

/** Auth endpoints answer 401/403 as an ordinary form error, so they never trigger the sign-in redirect. */
const NO_AUTH_REDIRECT = new Set(["/login", "/setup", "/session"]);

/** `$fetch` with Nitro's route-typed overloads erased: paths are dynamic strings here. */
const rawFetch = (url: string, opts: Record<string, unknown>) =>
  ($fetch as unknown as (url: string, opts: Record<string, unknown>) => Promise<unknown>)(url, opts);

function toApiError(e: unknown): ApiError {
  if (e instanceof ApiError) return e;
  const err = e as { response?: { status?: number }; status?: number; statusCode?: number; data?: unknown; message?: string };
  const status = err.response?.status ?? err.status ?? err.statusCode ?? 0;
  const body = err.data as Partial<ApiErrorBody> | undefined;
  if (body?.error && typeof body.error.message === "string") {
    return new ApiError(status, String(body.error.code ?? "error"), body.error.message);
  }
  if (status === 0) return new ApiError(0, "network", "Could not reach the server. Check your connection and try again.");
  return new ApiError(status, "error", `Unexpected response from the server (HTTP ${status}).`);
}

/**
 * Typed client for the same-origin admin API under `/api`.
 * - sends JSON and the `X-CSRF-Token` header (from the session state)
 * - throws ApiError built from the `{error:{code,message}}` body
 * - 401: clears the session state and navigates to `/login?returnTo=<current path>`
 * - 403 `csrf`: refetches the session once and retries once
 */
export function useApi() {
  const session = useSessionState();
  const router = useRouter();

  async function request<T>(method: Method, path: string, body?: unknown, opts?: ApiOptions, retried = false): Promise<T> {
    if (method !== "GET" && !session.info.value) {
      try { await session.refresh(); } catch { /* the request below reports the failure */ }
    }
    const headers: Record<string, string> = { Accept: "application/json" };
    if (method !== "GET") {
      headers["Content-Type"] = "application/json";
      const token = session.info.value?.csrfToken;
      if (token) headers["X-CSRF-Token"] = token;
    }
    try {
      return (await rawFetch(`/api${path}`, {
        method,
        headers,
        query: opts?.query,
        body,
        credentials: "same-origin",
        cache: "no-store",
      })) as T;
    } catch (e) {
      const err = toApiError(e);
      if (err.status === 403 && err.code === "csrf" && !retried) {
        await session.refresh();
        return request<T>(method, path, body, opts, true);
      }
      if (err.status === 401 && !NO_AUTH_REDIRECT.has(path)) {
        session.info.value = null;
        const here = router.currentRoute.value;
        if (here.path !== "/login") {
          await router.replace({ path: "/login", query: { returnTo: here.fullPath } });
        }
      }
      throw err;
    }
  }

  return {
    get: <T>(path: string, opts?: ApiOptions) => request<T>("GET", path, undefined, opts),
    post: <T = void>(path: string, body?: unknown) => request<T>("POST", path, body === undefined ? {} : body),
    put: <T = void>(path: string, body?: unknown) => request<T>("PUT", path, body === undefined ? {} : body),
    patch: <T = void>(path: string, body?: unknown) => request<T>("PATCH", path, body === undefined ? {} : body),
    del: <T = void>(path: string, body?: unknown) => request<T>("DELETE", path, body),
  };
}
