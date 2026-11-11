import { beforeEach, describe, expect, it, vi } from "vitest";
import type { SessionInfo } from "../../shared/types/api";

/**
 * app/composables/useApi.ts with Nuxt's auto-imports replaced by stubs: CSRF header attachment, ApiError mapping,
 * the 401 -> /login?returnTo redirect and the single retry after a 403 `csrf`.
 */
const g = globalThis as Record<string, unknown>;
const info = (csrf: string): SessionInfo => ({ setupRequired: false, authenticated: true, csrfToken: csrf, registrationMode: "dynamic", baseUrl: "http://x" });

let session: { info: { value: SessionInfo | null }; refresh: ReturnType<typeof vi.fn> };
let fetchMock: ReturnType<typeof vi.fn>;
let router: { currentRoute: { value: { path: string; fullPath: string } }; replace: ReturnType<typeof vi.fn> };

beforeEach(() => {
  session = { info: { value: info("tok-1") }, refresh: vi.fn(async () => { session.info.value = info("tok-2"); return session.info.value; }) };
  router = { currentRoute: { value: { path: "/audit", fullPath: "/audit?page=2" } }, replace: vi.fn(async () => {}) };
  fetchMock = vi.fn(async () => ({ ok: true }));
  g.useSessionState = () => session;
  g.useRouter = () => router;
  g.$fetch = fetchMock;
});

const { useApi, ApiError } = await import("../../app/composables/useApi");
const fetchError = (status: number, data?: unknown) => Object.assign(new Error(`HTTP ${status}`), { status, statusCode: status, response: { status }, data });
const apiErr = (status: number, code: string, message = "msg") => fetchError(status, { error: { code, message } });
const lastCall = (n = -1) => { const c = fetchMock.mock.calls.at(n)!; return { url: c[0] as string, opts: c[1] as Record<string, any> }; };

describe("useApi: requests", () => {
  it("GET hits /api<path> with query, JSON accept, same-origin credentials, no CSRF header and no body", async () => {
    fetchMock.mockResolvedValueOnce({ events: [] });
    const out = await useApi().get<{ events: unknown[] }>("/audit", { query: { page: 2, tool: "search_messages", skip: undefined } });
    expect(out).toEqual({ events: [] });
    const { url, opts } = lastCall();
    expect(url).toBe("/api/audit");
    expect(opts.method).toBe("GET");
    expect(opts.query).toEqual({ page: 2, tool: "search_messages", skip: undefined });
    expect(opts.headers["X-CSRF-Token"]).toBeUndefined();
    expect(opts.headers["Content-Type"]).toBeUndefined();
    expect(opts.headers.Accept).toBe("application/json");
    expect(opts.credentials).toBe("same-origin");
    expect(opts.body).toBeUndefined();
  });

  it.each([["post", "POST"], ["put", "PUT"], ["patch", "PATCH"], ["del", "DELETE"]] as const)("%s sends JSON and the session's CSRF token", async (fn, method) => {
    await (useApi() as any)[fn]("/things/1", { a: 1 });
    const { url, opts } = lastCall();
    expect(url).toBe("/api/things/1");
    expect(opts.method).toBe(method);
    expect(opts.headers["X-CSRF-Token"]).toBe("tok-1");
    expect(opts.headers["Content-Type"]).toBe("application/json");
    expect(opts.body).toEqual({ a: 1 });
  });

  it("POST/PUT/PATCH without a body send an empty JSON object; DELETE without a body sends none", async () => {
    const api = useApi();
    await api.post("/logout");
    expect(lastCall().opts.body).toEqual({});
    await api.put("/x");
    expect(lastCall().opts.body).toEqual({});
    await api.patch("/x");
    expect(lastCall().opts.body).toEqual({});
    await api.del("/x");
    expect(lastCall().opts.body).toBeUndefined();
  });

  it("mutations fetch the session first when it is not loaded yet, and then use its token", async () => {
    session.info.value = null;
    await useApi().post("/mailboxes", { label: "x" });
    expect(session.refresh).toHaveBeenCalledTimes(1);
    expect(lastCall().opts.headers["X-CSRF-Token"]).toBe("tok-2");
  });

  it("GETs never trigger a session fetch", async () => {
    session.info.value = null;
    await useApi().get("/overview");
    expect(session.refresh).not.toHaveBeenCalled();
  });

  it("the token is never put in the URL or the body", async () => {
    await useApi().post("/mailboxes", { label: "x" });
    const { url, opts } = lastCall();
    expect(url).not.toContain("tok-1");
    expect(JSON.stringify(opts.body)).not.toContain("tok-1");
  });
});

describe("useApi: ApiError mapping", () => {
  it("maps { error: { code, message } } bodies", async () => {
    fetchMock.mockRejectedValueOnce(apiErr(400, "bad_request", "Port must be 1-65535"));
    const e = await useApi().post("/mailboxes", {}).catch((x) => x);
    expect(e).toBeInstanceOf(ApiError);
    expect(e).toBeInstanceOf(Error);
    expect(e).toMatchObject({ name: "ApiError", status: 400, code: "bad_request", message: "Port must be 1-65535" });
  });

  it("reads the status from response.status, status or statusCode", async () => {
    for (const shape of [{ response: { status: 409 } }, { status: 409 }, { statusCode: 409 }]) {
      fetchMock.mockRejectedValueOnce(Object.assign(new Error("x"), shape, { data: { error: { code: "conflict", message: "m" } } }));
      expect(await useApi().post("/x", {}).catch((x) => x)).toMatchObject({ status: 409, code: "conflict" });
    }
  });

  it("a non-JSON error body becomes a generic message that names the status", async () => {
    fetchMock.mockRejectedValueOnce(fetchError(502, "<html>Bad gateway</html>"));
    const e = await useApi().get("/overview").catch((x) => x);
    expect(e).toMatchObject({ status: 502, code: "error" });
    expect(e.message).toMatch(/502/);
    expect(e.message).not.toContain("<html>");
  });

  it("a transport failure is status 0 / code network with a human message", async () => {
    fetchMock.mockRejectedValueOnce(new TypeError("fetch failed"));
    const e = await useApi().get("/overview").catch((x) => x);
    expect(e).toMatchObject({ status: 0, code: "network" });
    expect(e.message).not.toContain("fetch failed");
  });
});

describe("useApi: 401", () => {
  it("clears the session and navigates to /login?returnTo=<current page>, then still throws", async () => {
    fetchMock.mockRejectedValueOnce(apiErr(401, "unauthorized", "Authentication required"));
    const e = await useApi().get("/overview").catch((x) => x);
    expect(e).toMatchObject({ status: 401, code: "unauthorized" });
    expect(session.info.value).toBeNull();
    expect(router.replace).toHaveBeenCalledWith({ path: "/login", query: { returnTo: "/audit?page=2" } });
  });

  it("does not navigate when already on /login", async () => {
    router.currentRoute.value = { path: "/login", fullPath: "/login" };
    fetchMock.mockRejectedValueOnce(apiErr(401, "unauthorized", "x"));
    await useApi().get("/overview").catch(() => {});
    expect(router.replace).not.toHaveBeenCalled();
  });

  it.each(["/login", "/setup", "/session"])("%s answering 401 is an ordinary error (wrong password), not a redirect", async (path) => {
    fetchMock.mockRejectedValueOnce(apiErr(401, "invalid_credentials", "Wrong password. Try again."));
    const e = await useApi().post(path, { password: "x" }).catch((x) => x);
    expect(e).toMatchObject({ status: 401, message: "Wrong password. Try again." });
    expect(router.replace).not.toHaveBeenCalled();
    expect(session.info.value).not.toBeNull();
  });
});

describe("useApi: 403 csrf", () => {
  it("refreshes the session once and retries the request once with the new token", async () => {
    fetchMock.mockRejectedValueOnce(apiErr(403, "csrf", "Invalid or missing CSRF token")).mockResolvedValueOnce({ ok: 1 });
    const out = await useApi().post("/mailboxes", { label: "x" });
    expect(out).toEqual({ ok: 1 });
    expect(session.refresh).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(lastCall(0).opts.headers["X-CSRF-Token"]).toBe("tok-1");
    expect(lastCall(1).opts.headers["X-CSRF-Token"]).toBe("tok-2");
    expect(lastCall(1).opts.body).toEqual({ label: "x" });
  });

  it("gives up after one retry: the second csrf failure surfaces as an ApiError (no loop)", async () => {
    fetchMock.mockRejectedValue(apiErr(403, "csrf", "Invalid or missing CSRF token"));
    const e = await useApi().del("/mailboxes/1", { confirmLabel: "x" }).catch((x) => x);
    expect(e).toBeInstanceOf(ApiError);
    expect(e).toMatchObject({ status: 403, code: "csrf" });
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(session.refresh).toHaveBeenCalledTimes(1);
  });

  it("other 403s (and 403 without the csrf code) are not retried", async () => {
    fetchMock.mockRejectedValueOnce(apiErr(403, "forbidden", "Clients are registered dynamically"));
    const e = await useApi().post("/clients", { name: "x" }).catch((x) => x);
    expect(e).toMatchObject({ status: 403, code: "forbidden" });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(session.refresh).not.toHaveBeenCalled();
  });

  it("a 401 on the retry still redirects to the login page", async () => {
    fetchMock.mockRejectedValueOnce(apiErr(403, "csrf", "x")).mockRejectedValueOnce(apiErr(401, "unauthorized", "x"));
    const e = await useApi().post("/mailboxes", {}).catch((x) => x);
    expect(e).toMatchObject({ status: 401 });
    expect(router.replace).toHaveBeenCalledTimes(1);
  });
});
