import { beforeEach, describe, expect, it, vi } from "vitest";
import type { SessionInfo } from "../../shared/types/api";
import { safeReturnTo } from "../../app/composables/returnTo";

/**
 * app/middleware/auth.global.ts with Nuxt's auto-imports stubbed: where each combination of
 * setupRequired / authenticated / path leads, and that the post-login returnTo is a same-site path.
 */
const g = globalThis as Record<string, unknown>;
vi.hoisted(() => { (globalThis as Record<string, unknown>).defineNuxtRouteMiddleware = (fn: unknown) => fn; });

const info = (o: Partial<SessionInfo>): SessionInfo => ({ setupRequired: false, authenticated: false, csrfToken: "t", registrationMode: "dynamic", baseUrl: "http://x", ...o });
let session: { info: { value: SessionInfo | null }; refresh: ReturnType<typeof vi.fn> };
const navigateTo = vi.fn((to: unknown, opts?: unknown) => ({ navigateTo: to, opts }));
const abortNavigation = vi.fn((e: unknown) => ({ aborted: e }));
const createError = vi.fn((e: unknown) => e);

beforeEach(() => {
  session = { info: { value: null }, refresh: vi.fn() };
  navigateTo.mockClear();
  abortNavigation.mockClear();
  g.useSessionState = () => session;
  g.navigateTo = navigateTo;
  g.abortNavigation = abortNavigation;
  g.createError = createError;
  g.safeReturnTo = safeReturnTo;
});

const middleware = (await import("../../app/middleware/auth.global")).default as unknown as (to: any) => Promise<any>;
const route = (path: string, query: Record<string, string> = {}) => {
  const qs = new URLSearchParams(query).toString();
  return { path, query, fullPath: qs ? `${path}?${qs}` : path };
};
const withSession = (i: SessionInfo) => { session.info.value = i; };

describe("auth.global middleware", () => {
  it("loads the session once when it is not loaded yet, and not again when it is", async () => {
    session.refresh.mockImplementation(async () => { session.info.value = info({ authenticated: true }); });
    await middleware(route("/dashboard"));
    await middleware(route("/audit"));
    expect(session.refresh).toHaveBeenCalledTimes(1);
  });

  it("aborts with a 503 when the session cannot be loaded (fail closed, no redirect loop)", async () => {
    session.refresh.mockRejectedValue(new Error("down"));
    const r = await middleware(route("/dashboard"));
    expect(r).toHaveProperty("aborted");
    expect(createError).toHaveBeenCalledWith(expect.objectContaining({ statusCode: 503, fatal: true }));
    expect(navigateTo).not.toHaveBeenCalled();
  });

  it("setup required: everything goes to /setup, /setup stays", async () => {
    withSession(info({ setupRequired: true }));
    for (const p of ["/dashboard", "/login", "/", "/oauth/authorize", "/audit"]) {
      navigateTo.mockClear();
      await middleware(route(p));
      expect(navigateTo).toHaveBeenCalledWith("/setup", { replace: true });
    }
    navigateTo.mockClear();
    expect(await middleware(route("/setup"))).toBeUndefined();
    expect(navigateTo).not.toHaveBeenCalled();
  });

  it("signed out: protected pages go to /login with the page as returnTo (query kept), /login stays", async () => {
    withSession(info({}));
    await middleware(route("/audit", { outcome: "denied" }));
    expect(navigateTo).toHaveBeenLastCalledWith({ path: "/login", query: { returnTo: "/audit?outcome=denied" } }, { replace: true });
    await middleware(route("/oauth/authorize", { client_id: "c", state: "s" }));
    expect(navigateTo).toHaveBeenLastCalledWith({ path: "/login", query: { returnTo: "/oauth/authorize?client_id=c&state=s" } }, { replace: true });
    await middleware(route("/mailboxes/abc"));
    expect(navigateTo).toHaveBeenLastCalledWith({ path: "/login", query: { returnTo: "/mailboxes/abc" } }, { replace: true });
    navigateTo.mockClear();
    expect(await middleware(route("/login"))).toBeUndefined();
    expect(navigateTo).not.toHaveBeenCalled();
  });

  it("signed out: / and /setup (gone once an admin exists) go to a bare /login without returnTo", async () => {
    withSession(info({}));
    for (const p of ["/", "/setup"]) {
      await middleware(route(p));
      expect(navigateTo).toHaveBeenLastCalledWith({ path: "/login" }, { replace: true });
    }
  });

  it("signed in: /login and /setup lead to /dashboard, or to a same-site returnTo", async () => {
    withSession(info({ authenticated: true }));
    await middleware(route("/login"));
    expect(navigateTo).toHaveBeenLastCalledWith("/dashboard", { replace: true });
    await middleware(route("/setup"));
    expect(navigateTo).toHaveBeenLastCalledWith("/dashboard", { replace: true });
    await middleware(route("/login", { returnTo: "/oauth/authorize?client_id=c" }));
    expect(navigateTo).toHaveBeenLastCalledWith("/oauth/authorize?client_id=c", { replace: true });
  });

  it.each(["//evil.example", "https://evil.example/", "/\\evil.example", "javascript:alert(1)", "/login", "/setup", "dashboard", ""])(
    "signed in: the unsafe returnTo %j is ignored",
    async (bad) => {
      withSession(info({ authenticated: true }));
      await middleware(route("/login", { returnTo: bad }));
      expect(navigateTo).toHaveBeenLastCalledWith("/dashboard", { replace: true });
    },
  );

  it("signed in: ordinary pages are left alone", async () => {
    withSession(info({ authenticated: true }));
    for (const p of ["/dashboard", "/audit", "/mailboxes/new", "/oauth/authorize"]) expect(await middleware(route(p))).toBeUndefined();
    expect(navigateTo).not.toHaveBeenCalled();
  });
});
