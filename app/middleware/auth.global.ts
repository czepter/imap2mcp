export default defineNuxtRouteMiddleware(async (to) => {
  const session = useSessionState();
  if (!session.info.value) {
    try {
      await session.refresh();
    } catch {
      return abortNavigation(createError({
        statusCode: 503,
        statusMessage: "Server unreachable",
        message: "Could not load the session from the server.",
        fatal: true,
      }));
    }
  }
  const info = session.info.value!;

  if (info.setupRequired) {
    return to.path === "/setup" ? undefined : navigateTo("/setup", { replace: true });
  }
  if (!info.authenticated) {
    if (to.path === "/login") return;
    // /setup is gone once an admin exists. Every other page requires a session, /oauth/authorize included.
    const returnTo = to.path === "/setup" || to.path === "/" ? undefined : to.fullPath;
    return navigateTo(returnTo ? { path: "/login", query: { returnTo } } : { path: "/login" }, { replace: true });
  }
  if (to.path === "/login" || to.path === "/setup") {
    return navigateTo(safeReturnTo(to.query.returnTo) ?? "/dashboard", { replace: true });
  }
});
