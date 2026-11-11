/** Sign out: POST /api/logout, drop the session snapshot, load the fresh (signed-out) one, go to /login. */
export function useSignOut() {
  const api = useApi();
  const session = useSessionState();
  const signingOut = ref(false);

  async function signOut() {
    if (signingOut.value) return;
    signingOut.value = true;
    try {
      await api.post("/logout");
    } catch {
      // Even if the call failed, drop the local state: the next API call re-checks the session.
    }
    try {
      session.info.value = null;
      await session.refresh();
    } catch { /* middleware reports an unreachable server */ }
    await navigateTo("/login", { replace: true });
    signingOut.value = false;
  }

  return { signOut, signingOut };
}
