import type { Overview } from "~~/shared/types/api";

/** The overview payload every list page (Overview, Mailboxes, Clients, Tokens) is built from. */
export function useOverview() {
  const api = useApi();
  const state = useApiData(() => api.get<Overview>("/overview"));
  const mailboxes = computed(() => state.data.value?.mailboxes ?? []);
  const clients = computed(() => state.data.value?.clients ?? []);
  const tokens = computed(() => state.data.value?.tokens ?? []);
  const adminMode = computed(() => state.data.value?.registrationMode === "admin");
  const noDrafts = computed(() => mailboxes.value.filter((m) => !m.draftsFolder));
  return { ...state, mailboxes, clients, tokens, adminMode, noDrafts };
}
