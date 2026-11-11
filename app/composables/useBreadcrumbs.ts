import type { MaybeRefOrGetter } from "vue";

export interface Crumb { label: string; to?: string }

/**
 * Breadcrumbs shown in the app shell's top bar. Call from a page's setup with a static array,
 * a ref or a getter (so labels can depend on loaded data). Cleared when the page unmounts,
 * unless the next page has already set its own.
 */
export function useBreadcrumbs(crumbs: MaybeRefOrGetter<Crumb[]>) {
  const state = useState<Crumb[]>("imap2mcp:crumbs", () => []);
  let mine: Crumb[] | null = null;
  watchEffect(() => { mine = [...toValue(crumbs)]; state.value = mine; });
  onBeforeUnmount(() => { if (toRaw(state.value) === mine) state.value = []; });
}

/** Layout side: the current breadcrumbs. */
export function useCrumbState() {
  return useState<Crumb[]>("imap2mcp:crumbs", () => []);
}
