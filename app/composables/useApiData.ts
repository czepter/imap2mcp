import type { WatchSource } from "vue";

/**
 * Loads data through the API with explicit states (no SSR, no payload cache), so pages can render
 * skeletons while `pending` and an error Alert from `error`.
 * `refresh()` reloads quietly (keeps the current data visible, no skeleton flash).
 */
export function useApiData<T>(fetcher: () => Promise<T>, opts: { watch?: WatchSource[] } = {}) {
  const data = shallowRef<T | null>(null);
  const error = shallowRef<ApiError | null>(null);
  const pending = ref(true);
  let seq = 0;

  async function load(quiet: boolean) {
    const mine = ++seq;
    if (!quiet) pending.value = true;
    try {
      const result = await fetcher();
      if (mine !== seq) return;
      data.value = result;
      error.value = null;
    } catch (e) {
      if (mine !== seq) return;
      error.value = e instanceof ApiError ? e : new ApiError(0, "error", e instanceof Error ? e.message : "Unexpected error");
    } finally {
      if (mine === seq) pending.value = false;
    }
  }

  onMounted(() => load(false));
  onBeforeUnmount(() => { seq++; });
  if (opts.watch?.length) watch(opts.watch, () => load(false));

  return {
    data,
    error,
    pending,
    /** Reload. Pass `{ quiet: false }` to show the loading state again. */
    refresh: (o: { quiet?: boolean } = {}) => load(o.quiet ?? true),
  };
}
