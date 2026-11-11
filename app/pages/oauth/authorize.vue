<script setup lang="ts">
import { ApiError } from "~/composables/useApi";
import type { AuthorizeDecision, AuthorizeRedirect, AuthorizeRequest, GrantsUpdate } from "~~/shared/types/api";

definePageMeta({ layout: { name: "auth", props: { wide: true } } });
useHead({ title: "Authorize" });

const route = useRoute();
const api = useApi();

type Phase = "loading" | "ready" | "error" | "redirecting" | "done";
const phase = ref<Phase>("loading");
const request = ref<AuthorizeRequest | null>(null);
const loadError = ref("");
const submitError = ref("");
const busy = ref(false);

/** The OAuth request parameters, exactly as received; the server validates and normalises them. */
const OAUTH_PARAMS = ["client_id", "redirect_uri", "state", "response_type", "code_challenge", "code_challenge_method", "resource", "scope"];
function oauthQuery(): Record<string, string> {
  const q: Record<string, string> = {};
  for (const k of OAUTH_PARAMS) {
    const v = route.query[k];
    const s = Array.isArray(v) ? v[0] : v;
    if (typeof s === "string") q[k] = s;
  }
  return q;
}

/** Only ever navigate to an absolute http(s) URL (the client's registered redirect URI). */
function go(redirectTo: unknown): boolean {
  if (typeof redirectTo !== "string") return false;
  let u: URL;
  try { u = new URL(redirectTo); } catch { return false; }
  if (u.protocol !== "https:" && u.protocol !== "http:") return false;
  window.location.assign(u.toString());
  return true;
}

const isRedirect = (r: AuthorizeRequest | AuthorizeRedirect): r is AuthorizeRedirect => "redirectTo" in r;

async function load() {
  phase.value = "loading";
  loadError.value = "";
  try {
    const res = await api.get<AuthorizeRequest | AuthorizeRedirect>("/oauth/authorize", { query: oauthQuery() });
    if (isRedirect(res)) {
      // A protocol error the client must hear about (e.g. unsupported response_type): back to the client, as before.
      if (go(res.redirectTo)) phase.value = "redirecting";
      else { loadError.value = "The authorization server returned an invalid redirect."; phase.value = "error"; }
      return;
    }
    request.value = res;
    phase.value = "ready";
    await nextTick();
    document.getElementById("consent-title")?.focus();
  } catch (e) {
    loadError.value = e instanceof ApiError ? e.message : "Could not load this authorization request.";
    phase.value = "error";
  }
}

async function decide(decision: "approve" | "deny", grants: GrantsUpdate["grants"]) {
  const r = request.value;
  if (!r || busy.value) return;
  submitError.value = "";
  busy.value = true;
  try {
    const res = await api.post<AuthorizeRedirect>("/oauth/authorize", {
      params: r.params, decision, grants,
    } satisfies AuthorizeDecision);
    if (go(res?.redirectTo)) {
      phase.value = "redirecting"; // stay busy: the browser is leaving this page
      return;
    }
    submitError.value = "The authorization server returned an invalid redirect.";
  } catch (e) {
    submitError.value = e instanceof ApiError ? e.message : "Could not send your decision.";
  }
  busy.value = false;
}

// Coming back here with the back button after the decision: the code was already issued, so the request is spent.
function onPageShow(ev: PageTransitionEvent) {
  if (ev.persisted && phase.value === "redirecting") { phase.value = "done"; busy.value = false; }
}
onMounted(() => {
  window.addEventListener("pageshow", onPageShow);
  load();
});
onBeforeUnmount(() => window.removeEventListener("pageshow", onPageShow));
</script>

<template>
  <div>
    <div v-if="phase === 'loading'" class="grid gap-4" role="status" aria-busy="true">
      <span class="sr-only">Loading authorization request…</span>
      <Skeleton class="h-7 w-3/4" />
      <Skeleton class="h-14 w-full" />
      <Skeleton class="h-32 w-full" />
      <Skeleton class="h-9 w-full" />
    </div>

    <div v-else-if="phase === 'error'" class="grid gap-3.5">
      <h1>Authorization error</h1>
      <ErrorAlert :error="loadError" />
    </div>

    <div v-else-if="phase === 'done'" class="grid gap-3.5">
      <h1>Authorization already answered</h1>
      <p class="text-muted-foreground">
        Your decision was sent to the application. You can close this tab and return to it. To start over, begin the sign-in again from the application.
      </p>
    </div>

    <template v-else-if="request">
      <ConsentRequestPanel :request="request" :busy="busy || phase === 'redirecting'" :error="submitError" @decide="decide" />
      <p v-if="phase === 'redirecting'" role="status" class="text-muted-foreground mt-3 text-[13px]">Returning to the application…</p>
    </template>

    <p v-else-if="phase === 'redirecting'" role="status" class="text-muted-foreground text-[13px]">Returning to the application…</p>
  </div>
</template>
