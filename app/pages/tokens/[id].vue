<script setup lang="ts">
import { toast } from "vue-sonner";
import { ApiError } from "~/composables/useApi";
import type { Capability, GrantsUpdate, TokenDetail, TokenUpdate } from "~~/shared/types/api";

type Grant = GrantsUpdate["grants"][number];

const route = useRoute();
const api = useApi();
const id = computed(() => String(route.params.id));
const base = computed(() => `/tokens/${encodeURIComponent(id.value)}`);

const CAPABILITIES: Capability[] = ["read", "draft", "organize"];
const HELP: Record<Capability, string> = {
  read: "List folders, search, read messages",
  draft: "Create drafts in the mailbox's Drafts folder only",
  organize: "Move messages and set flags within one mailbox. No delete.",
};

const detail = ref<TokenDetail | null>(null);
const loading = ref(true);
const notFound = ref(false);
const loadError = ref("");
let loadSeq = 0;

const caps = ref<Capability[]>([]);
const draft = ref<Grant[]>([]);
const key = (g: Grant) => `${g.mailboxId}|${g.capability}`;
const fromDetail = (d: TokenDetail): Grant[] =>
  d.mailboxes.flatMap((m) => CAPABILITIES.filter((c) => m.granted[c]).map((capability) => ({ mailboxId: m.id, capability })));
const sorted = (c: readonly Capability[]) => CAPABILITIES.filter((x) => c.includes(x));

function adopt(d: TokenDetail) {
  detail.value = d;
  caps.value = sorted(d.token.scopes);
  draft.value = fromDetail(d);
}

async function load() {
  const seq = ++loadSeq;
  try {
    const d = await api.get<TokenDetail>(base.value);
    if (seq !== loadSeq) return;
    adopt(d);
    notFound.value = false;
    loadError.value = "";
  } catch (e) {
    if (seq !== loadSeq) return;
    if (e instanceof ApiError && e.status === 404) { notFound.value = true; detail.value = null; }
    else loadError.value = e instanceof ApiError ? e.message : "Could not load this token.";
  } finally {
    if (seq === loadSeq) loading.value = false;
  }
}

watch(id, () => { loading.value = true; detail.value = null; notFound.value = false; loadError.value = ""; load(); }, { immediate: true });

const name = computed(() => detail.value?.token.clientName || "Token");
useHead({ title: computed(() => (detail.value ? `${name.value} token` : "Token")) });
useBreadcrumbs(() => [{ label: "Tokens", to: "/tokens" }, { label: detail.value ? name.value : "Token" }]);

const plural = (n: number, w: string) => `${n} ${w}${n === 1 ? "" : "s"}`;

// ---- unsaved changes against the server state
const grantChanges = computed(() => {
  if (!detail.value) return [] as { grant: Grant; on: boolean }[];
  const saved = new Set(fromDetail(detail.value).map(key));
  const wanted = new Set(draft.value.map(key));
  return [
    ...draft.value.filter((g) => !saved.has(key(g))).map((grant) => ({ grant, on: true })),
    ...fromDetail(detail.value).filter((g) => !wanted.has(key(g))).map((grant) => ({ grant, on: false })),
  ];
});
const capChanged = computed(() => !!detail.value && sorted(caps.value).join() !== sorted(detail.value.token.scopes).join());
const changeCount = computed(() => grantChanges.value.length + (capChanged.value ? 1 : 0));

// A ticked grant the ceiling does not cover raises the ceiling, so ticking a new mailbox just works.
function onGrants(v: Grant[]) {
  draft.value = v;
  const missing = v.map((g) => g.capability).filter((c) => !caps.value.includes(c));
  if (missing.length) caps.value = sorted([...caps.value, ...missing]);
}
function setCap(c: Capability, on: boolean) {
  caps.value = sorted(on ? [...caps.value, c] : caps.value.filter((x) => x !== c));
}

const mailboxLabel = (mailboxId: string) => detail.value?.mailboxes.find((m) => m.id === mailboxId)?.label ?? mailboxId;
const consequence = computed(() => {
  const first = grantChanges.value.find((c) => c.on);
  if (first) return `${first.grant.capability} on ${mailboxLabel(first.grant.mailboxId)} will be reachable with this token.`;
  const gone = grantChanges.value[0];
  if (gone) return `Removing ${gone.grant.capability} on ${mailboxLabel(gone.grant.mailboxId)} applies on the next call.`;
  return "The new ceiling applies on the next call.";
});
const noCaps = computed(() => caps.value.length === 0);

const saving = ref(false);
const saveError = ref("");
async function save() {
  if (noCaps.value) return;
  saveError.value = "";
  saving.value = true;
  try {
    const d = await api.patch<TokenDetail>(base.value, { capabilities: caps.value, grants: draft.value } satisfies TokenUpdate);
    adopt(d);
    toast.success("Token updated.");
  } catch (e) {
    saveError.value = e instanceof ApiError ? e.message : "Could not save the token.";
  } finally {
    saving.value = false;
  }
}
function discard() {
  if (detail.value) adopt(detail.value);
  saveError.value = "";
}

// ---- revoke
const revokeOpen = ref(false);
const revoking = ref(false);
const revokeError = ref("");
watch(revokeOpen, () => { revokeError.value = ""; });
async function revoke() {
  revoking.value = true;
  revokeError.value = "";
  try {
    await api.post(`${base.value}/revoke`);
    toast.success("Token revoked.");
    revokeOpen.value = false;
    await navigateTo("/tokens");
  } catch (e) {
    revokeError.value = e instanceof ApiError ? e.message : "Could not revoke the token.";
  } finally {
    revoking.value = false;
  }
}
</script>

<template>
  <div>
    <div v-if="loading" class="grid gap-5" aria-busy="true">
      <span class="sr-only" role="status">Loading token…</span>
      <div class="mb-1 grid gap-2">
        <Skeleton class="h-7 w-56" />
        <Skeleton class="h-4 w-96 max-w-full" />
      </div>
      <section v-for="n in 2" :key="n" class="bg-card overflow-hidden rounded-xl border">
        <div class="border-b px-[18px] py-3.5"><Skeleton class="h-6 w-40" /></div>
        <TableSkeleton :rows="3" :cols="4" />
      </section>
    </div>

    <template v-else-if="notFound">
      <PageHeader title="Token not found" description="This token does not exist, was revoked, or has expired.">
        <Button as-child variant="outline"><NuxtLink to="/tokens">Back to the tokens</NuxtLink></Button>
      </PageHeader>
    </template>

    <ErrorAlert v-else-if="loadError && !detail" :error="loadError" title="Could not load this token">
      <template #actions>
        <Button variant="outline" size="sm" @click="loading = true; load()">Try again</Button>
      </template>
    </ErrorAlert>

    <template v-else-if="detail">
      <PageHeader :title="`${name} token`">
        <template #description>
          <span class="text-[13px]">
            Client <NuxtLink :to="`/clients/${encodeURIComponent(detail.client.clientId)}`" class="underline">{{ name }}</NuxtLink>
            &middot; issued {{ formatIssued(detail.token.createdAt) }} &middot; {{ detail.token.kind === "api" ? "API token" : "access token" }} expires {{ formatExpires(detail.token.expiresAt) }}
          </span>
        </template>
        <Button variant="outline" class="btn-d" @click="revokeOpen = true">Revoke token</Button>
      </PageHeader>

      <form class="grid gap-5" @submit.prevent="save">
        <ErrorAlert :error="saveError" />

        <SectionCard id="capabilities" title="Capabilities">
          <template #aside><span>The most this token may do on any mailbox.</span></template>
          <Table>
            <caption class="sr-only">Capabilities of this token</caption>
            <TableBody>
              <TableRow v-for="c in CAPABILITIES" :key="c">
                <TableCell class="w-12">
                  <Checkbox
                    :model-value="caps.includes(c)"
                    :disabled="saving"
                    :aria-label="`Allow ${c} for this token`"
                    @update:model-value="(v: boolean | 'indeterminate') => setCap(c, v === true)"
                  />
                </TableCell>
                <TableCell><CapabilityBadge :capability="c" /></TableCell>
                <TableCell>{{ HELP[c] }}</TableCell>
              </TableRow>
            </TableBody>
          </Table>
          <p v-if="noCaps" class="text-destructive px-[18px] pb-3 text-[13px]">
            A token needs at least one capability. Revoke it instead to remove all access.
          </p>
        </SectionCard>

        <SectionCard id="mailboxes" title="Mailboxes">
          <template #aside><span>Nothing ticked means no access.</span></template>
          <template v-if="detail.mailboxes.length">
            <p class="text-muted-foreground px-[18px] pt-[18px] text-[13px]">
              Grants belong to {{ name }}, so they apply to all of its tokens<template v-if="detail.otherActiveTokenCount > 0"> ({{ plural(detail.otherActiveTokenCount, "other active token") }} will change too)</template>.
              Ticking a capability this token does not have yet adds it to the ceiling above.
            </p>
            <div class="mt-3">
              <ClientsGrantsMatrix :model-value="draft" :mailboxes="detail.mailboxes" :capabilities="CAPABILITIES" :subject="name" :disabled="saving" @update:model-value="onGrants" />
            </div>
          </template>
          <EmptyState v-else title="No mailboxes configured." />
        </SectionCard>

        <div v-if="changeCount" class="confirm warn" role="group" aria-label="Unsaved token changes">
          <span class="min-w-0 flex-1 basis-64">
            <b>{{ plural(changeCount, "unsaved change") }}.</b> {{ consequence }}
          </span>
          <span class="flex items-center gap-2.5">
            <Button type="button" variant="outline" size="sm" :disabled="saving" @click="discard">Discard</Button>
            <Button type="submit" size="sm" :disabled="saving || noCaps" :aria-busy="saving">{{ saving ? "Saving…" : "Save changes" }}</Button>
          </span>
        </div>
      </form>

      <ConfirmDialog
        v-model:open="revokeOpen"
        :title="`Revoke ${name}'s token?`"
        :description="detail.token.kind === 'api' ? 'This takes effect at the next call. Anything using the token stops working; you cannot restore it.' : 'This takes effect at the next call. The client can ask you to authorize again.'"
        confirm-label="Revoke token"
        destructive
        :pending="revoking"
        :error="revokeError"
        @confirm="revoke"
      />
    </template>
  </div>
</template>
