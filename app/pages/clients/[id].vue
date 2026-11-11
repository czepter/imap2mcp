<script setup lang="ts">
import type { Ref } from "vue";
import { toast } from "vue-sonner";
import { ApiError } from "~/composables/useApi";
import type { Capability, ClientDetail, GrantsUpdate } from "~~/shared/types/api";

type Grant = GrantsUpdate["grants"][number];

const route = useRoute();
const api = useApi();
const id = computed(() => String(route.params.id));
const base = computed(() => `/clients/${encodeURIComponent(id.value)}`);

const CAPABILITIES: Capability[] = ["read", "draft", "organize"];

const detail = ref<ClientDetail | null>(null);
const loading = ref(true);
const notFound = ref(false);
const loadError = ref("");
let loadSeq = 0;

const draft = ref<Grant[]>([]);
const key = (g: Grant) => `${g.mailboxId}|${g.capability}`;
const fromDetail = (d: ClientDetail): Grant[] =>
  d.mailboxes.flatMap((m) => CAPABILITIES.filter((c) => m.granted[c]).map((capability) => ({ mailboxId: m.id, capability })));

/** keepDraft: refresh server state but do not discard grant edits the user has not saved yet. */
async function load(opts: { keepDraft?: boolean } = {}) {
  const seq = ++loadSeq;
  try {
    const d = await api.get<ClientDetail>(base.value);
    if (seq !== loadSeq) return;
    const hadEdits = changes.value.length > 0;
    detail.value = d;
    if (!(opts.keepDraft && hadEdits)) draft.value = fromDetail(d);
    notFound.value = false;
    loadError.value = "";
  } catch (e) {
    if (seq !== loadSeq) return;
    if (e instanceof ApiError && e.status === 404) { notFound.value = true; detail.value = null; }
    else loadError.value = e instanceof ApiError ? e.message : "Could not load this client.";
  } finally {
    if (seq === loadSeq) loading.value = false;
  }
}

watch(id, () => { loading.value = true; detail.value = null; notFound.value = false; loadError.value = ""; load(); }, { immediate: true });

const name = computed(() => detail.value?.client.clientName || "(unnamed)");
useHead({ title: computed(() => (detail.value ? `${name.value} · Client` : "Client")) });
useBreadcrumbs(() => [{ label: "Clients", to: "/dashboard#clients" }, { label: detail.value ? name.value : "Client" }]);

const plural = (n: number, w: string) => `${n} ${w}${n === 1 ? "" : "s"}`;

// ---- grants: unsaved changes against the server state
const changes = computed(() => {
  if (!detail.value) return [] as { grant: Grant; on: boolean }[];
  const saved = new Set(fromDetail(detail.value).map(key));
  const wanted = new Set(draft.value.map(key));
  return [
    ...draft.value.filter((g) => !saved.has(key(g))).map((grant) => ({ grant, on: true })),
    ...fromDetail(detail.value).filter((g) => !wanted.has(key(g))).map((grant) => ({ grant, on: false })),
  ];
});
const mailboxLabel = (mailboxId: string) => detail.value?.mailboxes.find((m) => m.id === mailboxId)?.label ?? mailboxId;
const WHAT: Record<Capability, string> = { read: "search and read mail", draft: "write drafts", organize: "move mail and set flags" };
const consequence = computed(() => {
  const first = changes.value.find((c) => c.on);
  if (first) {
    const cap = first.grant.capability;
    return `${cap[0]!.toUpperCase()}${cap.slice(1)} on ${mailboxLabel(first.grant.mailboxId)} will let ${name.value} ${WHAT[cap]}.`;
  }
  const gone = changes.value[0];
  return gone ? `Removing ${gone.grant.capability} on ${mailboxLabel(gone.grant.mailboxId)} applies on the next call.` : "";
});

const saving = ref(false);
const grantsError = ref("");
const grantsStatus = ref("");
watch(changes, (c) => { if (c.length) grantsStatus.value = ""; });

async function saveGrants() {
  grantsError.value = "";
  grantsStatus.value = "";
  saving.value = true;
  try {
    await api.put(`${base.value}/grants`, { grants: draft.value } satisfies GrantsUpdate);
    await load();
    grantsStatus.value = "Grants saved.";
    toast.success("Grants saved.");
  } catch (e) {
    grantsError.value = e instanceof ApiError ? e.message : "Could not save the grants.";
  } finally {
    saving.value = false;
  }
}
function discard() {
  if (detail.value) draft.value = fromDetail(detail.value);
  grantsError.value = "";
}

// ---- enable / disable / revoke
const actionError = ref("");
const disableOpen = ref(false);
const revokeOpen = ref(false);
const enabling = ref(false);
const pending = ref(false);
const dialogError = ref("");

/** Returns true on success. */
async function run(path: string, success: string): Promise<boolean> {
  try {
    await api.post(`${base.value}/${path}`);
    toast.success(success);
    await load({ keepDraft: true });
    return true;
  } catch (e) {
    const msg = e instanceof ApiError ? e.message : "The action failed.";
    actionError.value = msg;
    dialogError.value = msg;
    return false;
  }
}
async function enable() {
  actionError.value = "";
  enabling.value = true;
  try { await run("enable", "Client enabled."); } finally { enabling.value = false; }
}
async function confirmed(path: string, success: string, open: Ref<boolean>) {
  actionError.value = "";
  dialogError.value = "";
  pending.value = true;
  try {
    if (await run(path, success)) open.value = false;
  } finally { pending.value = false; }
}
const disable = () => confirmed("disable", "Client disabled and its tokens revoked.", disableOpen);
const revoke = () => confirmed("revoke", "All rules removed and tokens revoked. IMAP credentials are unchanged.", revokeOpen);
watch([disableOpen, revokeOpen], () => { dialogError.value = ""; });
</script>

<template>
  <div>
    <!-- loading -->
    <div v-if="loading" class="grid gap-5" aria-busy="true">
      <span class="sr-only" role="status">Loading client…</span>
      <div class="mb-1 grid gap-2">
        <Skeleton class="h-7 w-56" />
        <Skeleton class="h-4 w-96 max-w-full" />
      </div>
      <section v-for="n in 2" :key="n" class="bg-card overflow-hidden rounded-xl border">
        <div class="border-b px-[18px] py-3.5"><Skeleton class="h-6 w-40" /></div>
        <TableSkeleton :rows="3" :cols="4" />
      </section>
    </div>

    <!-- 404 -->
    <template v-else-if="notFound">
      <PageHeader title="Client not found" description="This client does not exist, or it was removed.">
        <Button as-child variant="outline"><NuxtLink to="/dashboard">Back to the dashboard</NuxtLink></Button>
      </PageHeader>
    </template>

    <!-- load failure -->
    <ErrorAlert v-else-if="loadError && !detail" :error="loadError" title="Could not load this client">
      <template #actions>
        <Button variant="outline" size="sm" @click="loading = true; load()">Try again</Button>
      </template>
    </ErrorAlert>

    <template v-else-if="detail">
      <PageHeader :title="name">
        <template #description>
          <span class="font-mono text-xs">
            <span class="break-all">{{ detail.client.clientId }}</span> &middot; registered
            <time :datetime="detail.client.createdAt">{{ formatWhen(detail.client.createdAt) }}</time> &middot;
            <Pill :tone="detail.client.disabled ? 'off' : 'ok'" class="font-sans">{{ detail.client.disabled ? "disabled" : "active" }}</Pill>
          </span>
        </template>
        <Button v-if="detail.client.disabled" :disabled="enabling" @click="enable">
          {{ enabling ? "Enabling…" : "Enable client" }}
        </Button>
        <Button v-else variant="outline" class="btn-d" @click="disableOpen = true">Disable client</Button>
      </PageHeader>

      <div class="grid gap-5">
        <ErrorAlert :error="actionError" />
        <Notice v-if="detail.client.disabled" kind="warn">
          This client is disabled. Its tokens are revoked and it cannot authorize again until you enable it. Grants are kept.
        </Notice>

        <!-- Grants -->
        <SectionCard id="grants" title="Grants">
          <template #aside><span>Nothing ticked means no access.</span></template>
          <template v-if="detail.mailboxes.length">
            <form @submit.prevent="saveGrants">
              <p class="text-muted-foreground px-[18px] pt-[18px] text-[13px]">
                Removing a grant applies on the next call, even for tokens already issued. Adding a capability the token
                was not authorized for needs a new authorization.
              </p>
              <div v-if="grantsError || grantsStatus" class="px-[18px] pt-3">
                <ErrorAlert :error="grantsError" />
                <Notice v-if="grantsStatus && !grantsError" kind="ok">{{ grantsStatus }}</Notice>
              </div>
              <div class="mt-3">
                <ClientsGrantsMatrix v-model="draft" :mailboxes="detail.mailboxes" :capabilities="CAPABILITIES" :subject="name" :disabled="saving" />
              </div>
              <div v-if="changes.length" class="confirm warn" role="group" aria-label="Unsaved grant changes">
                <span class="min-w-0 flex-1 basis-64">
                  <b>{{ plural(changes.length, "unsaved change") }}.</b> {{ consequence }}
                </span>
                <span class="flex items-center gap-2.5">
                  <Button type="button" variant="outline" size="sm" :disabled="saving" @click="discard">Discard</Button>
                  <Button type="submit" size="sm" :disabled="saving" :aria-busy="saving">{{ saving ? "Saving…" : "Save grants" }}</Button>
                </span>
              </div>
            </form>
          </template>
          <EmptyState v-else title="No mailboxes configured." />
        </SectionCard>

        <ClientsRulesCard :client-id="detail.client.clientId" :detail="detail" @changed="load({ keepDraft: true })" />

        <!-- Capability help -->
        <SectionCard id="caps" title="What each capability allows">
          <Table>
            <caption class="sr-only">What each capability allows</caption>
            <TableBody>
              <TableRow v-for="c in CAPABILITIES" :key="c">
                <TableCell><CapabilityBadge :capability="c" /></TableCell>
                <TableCell>{{ detail.help.capabilities[c] }}</TableCell>
              </TableRow>
            </TableBody>
          </Table>
        </SectionCard>

        <!-- Redirect URIs -->
        <SectionCard id="uris" title="Redirect URIs" padded>
          <ul class="grid gap-1 font-mono text-xs break-all">
            <li v-for="u in detail.client.redirectUris" :key="u">{{ u }}</li>
          </ul>
        </SectionCard>

        <!-- Danger zone -->
        <SectionCard id="revoke" title="Revoke client" danger padded>
          <p>Removes every rule and revokes all tokens. IMAP credentials are not changed.</p>
          <Button variant="destructive" class="mt-3.5" @click="revokeOpen = true">Revoke client</Button>
        </SectionCard>
      </div>

      <ConfirmDialog
        v-model:open="disableOpen"
        :title="`Disable ${name}?`"
        :description="`This takes effect immediately. ${plural(detail.activeTokenCount, 'active token')} will be revoked and the client cannot authorize again until you enable it. Grants are kept.`"
        confirm-label="Disable client"
        destructive
        :pending="pending"
        :error="dialogError"
        @confirm="disable"
      />
      <ConfirmDialog
        v-model:open="revokeOpen"
        :title="`Revoke ${name}?`"
        :description="`This removes every rule and revokes ${plural(detail.activeTokenCount, 'active token')}. The client keeps its registration and can ask for access again. IMAP credentials are not changed.`"
        confirm-label="Revoke client"
        destructive
        :pending="pending"
        :error="dialogError"
        @confirm="revoke"
      />
    </template>
  </div>
</template>
