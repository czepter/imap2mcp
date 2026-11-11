<script setup lang="ts">
import { LoaderCircle } from "@lucide/vue";
import { toast } from "vue-sonner";
import type { Capability, Overview, TokenSummary } from "~~/shared/types/api";

useHead({ title: "Overview" });

const api = useApi();
const { data, error, pending, refresh } = useApiData(() => api.get<Overview>("/overview"));

const mailboxes = computed(() => data.value?.mailboxes ?? []);
const clients = computed(() => data.value?.clients ?? []);
const tokens = computed(() => data.value?.tokens ?? []);
const adminMode = computed(() => data.value?.registrationMode === "admin");

/** `${clientId}:${mailboxId}` -> capabilities held through grants. */
const granted = computed(() => {
  const map = new Map<string, Capability[]>();
  for (const g of data.value?.grants ?? []) {
    const k = `${g.clientId}:${g.mailboxId}`;
    map.set(k, [...(map.get(k) ?? []), g.capability]);
  }
  return map;
});

const noDrafts = computed(() => mailboxes.value.filter((m) => !m.draftsFolder));

// ---- enable a disabled client ----
const enablingId = ref<string | null>(null);
async function enableClient(clientId: string) {
  enablingId.value = clientId;
  try {
    await api.post(`/clients/${encodeURIComponent(clientId)}/enable`);
    toast.success("Client enabled.");
    await refresh();
  } catch (e) {
    toast.error(e instanceof ApiError ? e.message : "Could not enable the client.");
  } finally {
    enablingId.value = null;
  }
}

// ---- revoke a token: inline confirmation band under the row (design), one open at a time ----
const confirmingId = ref<string | null>(null);
const revoking = ref(false);
const revokeError = ref("");
function toggleRevoke(t: TokenSummary) {
  revokeError.value = "";
  confirmingId.value = confirmingId.value === t.id ? null : t.id;
}
function revokeText(t: TokenSummary): string {
  const name = t.clientName || t.clientId;
  if (!t.reach.length) return ` ${name} has no access left through this token; revoking removes it. It can ask you to authorize again.`;
  const parts = t.reach.map((r) => `${joinList(sortCapabilities(r.capabilities))} on ${r.mailboxLabel}`);
  return ` ${name} loses ${joinList(parts)} right now. It can ask you to authorize again.`;
}
async function revokeToken(t: TokenSummary) {
  revoking.value = true;
  revokeError.value = "";
  try {
    await api.post(`/tokens/${encodeURIComponent(t.id)}/revoke`);
    confirmingId.value = null;
    toast.success("Token revoked.");
    await refresh();
  } catch (e) {
    revokeError.value = e instanceof ApiError ? e.message : "Could not revoke the token.";
  } finally {
    revoking.value = false;
  }
}
</script>

<template>
  <div>
    <PageHeader title="Overview" description="Who can reach which mailbox, and how." />

    <div v-if="error && !data">
      <ErrorAlert :error="error" title="Could not load the overview">
        <template #actions>
          <Button variant="outline" size="sm" @click="refresh({ quiet: false })">Try again</Button>
        </template>
      </ErrorAlert>
    </div>

    <div v-else-if="pending && !data" class="grid gap-5" aria-busy="true">
      <section v-for="s in [{ id: 'clients', cols: 4 }, { id: 'mailboxes', cols: 6 }, { id: 'tokens', cols: 4 }]" :id="s.id" :key="s.id" class="bg-card overflow-hidden rounded-xl border">
        <div class="border-b px-[18px] py-3.5"><Skeleton class="h-6 w-40" /></div>
        <TableSkeleton :rows="3" :cols="s.cols" />
      </section>
    </div>

    <div v-else-if="data" class="grid gap-5">
      <Notice v-if="noDrafts.length" kind="warn">
        <template v-for="(m, i) in noDrafts" :key="m.id"><template v-if="i > 0">, </template><b>{{ m.label }}</b></template>
        {{ noDrafts.length === 1 ? "has" : "have" }} no Drafts folder. <b>draft</b> grants there will fail until you pick one.
        <template #action>
          <NuxtLink :to="`/mailboxes/${encodeURIComponent(noDrafts[0]!.id)}`">Fix it</NuxtLink>
        </template>
      </Notice>

      <!-- Access map -->
      <SectionCard id="clients" title="Access map">
        <template #aside>
          <span>
            Blank means no access. <CapabilityBadge capability="draft" /> <CapabilityBadge capability="organize" /> change things.{{ adminMode ? "" : " Clients register themselves; registration grants nothing." }}
          </span>
        </template>

        <EmptyState v-if="!mailboxes.length" title="Add a mailbox first, then connect a client." />
        <EmptyState v-else-if="!clients.length" title="No clients registered yet." />
        <Table v-else>
          <caption class="sr-only">Capabilities each client holds on each mailbox</caption>
          <TableHeader>
            <TableRow>
              <TableHead scope="col">Client</TableHead>
              <TableHead v-for="m in mailboxes" :key="m.id" scope="col">{{ m.label }}</TableHead>
              <TableHead scope="col"><span class="sr-only">Actions</span></TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            <TableRow v-for="c in clients" :key="c.clientId">
              <TableHead scope="row">
                <span class="font-semibold">{{ c.clientName || "(unnamed)" }}</span>
                <Pill v-if="c.disabled" tone="off" class="ml-1.5">disabled</Pill>
                <div class="text-muted-foreground font-mono text-xs font-normal break-all">{{ c.clientId }}</div>
              </TableHead>
              <TableCell v-for="m in mailboxes" :key="m.id">
                <CapabilityBadges :capabilities="granted.get(`${c.clientId}:${m.id}`)" />
              </TableCell>
              <TableCell class="r">
                <Button v-if="c.disabled" variant="outline" size="sm" :disabled="enablingId === c.clientId" @click="enableClient(c.clientId)">
                  <LoaderCircle v-if="enablingId === c.clientId" class="animate-spin" aria-hidden="true" />
                  Enable<span class="sr-only"> {{ c.clientName || c.clientId }}</span>
                </Button>
                <Button v-else as-child variant="outline" size="sm">
                  <NuxtLink :to="`/clients/${encodeURIComponent(c.clientId)}`">Edit grants<span class="sr-only"> for {{ c.clientName || c.clientId }}</span></NuxtLink>
                </Button>
              </TableCell>
            </TableRow>
          </TableBody>
        </Table>

        <AddClientForm v-if="adminMode" />
      </SectionCard>

      <!-- Mailboxes -->
      <SectionCard id="mailboxes" title="Mailboxes">
        <template #aside>
          <Button as-child size="sm"><NuxtLink to="/mailboxes/new">Add mailbox</NuxtLink></Button>
        </template>
        <EmptyState v-if="!mailboxes.length" title="No mailboxes yet." />
        <Table v-else>
          <caption class="sr-only">Configured mailboxes</caption>
          <TableHeader>
            <TableRow>
              <TableHead scope="col">Label</TableHead>
              <TableHead scope="col">Server</TableHead>
              <TableHead scope="col">User</TableHead>
              <TableHead scope="col">Status</TableHead>
              <TableHead scope="col">Drafts folder</TableHead>
              <TableHead scope="col">Clients</TableHead>
              <TableHead scope="col"><span class="sr-only">Actions</span></TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            <TableRow v-for="m in mailboxes" :key="m.id">
              <TableCell class="max-w-56 font-semibold break-words">{{ m.label }}</TableCell>
              <TableCell class="font-mono text-xs">{{ m.host }}:{{ m.port }}</TableCell>
              <TableCell class="max-w-56 break-all">{{ m.username }}</TableCell>
              <TableCell><StatusBadge :status="m.status" /></TableCell>
              <TableCell>
                <template v-if="m.draftsFolder">{{ m.draftsFolder }}</template>
                <Pill v-else tone="warn">not set</Pill>
              </TableCell>
              <TableCell>
                <template v-if="m.clientCount">{{ m.clientCount }}</template>
                <span v-else class="text-muted-foreground">0</span>
              </TableCell>
              <TableCell class="r">
                <Button as-child variant="outline" size="sm">
                  <NuxtLink :to="`/mailboxes/${encodeURIComponent(m.id)}`">Manage<span class="sr-only"> {{ m.label }}</span></NuxtLink>
                </Button>
              </TableCell>
            </TableRow>
          </TableBody>
        </Table>
      </SectionCard>

      <!-- Active tokens -->
      <SectionCard id="tokens" title="Active tokens">
        <template #aside><span>Revoking cuts access at the next call.</span></template>
        <EmptyState v-if="!tokens.length" title="No active tokens." />
        <Table v-else>
          <caption class="sr-only">Active access tokens</caption>
          <TableHeader>
            <TableRow>
              <TableHead scope="col">Client</TableHead>
              <TableHead scope="col">Can reach</TableHead>
              <TableHead scope="col">Issued</TableHead>
              <TableHead scope="col">Access token expires</TableHead>
              <TableHead scope="col"><span class="sr-only">Actions</span></TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            <template v-for="t in tokens" :key="t.id">
              <TableRow>
                <TableCell class="max-w-56 font-semibold break-words">{{ t.clientName || t.clientId }}</TableCell>
                <TableCell>
                  <template v-if="t.reach.length">
                    <div v-for="r in t.reach" :key="r.mailboxId">{{ r.mailboxLabel }} <CapabilityBadges :capabilities="r.capabilities" /></div>
                  </template>
                  <span v-else class="text-muted-foreground">nothing (all grants removed)</span>
                </TableCell>
                <TableCell class="text-muted-foreground text-[13px]">{{ formatIssued(t.createdAt) }}</TableCell>
                <TableCell class="text-muted-foreground text-[13px]">{{ formatExpires(t.expiresAt) }}</TableCell>
                <TableCell class="r">
                  <Button variant="outline" size="sm" class="btn-d" :aria-expanded="confirmingId === t.id" :aria-controls="`revoke-${t.id}`" @click="toggleRevoke(t)">
                    Revoke<span class="sr-only"> token of {{ t.clientName || t.clientId }}</span>
                  </Button>
                </TableCell>
              </TableRow>
              <TableRow v-if="confirmingId === t.id" :id="`revoke-${t.id}`">
                <TableCell colspan="5" data-static class="!border-t-0 !p-0">
                  <ConfirmBand
                    :title="`Revoke ${t.clientName || t.clientId}'s token?`"
                    confirm-label="Revoke token"
                    label="Confirm revoke"
                    :pending="revoking"
                    :error="revokeError"
                    @cancel="confirmingId = null"
                    @confirm="revokeToken(t)"
                  >{{ revokeText(t) }}</ConfirmBand>
                </TableCell>
              </TableRow>
            </template>
          </TableBody>
        </Table>
      </SectionCard>
    </div>
  </div>
</template>
