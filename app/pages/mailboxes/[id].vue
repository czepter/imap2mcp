<script setup lang="ts">
import { LoaderCircle } from "@lucide/vue";
import { toast } from "vue-sonner";
import type { MailboxDetail, MailboxInput, MailboxTestResult } from "~~/shared/types/api";

const route = useRoute();
const api = useApi();
const id = computed(() => String(route.params.id));
const base = computed(() => `/mailboxes/${encodeURIComponent(id.value)}`);

const { data, error, pending, refresh } = useApiData(() => api.get<MailboxDetail>(base.value), { watch: [id] });
const mailbox = computed(() => data.value?.mailbox ?? null);
const status = computed(() => data.value?.status ?? null);

useHead({ title: () => mailbox.value?.label ?? "Mailbox" });
useBreadcrumbs(() => [
  { label: "Mailboxes", to: "/mailboxes" },
  { label: mailbox.value?.label ?? "Mailbox" },
]);

// ---- connection form ----
const saving = ref(false);
const saveError = ref("");
async function save(input: MailboxInput) {
  saving.value = true;
  saveError.value = "";
  try {
    await api.patch(base.value, input);
    toast.success("Saved. If host, port or username changed, re-test and re-select the Drafts folder.");
    test.value = null; // the folder list belongs to the old connection
    await refresh();
  } catch (e) {
    saveError.value = e instanceof ApiError ? e.message : "Could not save the connection.";
  } finally {
    saving.value = false;
  }
}

// ---- status / retry ----
const retrying = ref(false);
async function retry() {
  retrying.value = true;
  try {
    await api.post(`${base.value}/retry`);
    toast.success("Status reset. The bridge will try to connect again on the next request.");
    await refresh();
  } catch (e) {
    toast.error(e instanceof ApiError ? e.message : "Could not reset the status.");
  } finally {
    retrying.value = false;
  }
}

// ---- connection test ----
const test = ref<MailboxTestResult | null>(null);
const testing = ref(false);
const testError = ref("");
async function runTest() {
  testing.value = true;
  testError.value = "";
  try {
    test.value = await api.post<MailboxTestResult>(`${base.value}/test`);
    await refresh();
  } catch (e) {
    test.value = null;
    testError.value = e instanceof ApiError ? e.message : "The connection test failed to run.";
  } finally {
    testing.value = false;
  }
}

// ---- drafts folder ----
const folder = ref("");
watch([() => mailbox.value?.draftsFolder, test], () => { folder.value = mailbox.value?.draftsFolder ?? ""; }, { immediate: true });
const folderSaving = ref(false);
const folderError = ref("");
const folderSelectId = useId();
async function saveFolder() {
  if (!folder.value) { folderError.value = "Choose a folder"; return; }
  folderSaving.value = true;
  folderError.value = "";
  try {
    await api.put(`${base.value}/drafts`, { folder: folder.value });
    toast.success("Drafts folder saved.");
    await refresh();
  } catch (e) {
    folderError.value = e instanceof ApiError ? e.message : "Could not save the Drafts folder.";
  } finally {
    folderSaving.value = false;
  }
}

// ---- delete: type the label to enable the button (design: inline, no dialog) ----
const confirmLabel = ref("");
const deleting = ref(false);
const deleteError = ref("");
const deleteId = useId();
const canDelete = computed(() => !!mailbox.value && confirmLabel.value === mailbox.value.label);
async function remove() {
  if (!mailbox.value || !canDelete.value) return;
  deleting.value = true;
  deleteError.value = "";
  try {
    await api.del(base.value, { confirmLabel: mailbox.value.label });
    toast.success("Mailbox configuration removed.");
    await navigateTo("/dashboard", { replace: true });
  } catch (e) {
    deleteError.value = e instanceof ApiError ? e.message : "Could not delete the mailbox.";
  } finally {
    deleting.value = false;
  }
}

const clientCount = computed(() => data.value?.reach.length ?? 0);
</script>

<template>
  <div>
    <!-- Loading -->
    <div v-if="pending && !data" aria-busy="true" class="grid gap-5">
      <div class="grid gap-2"><Skeleton class="h-7 w-64" /><Skeleton class="h-4 w-80 max-w-full" /></div>
      <div class="bg-card rounded-xl border"><TableSkeleton :rows="4" :cols="2" /></div>
    </div>

    <!-- Not found / failed -->
    <div v-else-if="error && !data">
      <ErrorAlert :error="error" :title="error.status === 404 ? 'Mailbox not found' : 'Could not load the mailbox'">
        <template #actions>
          <Button v-if="error.status !== 404" variant="outline" size="sm" @click="refresh({ quiet: false })">Try again</Button>
          <Button as-child variant="outline" size="sm"><NuxtLink to="/dashboard">Back</NuxtLink></Button>
        </template>
      </ErrorAlert>
    </div>

    <div v-else-if="data && mailbox && status">
      <PageHeader :title="mailbox.label">
        <template #description>
          <span class="font-mono text-xs">{{ mailbox.username }} &middot; {{ mailbox.host }}:{{ mailbox.port }}</span>
        </template>
        <Button variant="outline" :disabled="testing" @click="runTest">
          <LoaderCircle v-if="testing" class="animate-spin" aria-hidden="true" />
          Test connection
        </Button>
      </PageHeader>

      <div class="grid gap-5">
        <!-- Status banner -->
        <Notice v-if="status.status === 'auth_failed'" kind="err">
          <b>Authentication failed.</b> The mail server rejected this mailbox's credentials, so the bridge stopped trying. Update the password below, or press Retry once it is fixed at the provider.<template v-if="status.lastErrorCode">{{ " " }}<span class="font-mono text-xs">{{ status.lastErrorCode }}</span></template>
          <template #action>
            <Button variant="outline" size="sm" :disabled="retrying" @click="retry">
              <LoaderCircle v-if="retrying" class="animate-spin" aria-hidden="true" />
              Retry
            </Button>
          </template>
        </Notice>
        <Notice v-else-if="status.status === 'degraded'" kind="warn">
          <b>Degraded.</b> The connection is unstable<template v-if="status.lastErrorCode"> (<span class="font-mono text-xs">{{ status.lastErrorCode }}</span>)</template><template v-if="status.nextRetryAt">; next attempt {{ formatWhen(status.nextRetryAt) }}</template>.
          <template #action>
            <Button variant="outline" size="sm" :disabled="retrying" @click="retry">
              <LoaderCircle v-if="retrying" class="animate-spin" aria-hidden="true" />
              Retry
            </Button>
          </template>
        </Notice>
        <p v-else class="text-muted-foreground -mb-1 text-[13px]">
          Connection status: <StatusBadge :status="status.status" />
          <template v-if="status.lastOkAt"> &middot; last OK {{ formatWhen(status.lastOkAt) }}</template>
        </p>

        <!-- Test result (the live region is always present so screen readers announce changes) -->
        <div aria-live="polite" role="status" class="empty:hidden">
          <Notice v-if="test" :kind="test.ok ? 'ok' : 'err'" role="none">{{ test.message }}</Notice>
          <ErrorAlert v-else-if="testError" :error="testError" />
        </div>

        <SectionCard id="conn" title="Connection">
          <MailboxForm mode="edit" :initial="mailbox" :pending="saving" :error="saveError" @submit="save" />
        </SectionCard>

        <SectionCard id="drafts" title="Drafts folder">
          <template #aside>
            <span v-if="mailbox.draftsFolder">Current: <b class="text-foreground">{{ mailbox.draftsFolder }}</b></span>
            <Pill v-else tone="warn">not set</Pill>
          </template>
          <form class="grid gap-[14px] p-[18px]" @submit.prevent="saveFolder">
            <p class="text-muted-foreground text-[13px]">Clients with <b class="text-foreground">draft</b> write only here. They cannot read, move or send.</p>
            <template v-if="test?.ok">
              <div class="grid gap-[5px] sm:max-w-[340px]">
                <Label :for="folderSelectId">Folder on server</Label>
                <Select v-model="folder">
                  <SelectTrigger :id="folderSelectId">
                    <SelectValue placeholder="Choose a folder…" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem v-for="f in test.folders" :key="f" :value="f">{{ f }}</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div aria-live="polite" class="empty:hidden"><ErrorAlert :error="folderError" /></div>
              <div>
                <Button type="submit" :disabled="folderSaving || !folder">
                  <LoaderCircle v-if="folderSaving" class="animate-spin" aria-hidden="true" />
                  Save Drafts folder
                </Button>
              </div>
            </template>
            <p v-else class="text-muted-foreground text-[13px]">Run the connection test to choose the Drafts folder from the server's folder list.</p>
          </form>
        </SectionCard>

        <SectionCard id="reach" title="Who can reach this mailbox">
          <EmptyState v-if="!data.reach.length" :title="`No client has access to ${mailbox.label} yet.`" description="Grant it from a client's page." />
          <Table v-else>
            <caption class="sr-only">Clients with access to {{ mailbox.label }}</caption>
            <TableBody>
              <TableRow v-for="r in data.reach" :key="r.clientId">
                <TableHead scope="row">{{ r.clientName || "(unnamed)" }}</TableHead>
                <TableCell><CapabilityBadges :capabilities="r.capabilities" /></TableCell>
                <TableCell class="r">
                  <Button as-child variant="outline" size="sm">
                    <NuxtLink :to="`/clients/${encodeURIComponent(r.clientId)}`">Edit grants<span class="sr-only"> for {{ r.clientName || r.clientId }}</span></NuxtLink>
                  </Button>
                </TableCell>
              </TableRow>
            </TableBody>
          </Table>
        </SectionCard>

        <SectionCard id="delete" title="Delete mailbox" danger>
          <form class="p-[18px]" @submit.prevent="remove">
            <p>
              This removes the connection and
              <template v-if="clientCount">the grants of <b>{{ clientCount }}</b> client{{ clientCount === 1 ? "" : "s" }}</template><template v-else>all grants</template>
              for <b>{{ mailbox.label }}</b>. Mail on the server is not touched.<template v-if="!clientCount"> Nothing currently uses it.</template>
            </p>
            <div class="mt-[14px] grid gap-[5px] sm:max-w-[340px]">
              <Label :for="deleteId">Type <b>{{ mailbox.label }}</b> to confirm</Label>
              <Input :id="deleteId" v-model="confirmLabel" type="text" autocomplete="off" autocapitalize="off" spellcheck="false" :disabled="deleting" />
            </div>
            <div aria-live="polite" class="mt-[14px] empty:hidden"><ErrorAlert :error="deleteError" /></div>
            <Button type="submit" variant="destructive" class="mt-[14px]" :disabled="!canDelete || deleting" :aria-busy="deleting">
              <LoaderCircle v-if="deleting" class="animate-spin" aria-hidden="true" />
              Delete mailbox
            </Button>
          </form>
        </SectionCard>
      </div>
    </div>
  </div>
</template>
