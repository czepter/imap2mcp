<script setup lang="ts">
import { LoaderCircle } from "@lucide/vue";
import { toast } from "vue-sonner";
import {
  API_TOKEN_EXPIRY_DAYS, type ApiTokenCreate, type ApiTokenCreated, type ApiTokenExpiryDays, type Capability, type GrantsUpdate,
} from "~~/shared/types/api";

useHead({ title: "Create API token" });
useBreadcrumbs([{ label: "Tokens", to: "/tokens" }, { label: "New" }]);

const CAPABILITIES: Capability[] = ["read", "draft", "organize"];

const api = useApi();
const session = useSessionState();
const { data, error: loadError, pending: loading, refresh, mailboxes } = useOverview();

const name = ref("");
const days = ref<ApiTokenExpiryDays>(90);
const grants = ref<GrantsUpdate["grants"]>([]);
const pending = ref(false);
const error = ref("");

/** Only held in memory: leaving the page discards it, and the server cannot show it again. */
const created = ref<ApiTokenCreated | null>(null);
const endpoint = computed(() => `${(session.info.value?.baseUrl ?? "").replace(/\/+$/, "")}/mcp`);

async function submit() {
  if (pending.value) return;
  error.value = "";
  if (!name.value.trim()) { error.value = "A name is required"; return; }
  if (!grants.value.length) { error.value = "Choose at least one mailbox permission"; return; }
  pending.value = true;
  try {
    created.value = await api.post<ApiTokenCreated>("/tokens", {
      name: name.value.trim(), expiresInDays: days.value, grants: grants.value,
    } satisfies ApiTokenCreate);
    toast.success("API token created.");
  } catch (e) {
    error.value = e instanceof ApiError ? e.message : "Could not create the token.";
  } finally {
    pending.value = false;
  }
}

const secretField = useTemplateRef<HTMLElement>("secretField");
async function copy() {
  try {
    await navigator.clipboard.writeText(created.value!.secret);
    toast.success("Token copied.");
  } catch {
    // No clipboard access (for example plain http on a non-local host): select it for a manual copy.
    secretField.value?.querySelector("input")?.select();
    toast.error("Could not copy. The token is selected, copy it by hand.");
  }
}
</script>

<template>
  <div>
    <template v-if="created">
      <PageHeader :title="`${created.token.clientName} token`" />
      <div class="grid gap-5">
        <Notice kind="warn">Copy the token now. It is shown only this once.</Notice>
        <SectionCard id="secret" title="Your API token" padded>
          <div class="grid gap-[14px]">
            <div class="grid gap-[5px]">
              <Label for="token-secret">Token</Label>
              <div ref="secretField" class="flex gap-2">
                <Input id="token-secret" :model-value="created.secret" readonly spellcheck="false" autocomplete="off" class="font-mono text-xs" @focus="($event.target as HTMLInputElement).select()" />
                <Button type="button" variant="outline" @click="copy">Copy</Button>
              </div>
            </div>
            <p class="text-[13px]">
              Point the client at <code class="font-mono text-xs break-all">{{ endpoint }}</code> and send the header
              <code class="font-mono text-xs break-all">Authorization: Bearer &lt;token&gt;</code>.
            </p>
            <p class="text-muted-foreground text-[13px]">
              Expires {{ formatExpires(created.token.expiresAt) }}. It cannot be renewed; create a new one before then.
            </p>
          </div>
        </SectionCard>
        <div class="flex flex-wrap gap-2.5">
          <Button as-child><NuxtLink to="/tokens">Done</NuxtLink></Button>
          <Button as-child variant="outline">
            <NuxtLink :to="`/tokens/${encodeURIComponent(created.token.id)}`">Manage this token</NuxtLink>
          </Button>
        </div>
      </div>
    </template>

    <template v-else>
      <PageHeader title="Create API token" description="For scripts and clients that cannot sign in through the browser." />

      <ErrorAlert v-if="loadError && !data" :error="loadError" title="Could not load the mailboxes">
        <template #actions>
          <Button variant="outline" size="sm" @click="refresh({ quiet: false })">Try again</Button>
        </template>
      </ErrorAlert>

      <section v-else-if="loading && !data" class="bg-card overflow-hidden rounded-xl border" aria-busy="true">
        <TableSkeleton :rows="3" :cols="4" />
      </section>

      <SectionCard v-else-if="!mailboxes.length" id="no-mailboxes" title="Mailboxes">
        <EmptyState title="Add a mailbox first, then create a token.">
          <Button as-child size="sm"><NuxtLink to="/mailboxes/new">Add mailbox</NuxtLink></Button>
        </EmptyState>
      </SectionCard>

      <form v-else class="grid gap-5" novalidate @submit.prevent="submit">
        <div aria-live="polite">
          <ErrorAlert :error="error" />
        </div>

        <SectionCard id="token" title="Token" padded>
          <div class="grid gap-[14px]">
            <div class="grid gap-[5px]">
              <Label for="token-name">Name</Label>
              <Input id="token-name" v-model="name" type="text" maxlength="100" required autocomplete="off" class="sm:max-w-[340px]" />
            </div>
            <div class="grid gap-[5px]">
              <Label for="token-expiry">Expires after</Label>
              <Select :model-value="String(days)" @update:model-value="days = Number($event) as ApiTokenExpiryDays">
                <SelectTrigger id="token-expiry" class="sm:max-w-[340px]"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem v-for="d in API_TOKEN_EXPIRY_DAYS" :key="d" :value="String(d)">{{ d }} days</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </SectionCard>

        <SectionCard id="mailboxes" title="Mailboxes">
          <template #aside><span>Nothing ticked means no access.</span></template>
          <ClientsGrantsMatrix v-model="grants" :mailboxes="mailboxes" :capabilities="CAPABILITIES" :subject="name.trim() || 'New token'" :disabled="pending" />
        </SectionCard>

        <p class="text-muted-foreground text-[13px]">
          Anyone who has the token gets this access until it expires or you revoke it. For clients that support signing in, use that instead.
        </p>

        <div class="flex flex-wrap gap-2.5">
          <Button type="submit" :disabled="pending">
            <LoaderCircle v-if="pending" class="animate-spin" aria-hidden="true" />
            Create token
          </Button>
          <Button as-child variant="outline"><NuxtLink to="/tokens">Cancel</NuxtLink></Button>
        </div>
      </form>
    </template>
  </div>
</template>
