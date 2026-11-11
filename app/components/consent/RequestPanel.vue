<script setup lang="ts">
import type { AuthorizeRequest, Capability, GrantsUpdate } from "~~/shared/types/api";

type Grant = GrantsUpdate["grants"][number];

const props = defineProps<{
  request: AuthorizeRequest;
  /** True while the decision is being sent (or the redirect to the client is under way). */
  busy: boolean;
  error?: string;
}>();
const emit = defineEmits<{ decide: [decision: "approve" | "deny", grants: Grant[]] }>();

const grants = ref<Grant[]>([]);
const name = computed(() => props.request.client.name || props.request.client.id);
// Only the capabilities the client asked for are offered, in the usual order.
const columns = computed<Capability[]>(() => sortCapabilities(props.request.capabilities));
const hasMailboxes = computed(() => props.request.mailboxes.length > 0);
</script>

<template>
  <div>
    <h1 id="consent-title" tabindex="-1" style="outline: none">“{{ name }}” asks for access to your mail</h1>
    <dl class="text-muted-foreground mt-2.5 grid grid-cols-[auto_1fr] gap-x-3.5 gap-y-0.5 text-[13px]">
      <dt>Client name</dt>
      <dd>Chosen by the client itself. Anyone can register under any name.</dd>
      <dt>Registered</dt>
      <dd><time :datetime="request.client.createdAt">{{ formatWhen(request.client.createdAt) }}</time></dd>
      <dt>Returns to</dt>
      <dd class="font-mono text-xs break-all">{{ request.redirectUri }}</dd>
    </dl>

    <div v-if="!hasMailboxes" class="mt-[18px]">
      <Notice kind="err" role="status">No mailboxes configured. <NuxtLink to="/mailboxes/new">Add one</NuxtLink> first.</Notice>
    </div>

    <template v-else>
      <fieldset class="mt-[18px] min-w-0 border-0 p-0" :disabled="busy">
        <legend class="mb-2 font-semibold">Choose what it may do. Nothing ticked means no access.</legend>
        <div class="bg-card overflow-hidden rounded-xl border [contain:inline-size]">
          <ClientsGrantsMatrix v-model="grants" :mailboxes="request.mailboxes" :capabilities="columns" :subject="name" label-prefix="Allow" :disabled="busy" />
        </div>
      </fieldset>
      <p class="text-muted-foreground mt-[5px] text-[13px]">
        Only the capabilities this client requested are listed. <b class="text-foreground">read</b> searches and reads messages.
        <b class="text-foreground">draft</b> writes drafts, never sends.<template v-if="columns.includes('organize')">{{ " " }}<b class="text-foreground">organize</b> moves messages and sets flags.</template>
        Change this later under <NuxtLink to="/dashboard#clients" class="underline underline-offset-2">Clients</NuxtLink>.
      </p>
    </template>

    <div class="mt-4 empty:hidden" aria-live="polite"><ErrorAlert :error="error" /></div>

    <div class="mt-[22px] flex flex-wrap gap-2.5">
      <Button class="flex-1 basis-40" :disabled="busy || !hasMailboxes" @click="emit('decide', 'approve', grants)">
        {{ busy ? "Working…" : "Allow selected access" }}
      </Button>
      <Button variant="outline" class="flex-1 basis-40" :disabled="busy" @click="emit('decide', 'deny', [])">Deny</Button>
    </div>
  </div>
</template>
