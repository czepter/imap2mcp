<script setup lang="ts">
import { LoaderCircle } from "@lucide/vue";
import { toast } from "vue-sonner";
import type { ClientCreateRequest, ClientSummary } from "~~/shared/types/api";

const api = useApi();
const name = ref("");
const uris = ref("");
const error = ref("");
const pending = ref(false);

async function submit() {
  if (pending.value) return;
  error.value = "";
  const redirectUris = uris.value.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
  if (!name.value.trim() || redirectUris.length === 0 || redirectUris.length > 10) {
    error.value = "Name and 1-10 valid redirect URIs required (https, or http on localhost)";
    return;
  }
  pending.value = true;
  try {
    const created = await api.post<ClientSummary>("/clients", { name: name.value.trim(), redirectUris } satisfies ClientCreateRequest);
    toast.success(`Client created. client_id: ${created.clientId}`);
    await navigateTo(`/clients/${encodeURIComponent(created.clientId)}`);
  } catch (e) {
    error.value = e instanceof ApiError ? e.message : "Could not create the client.";
  } finally {
    pending.value = false;
  }
}
</script>

<template>
  <form class="grid gap-[14px] border-t p-[18px]" novalidate @submit.prevent="submit">
    <h3 class="text-sm font-semibold">Add client</h3>
    <div aria-live="polite">
      <ErrorAlert :error="error" />
    </div>
    <div class="grid gap-[5px]">
      <Label for="client-name">Name</Label>
      <Input id="client-name" v-model="name" type="text" name="client_name" maxlength="100" required autocomplete="off" class="sm:max-w-[340px]" />
    </div>
    <div class="grid gap-[5px]">
      <Label for="client-uris">Redirect URIs (one per line; https or http://localhost)</Label>
      <Textarea id="client-uris" v-model="uris" name="redirect_uris" rows="3" required spellcheck="false" autocapitalize="off" class="font-mono text-xs" />
    </div>
    <div>
      <Button type="submit" :disabled="pending">
        <LoaderCircle v-if="pending" class="animate-spin" aria-hidden="true" />
        Create client
      </Button>
    </div>
  </form>
</template>
