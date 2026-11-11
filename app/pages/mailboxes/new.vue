<script setup lang="ts">
import { toast } from "vue-sonner";
import type { Mailbox, MailboxInput } from "~~/shared/types/api";

useHead({ title: "Add mailbox" });
useBreadcrumbs([{ label: "Mailboxes", to: "/dashboard#mailboxes" }, { label: "New" }]);

const api = useApi();
const pending = ref(false);
const error = ref("");

async function create(input: MailboxInput) {
  pending.value = true;
  error.value = "";
  try {
    const m = await api.post<Mailbox>("/mailboxes", input);
    toast.success("Mailbox saved. Run the connection test, then choose the Drafts folder.");
    await navigateTo(`/mailboxes/${encodeURIComponent(m.id)}`, { replace: true });
  } catch (e) {
    error.value = e instanceof ApiError ? e.message : "Could not save the mailbox.";
  } finally {
    pending.value = false;
  }
}
</script>

<template>
  <div>
    <PageHeader title="Add mailbox" />
    <SectionCard id="add" title="Connection">
      <MailboxForm mode="create" :pending="pending" :error="error" @submit="create" />
    </SectionCard>
    <p class="text-muted-foreground mt-3.5 text-[13px]">Test the connection after saving, then choose the Drafts folder.</p>
  </div>
</template>
