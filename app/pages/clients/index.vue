<script setup lang="ts">
import { LoaderCircle } from "@lucide/vue";
import { toast } from "vue-sonner";
import type { Capability } from "~~/shared/types/api";

useHead({ title: "Clients" });

const api = useApi();
const { data, error, pending, refresh, mailboxes, clients, adminMode } = useOverview();

/** `${clientId}:${mailboxId}` -> capabilities held through grants. */
const granted = computed(() => {
  const map = new Map<string, Capability[]>();
  for (const g of data.value?.grants ?? []) {
    const k = `${g.clientId}:${g.mailboxId}`;
    map.set(k, [...(map.get(k) ?? []), g.capability]);
  }
  return map;
});

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
</script>

<template>
  <div>
    <PageHeader title="Clients" description="Who can reach which mailbox, and how." />

    <ErrorAlert v-if="error && !data" :error="error" title="Could not load the clients">
      <template #actions>
        <Button variant="outline" size="sm" @click="refresh({ quiet: false })">Try again</Button>
      </template>
    </ErrorAlert>

    <section v-else-if="pending && !data" class="bg-card overflow-hidden rounded-xl border" aria-busy="true">
      <TableSkeleton :rows="3" :cols="4" />
    </section>

    <SectionCard v-else-if="data" id="clients" title="Access map">
      <template #aside>
        <span>
          Blank means no access. <CapabilityBadge capability="draft" /> <CapabilityBadge capability="organize" /> change things.{{ adminMode ? "" : " Clients register themselves; registration grants nothing." }}
        </span>
      </template>

      <EmptyState v-if="!mailboxes.length" title="Add a mailbox first, then connect a client.">
        <Button as-child size="sm"><NuxtLink to="/mailboxes/new">Add mailbox</NuxtLink></Button>
      </EmptyState>
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
  </div>
</template>
