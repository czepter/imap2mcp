<script setup lang="ts">
useHead({ title: "Overview" });

const { data, error, pending, refresh, mailboxes, clients, tokens, noDrafts } = useOverview();

const tiles = computed(() => [
  { to: "/mailboxes", label: "Mailboxes", count: mailboxes.value.length, hint: "IMAP accounts bridged to clients" },
  { to: "/clients", label: "Clients", count: clients.value.length, hint: `${clients.value.filter((c) => c.disabled).length} disabled` },
  { to: "/tokens", label: "Active tokens", count: tokens.value.length, hint: "Revoke to cut access" },
]);
</script>

<template>
  <div>
    <PageHeader title="Overview" description="Who can reach which mailbox, and how." />

    <ErrorAlert v-if="error && !data" :error="error" title="Could not load the overview">
      <template #actions>
        <Button variant="outline" size="sm" @click="refresh({ quiet: false })">Try again</Button>
      </template>
    </ErrorAlert>

    <div v-else-if="pending && !data" class="grid gap-5 sm:grid-cols-3" aria-busy="true">
      <Skeleton v-for="i in 3" :key="i" class="h-28 rounded-xl" />
    </div>

    <div v-else-if="data" class="grid gap-5">
      <NoDraftsNotice :mailboxes="noDrafts" />

      <ul class="grid list-none gap-5 p-0 sm:grid-cols-3">
        <li v-for="t in tiles" :key="t.to">
          <NuxtLink :to="t.to" class="bg-card hover:bg-accent block rounded-xl border p-[18px] no-underline transition-colors">
            <span class="text-muted-foreground block text-[13px]">{{ t.label }}</span>
            <span class="block text-3xl font-semibold tabular-nums">{{ t.count }}</span>
            <span class="text-muted-foreground block text-[13px]">{{ t.hint }}</span>
          </NuxtLink>
        </li>
      </ul>

      <EmptyState v-if="!mailboxes.length" title="Add a mailbox first, then connect a client.">
        <Button as-child size="sm"><NuxtLink to="/mailboxes/new">Add mailbox</NuxtLink></Button>
      </EmptyState>
    </div>
  </div>
</template>
