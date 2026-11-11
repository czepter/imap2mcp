<script setup lang="ts">
useHead({ title: "Mailboxes" });

const { data, error, pending, refresh, mailboxes, noDrafts } = useOverview();
</script>

<template>
  <div>
    <PageHeader title="Mailboxes" description="The IMAP accounts clients can be granted access to.">
      <Button as-child size="sm"><NuxtLink to="/mailboxes/new">Add mailbox</NuxtLink></Button>
    </PageHeader>

    <ErrorAlert v-if="error && !data" :error="error" title="Could not load the mailboxes">
      <template #actions>
        <Button variant="outline" size="sm" @click="refresh({ quiet: false })">Try again</Button>
      </template>
    </ErrorAlert>

    <section v-else-if="pending && !data" class="bg-card overflow-hidden rounded-xl border" aria-busy="true">
      <TableSkeleton :rows="3" :cols="6" />
    </section>

    <div v-else-if="data" class="grid gap-5">
      <NoDraftsNotice :mailboxes="noDrafts" />

      <SectionCard id="mailboxes" title="Mailboxes">
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
    </div>
  </div>
</template>
