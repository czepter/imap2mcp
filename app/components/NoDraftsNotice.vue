<script setup lang="ts">
import type { MailboxSummary } from "~~/shared/types/api";

defineProps<{ mailboxes: MailboxSummary[] }>();
</script>

<template>
  <Notice v-if="mailboxes.length" kind="warn">
    <template v-for="(m, i) in mailboxes" :key="m.id"><template v-if="i > 0">, </template><b>{{ m.label }}</b></template>
    {{ mailboxes.length === 1 ? "has" : "have" }} no Drafts folder. <b>draft</b> grants there will fail until you pick one.
    <template #action>
      <NuxtLink :to="`/mailboxes/${encodeURIComponent(mailboxes[0]!.id)}`">Fix it</NuxtLink>
    </template>
  </Notice>
</template>
