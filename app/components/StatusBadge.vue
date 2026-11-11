<script setup lang="ts">
import type { MailboxStatusValue } from "~~/shared/types/api";

const props = defineProps<{ status: MailboxStatusValue }>();
const tone = computed(() => ({ ok: "ok", degraded: "warn", auth_failed: "off", unknown: "read" } as const)[props.status] ?? "read");
const text = computed(() => (props.status === "auth_failed" ? "auth failed" : props.status));
</script>

<template>
  <Pill :tone="tone">{{ text }}</Pill>
</template>
