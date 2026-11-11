<script setup lang="ts">
/**
 * The design's .alert: soft background, optional inline action (slot `action`), no icon.
 * kind: ok | err | warn. err announces as role=alert, the others as role=status.
 */
const props = withDefaults(defineProps<{ kind?: "ok" | "err" | "warn"; role?: "alert" | "status" | "none" }>(), { kind: "err" });
const effectiveRole = computed(() => props.role ?? (props.kind === "err" ? "alert" : "status"));
</script>

<template>
  <div
    :role="effectiveRole === 'none' ? undefined : effectiveRole"
    class="flex items-center justify-between gap-2.5 rounded-[9px] px-3.5 py-2.5 [&_a]:font-semibold [&_a]:text-inherit"
    :class="{ 'bg-ok-soft text-ok': kind === 'ok', 'bg-danger-soft text-danger': kind === 'err', 'bg-warn-soft text-warn': kind === 'warn' }"
  >
    <span class="min-w-0"><slot /></span>
    <span v-if="$slots.action" class="flex shrink-0 items-center gap-2"><slot name="action" /></span>
  </div>
</template>
