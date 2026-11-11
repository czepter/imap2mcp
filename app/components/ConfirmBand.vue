<script setup lang="ts">
import { LoaderCircle } from "@lucide/vue";

/**
 * The design's inline confirmation row (e.g. under a token row: "Revoke X's token?" + Cancel / Revoke token).
 * Put it in a full-width table cell (`<TableCell colspan=N data-static class="p-0">`) or right under a block.
 * The parent owns visibility and flips `aria-expanded` on its trigger button.
 */
withDefaults(defineProps<{ title: string; confirmLabel: string; cancelLabel?: string; pending?: boolean; error?: unknown; label?: string }>(), { cancelLabel: "Cancel", label: "Confirm" });
const emit = defineEmits<{ confirm: []; cancel: [] }>();

function messageOf(e: unknown): string {
  if (!e) return "";
  return typeof e === "string" ? e : e instanceof Error ? e.message : "Something went wrong.";
}
</script>

<template>
  <div class="confirm" role="group" :aria-label="label" @keydown.esc="emit('cancel')">
    <span class="min-w-0 flex-1 basis-64">
      <b>{{ title }}</b>
      <slot />
      <span v-if="error" class="text-danger mt-1 block" role="alert">{{ messageOf(error) }}</span>
    </span>
    <span class="flex items-center gap-2.5">
      <Button variant="outline" size="sm" :disabled="pending" @click="emit('cancel')">{{ cancelLabel }}</Button>
      <Button variant="destructive" size="sm" :disabled="pending" :aria-busy="pending" @click="emit('confirm')">
        <LoaderCircle v-if="pending" class="animate-spin" aria-hidden="true" />
        {{ confirmLabel }}
      </Button>
    </span>
  </div>
</template>
