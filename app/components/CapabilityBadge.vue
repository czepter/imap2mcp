<script setup lang="ts">
import type { Capability } from "~~/shared/types/api";

/** read is neutral; draft and organize are warn-tinted because they change things (organize also gets a ring). */
defineProps<{ capability: Capability }>();
</script>

<template>
  <Pill :tone="capability">{{ capability }}</Pill>
</template>
