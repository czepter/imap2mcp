<script setup lang="ts">
import type { Capability } from "~~/shared/types/api";

/** The capabilities in canonical order, or a dash when there are none. */
defineProps<{ capabilities?: readonly Capability[]; emptyLabel?: string }>();
</script>

<template>
  <span v-if="capabilities && capabilities.length" class="inline-flex flex-wrap items-center gap-1">
    <CapabilityBadge v-for="c in sortCapabilities(capabilities)" :key="c" :capability="c" />
  </span>
  <span v-else class="text-muted-foreground">
    <span v-if="!emptyLabel" aria-hidden="true">&mdash;</span>
    <span :class="emptyLabel ? '' : 'sr-only'">{{ emptyLabel ?? "no access" }}</span>
  </span>
</template>
