<script setup lang="ts">
/** The design's .head: h1 + muted subtitle on the left, actions (default slot) right-aligned; stacks under 820px. */
defineProps<{ title: string; description?: string }>();
</script>

<template>
  <header class="head">
    <div class="min-w-0">
      <h1 class="break-words">{{ title }}</h1>
      <p v-if="description || $slots.description">
        <slot name="description">{{ description }}</slot>
      </p>
    </div>
    <div v-if="$slots.default" class="flex shrink-0 flex-wrap items-center gap-2"><slot /></div>
  </header>
</template>
