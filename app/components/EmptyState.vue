<script setup lang="ts">
/** Empty list copy as in the design: plain muted text in a padded block, optional actions below. */
defineProps<{ title: string; description?: string }>();
</script>

<template>
  <div class="p-[18px]">
    <p class="text-muted-foreground text-[13px]">
      {{ title }}<template v-if="description || $slots.description">{{ " " }}<slot name="description">{{ description }}</slot></template>
    </p>
    <div v-if="$slots.default" class="mt-3 flex flex-wrap items-center gap-2"><slot /></div>
  </div>
</template>
