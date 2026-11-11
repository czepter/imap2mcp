<script setup lang="ts">
withDefaults(defineProps<{ rows?: number; cols?: number }>(), { rows: 3, cols: 4 });
</script>

<template>
  <div class="grid gap-3 p-[18px]" role="status" aria-label="Loading">
    <div v-for="r in rows" :key="r" class="grid gap-4" :style="{ gridTemplateColumns: `repeat(${cols}, minmax(0, 1fr))` }">
      <Skeleton v-for="c in cols" :key="c" class="h-5" />
    </div>
    <span class="sr-only">Loading</span>
  </div>
</template>
